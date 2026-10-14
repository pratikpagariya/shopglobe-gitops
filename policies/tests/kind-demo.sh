#!/usr/bin/env bash
# Prove the Kyverno policies on a throwaway kind cluster: Audit first, then
# Deny. Free and local -- the rehearsal before they reach EKS.
#
# Run from the gitops repo root:
#   bash policies/tests/kind-demo.sh          # create/reuse cluster, test, keep it
#   bash policies/tests/kind-demo.sh --clean  # ...and delete the cluster after
#
# Uses its own kubeconfig file, so your normal kubectl context is untouched.
# Exit code 0 = every case behaved as expected.
set -euo pipefail

CLUSTER=kyverno-lab
KYVERNO_CHART=3.9.1  # = Kyverno v1.19.1, same pin as bootstrap/values/kyverno.yaml
NS=shopglobe-dev
ECR=355653384401.dkr.ecr.ap-south-1.amazonaws.com
GOOD_IMAGE="$ECR/shopglobe-prod-catalog-svc:1a71019ce2c2"
export KUBECONFIG="${TMPDIR:-/tmp}/kind-$CLUSTER.kubeconfig"

say() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
FAILED=0

# ---------------------------------------------------------------------------
say "preflight"
# Several kind clusters exhaust the default inotify instance limit (128):
# kube-proxy then crash-loops with "too many open files", pods cannot reach
# the API server, and Kyverno hangs at startup with no error. Fail fast.
others=$(kind get clusters 2>/dev/null | grep -vx "$CLUSTER" | wc -l)
limit=$(sysctl -n fs.inotify.max_user_instances 2>/dev/null || echo 0)
if [ "$others" -gt 0 ] && [ "$limit" -lt 512 ]; then
  echo "  $others other kind cluster(s) running and fs.inotify.max_user_instances=$limit."
  echo "  Raise it first (lasts until WSL restarts):"
  echo "    sudo sysctl fs.inotify.max_user_instances=512"
  exit 1
fi
echo "  ok (other kind clusters: $others, inotify instances: $limit)"

# ---------------------------------------------------------------------------
say "kind cluster '$CLUSTER'"
if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  kind create cluster --name "$CLUSTER" --kubeconfig "$KUBECONFIG" --wait 120s
fi
kind export kubeconfig --name "$CLUSTER" --kubeconfig "$KUBECONFIG" >/dev/null 2>&1

say "Kyverno chart $KYVERNO_CHART"
# Not bootstrap/values/kyverno.yaml: kind has no tainted platform node, so
# that nodeSelector would leave every Kyverno pod Pending.
helm upgrade --install kyverno kyverno --repo https://kyverno.github.io/kyverno/ \
  --version "$KYVERNO_CHART" -n kyverno --create-namespace --wait --timeout 6m >/dev/null
kubectl get pods -n kyverno --no-headers | awk '{print "  " $1, $3}'

kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f - >/dev/null

# ---------------------------------------------------------------------------
say "phase 1: AUDIT (the policies exactly as committed)"
# Recreate rather than re-apply, so a previous run's Deny never leaks in.
kubectl delete -f policies/ --ignore-not-found >/dev/null
kubectl delete pod audit-me -n "$NS" --ignore-not-found >/dev/null
kubectl apply -f policies/ >/dev/null
kubectl wait validatingpolicy --all --for=jsonpath='{.status.conditionStatus.ready}'=true --timeout=90s >/dev/null

if kubectl -n "$NS" run audit-me --image=nginx:latest >/dev/null 2>&1; then
  echo "  PASS  nginx:latest pod ADMITTED -- Audit records, it does not block"
else
  echo "  FAIL  nginx:latest pod was rejected in Audit mode"; FAILED=1
fi
for _ in $(seq 1 30); do  # the reports controller writes asynchronously
  fails=$(kubectl -n "$NS" get policyreports -o jsonpath='{.items[*].summary.fail}' 2>/dev/null || true)
  [ -n "$fails" ] && [ "$fails" != 0 ] && break
  sleep 3
done
echo "  PolicyReport for audit-me:"
kubectl -n "$NS" get policyreports \
  -o jsonpath='{range .items[*].results[*]}{"    "}{.result}{"  "}{.policy}{"\n"}{end}' | sort -u
[ "${fails:-0}" = 4 ] || { echo "  FAIL  expected 4 failed rules, got '${fails:-none}'"; FAILED=1; }

# ---------------------------------------------------------------------------
say "phase 2: DENY"
for p in $(kubectl get validatingpolicies -o name); do
  kubectl patch "$p" --type merge -p '{"spec":{"validationActions":["Deny"]}}' >/dev/null
done
for _ in $(seq 1 20); do  # wait until the webhook actually enforces
  kubectl -n "$NS" create deployment probe --image=nginx:latest --dry-run=server >/dev/null 2>&1 || break
  sleep 3
done

RES='      resources: {requests: {cpu: 10m, memory: 32Mi}, limits: {memory: 64Mi}}'
SEC='      securityContext: {runAsNonRoot: true}'
pod() {  # name image resources-line securityContext-line
  printf 'apiVersion: v1\nkind: Pod\nmetadata: {name: %s, namespace: %s}\nspec:\n  containers:\n    - name: app\n      image: %s\n%s\n%s\n' \
    "$1" "$NS" "$2" "$3" "$4"
}
dry() { kubectl apply --dry-run=server -f - ; }  # admission runs, nothing is created

# case <admit|deny> <policy that must reject, or -> <description> <command>
case_() {
  local want=$1 policy=$2 desc=$3 out got ok=1
  if out=$(eval "$4" 2>&1); then got=admit; else got=deny; fi
  [ "$got" = "$want" ] || ok=0
  if [ "$want" = deny ] && [ "$ok" = 1 ]; then
    grep -q "Policy $policy failed" <<<"$out" || ok=0
    # A single-rule case must be rejected by THAT rule only.
    [ "$(grep -o 'Policy [a-z-]* failed' <<<"$out" | wc -l)" = 1 ] || [ "${5:-}" = multi ] || ok=0
  fi
  if [ "$ok" = 1 ]; then printf '  \033[32mPASS\033[0m  '; else printf '  \033[31mFAIL\033[0m  '; FAILED=1; fi
  printf '%-52s -> %s\n' "$desc" "$got"
  if [ "$got" = deny ]; then grep -o 'Policy [a-z-]* failed: [^;]*' <<<"$out" | sed 's/^/          /'; fi
  return 0
}

case_ admit -                         "compliant pod (ECR, tag, resources, non-root)" "pod good  '$GOOD_IMAGE'                          \"\$RES\" \"\$SEC\" | dry"
case_ deny  disallow-latest-tag       "only fault: :latest tag"                        "pod t1    '$ECR/shopglobe-prod-catalog-svc:latest' \"\$RES\" \"\$SEC\" | dry"
case_ deny  restrict-image-registries "only fault: Docker Hub image"                   "pod t2    'docker.io/library/nginx:1.27'      \"\$RES\" \"\$SEC\" | dry"
case_ deny  require-requests-limits   "only fault: no resources"                       "pod t3    '$GOOD_IMAGE'                          ''        \"\$SEC\" | dry"
case_ deny  disallow-privileged       "only fault: privileged"                         "pod t4    '$GOOD_IMAGE' \"\$RES\" '      securityContext: {runAsNonRoot: true, privileged: true}' | dry"
case_ deny  require-run-as-non-root   "only fault: runAsNonRoot unset"                 "pod t5    '$GOOD_IMAGE'                          \"\$RES\" ''        | dry"
case_ deny  disallow-latest-tag       "DEPLOYMENT nginx:latest (autogen catches it)"  "kubectl -n $NS create deployment bad --image=nginx:latest --dry-run=server" multi
case_ admit -                         "our chart: catalog-svc Deployment + 2 hook Jobs" "helm template catalog-svc charts/service -n $NS -f values/dev/catalog-svc/values.yaml | kubectl apply -n $NS --dry-run=server -f -"
case_ admit -                         "nginx:latest in 'default' (out of scope)"       "kubectl -n default create deployment bad --image=nginx:latest --dry-run=server"

# ---------------------------------------------------------------------------
say "result"
kubectl delete pod audit-me -n "$NS" --ignore-not-found >/dev/null
if [ "${1:-}" = --clean ]; then
  kind delete cluster --name "$CLUSTER" --kubeconfig "$KUBECONFIG"
else
  echo "  cluster kept -- delete it with: kind delete cluster --name $CLUSTER"
fi
if [ "$FAILED" = 0 ]; then echo "  ALL CASES PASSED"; else echo "  SOME CASES FAILED"; exit 1; fi
