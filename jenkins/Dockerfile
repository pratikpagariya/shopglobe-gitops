# Pre-baking plugins is the difference between a controller that starts in 30
# seconds and one that downloads 60 plugins on every restart -- and between a
# reproducible build and whatever the update centre happened to serve today.
FROM jenkins/jenkins:lts-jdk21

COPY plugins.txt /usr/share/jenkins/ref/plugins.txt

# resolves each plugin to the newest version compatible with
# THIS Jenkins release, rather than bleeding edge. Without it a plugin can
# pull in a core requirement the base image does not satisfy.
RUN jenkins-plugin-cli --plugin-file /usr/share/jenkins/ref/plugins.txt

# No setup wizard: the whole point is that nothing is configured by clicking.
ENV JAVA_OPTS="-Djenkins.install.runSetupWizard=false -Dhudson.model.DownloadService.noSignatureCheck=true"
ENV CASC_JENKINS_CONFIG=/var/jenkins_config/jenkins.yaml
