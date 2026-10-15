# Generic image for harnesses distributed on npm: `--build-arg PKG=<name>@<exact version>`.
# Install scripts run here, inside the image build, never on the host (A06).
FROM harnesswatch-bench-base:1
ARG PKG
RUN test -n "$PKG" && npm install -g "$PKG" && npm cache clean --force
USER agent
WORKDIR /workspace
