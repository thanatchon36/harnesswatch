FROM harnesswatch-bench-base:1
ARG VERSION=0.86.2
RUN apt-get update && apt-get install -y --no-install-recommends python3-venv && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /opt/aider && /opt/aider/bin/pip install --no-cache-dir "aider-chat==${VERSION}" \
    && ln -s /opt/aider/bin/aider /usr/local/bin/aider
USER agent
WORKDIR /workspace
