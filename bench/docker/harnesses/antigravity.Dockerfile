# Antigravity CLI (closed source, Tier B): official installer, run only inside this image build.
# Pre-login observation only (A19); no Google account or API key ever enters the container.
FROM harnesswatch-bench-base:1
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
USER agent
WORKDIR /home/agent
RUN curl -fsSL https://antigravity.google/cli/install.sh -o /tmp/install.sh \
    && sha256sum /tmp/install.sh > /home/agent/.install.sh.sha256 \
    && bash /tmp/install.sh && rm /tmp/install.sh
ENV PATH=/home/agent/.local/bin:$PATH
WORKDIR /workspace
