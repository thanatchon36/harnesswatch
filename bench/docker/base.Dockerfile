# Bench/observe base: Node 22 + Python 3 + git, non-root user `agent` (uid 1000).
# Harness images build FROM this. No credentials are ever baked in.
FROM node@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates python3 python3-pytest procps ripgrep \
    && rm -rf /var/lib/apt/lists/* \
    && userdel -r node \
    && useradd -m -u 1000 -s /bin/bash agent \
    && mkdir -p /workspace && chown agent:agent /workspace \
    && git config --system user.name "Bench Agent" && git config --system user.email "agent@bench.invalid" \
    && git config --system init.defaultBranch main
ENV NPM_CONFIG_UPDATE_NOTIFIER=false NPM_CONFIG_FUND=false
