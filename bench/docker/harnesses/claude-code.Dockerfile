# Claude Code (closed source, Tier B): official npm package, metadata only, no login (A16).
FROM harnesswatch-bench-base:1
ARG VERSION=2.1.300
RUN npm install -g "@anthropic-ai/claude-code@${VERSION}" && npm cache clean --force
USER agent
WORKDIR /workspace
