# FlowControl runner: the isolated environment the AI agent runs in.
#
# What this image is for (docs/threat-model.md, categories 0, 3, 5):
#   - the agent runs here, the gateway runs outside it
#   - no real credentials are ever baked in or passed in
#   - the agent runs as an unprivileged user, and only /workspace is meant to be writable
#
# Network isolation is NOT in this file: it comes from how the container is started
# (an internal Docker network whose only other member is the gateway; see step 2).

FROM node:22-bookworm-slim

# Tools a coding agent normally needs. curl and dnsutils are also used by the T00 bypass tests.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git python3 ca-certificates curl dnsutils \
 && rm -rf /var/lib/apt/lists/*

# Claude Code, pinned so test runs are repeatable (record it with every test, threat model §7).
# Upgrade deliberately: docker build --build-arg CLAUDE_CODE_VERSION=x.y.z
ARG CLAUDE_CODE_VERSION=2.1.319
RUN npm install -g "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" \
 && npm cache clean --force

# Don't let the agent update itself or make calls that bypass the model route.
ENV DISABLE_AUTOUPDATER=1 \
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1

# Skips Claude Code's first-run setup questions (see the script for exactly what it seeds).
COPY --chmod=755 entrypoint.sh /usr/local/bin/fc-entrypoint

# The node base image ships an unprivileged "node" user (uid 1000). The agent runs as it.
RUN mkdir -p /workspace && chown node:node /workspace
USER node
WORKDIR /workspace

ENTRYPOINT ["/usr/local/bin/fc-entrypoint"]
CMD ["claude"]
