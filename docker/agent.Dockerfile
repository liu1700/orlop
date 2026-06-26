# orlop-agent: batteries-included per-session container image.
#
# Carries the orlop CLI + the agents Orlop is known to work with (opencode,
# hermes) so callers can run any of them out of the box. claude-code is
# intentionally NOT bundled — Anthropic's TOS treats claude-code as a
# per-developer tool, and running it from short-lived shared infrastructure
# would risk account bans. Users who want claude-code install it themselves
# inside the container (`npm i -g @anthropic-ai/claude-code`) once and it
# lives on their Orlop disk via HOME-on-Orlop.
#
# HOME = /workspace/.home, which means every agent's auth state, config,
# and shell history persist on the user's own Orlop disk. `opencode auth set`
# or `hermes auth login` once, and the credentials follow the user across
# sessions, machines, even agents — the actual delivery of Orlop's "disk
# follows you" pitch.
#
# Build (from the docker/ directory so COPY paths are relative to here, not
# the repo root):
#   docker build -t orlop-agent:latest \
#     [--build-arg ORLOP_BIN_URL=https://example.com/releases/orlop-linux-amd64] \
#     docker/
#
# Run (mirrors what orlop-spawner does):
#   docker run -d \
#     --cap-add SYS_ADMIN --device /dev/fuse \
#     --security-opt apparmor=unconfined \
#     -e ORLOP_TOKEN=orlop_xxx -e ORLOP_SESSION_ID=sess-a \
#     orlop-agent:latest

FROM debian:bookworm-slim

ARG ORLOP_BIN_URL=""

# Base system + Node (for opencode).
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        fuse3 \
        ca-certificates \
        curl \
        bash \
        coreutils \
        procps \
        git \
        gnupg && \
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    rm -rf /var/lib/apt/lists/*

# opencode via npm.
RUN npm install -g --no-fund --no-audit opencode-ai

# Hermes Agent (Nous Research) — the default agent the entrypoint launches,
# so any failure here must fail the image build. install.sh uses bash syntax;
# pipe to bash explicitly (Debian's /bin/sh is dash).
RUN set -eu; \
    curl -fsSL https://hermes-agent.nousresearch.com/install.sh -o /tmp/hermes-install.sh && \
    HERMES_NONINTERACTIVE=1 bash /tmp/hermes-install.sh && \
    rm -f /tmp/hermes-install.sh && \
    command -v hermes >/dev/null

# Orlop CLI: URL- or staged-binary path. Build context is docker/, so
# entrypoint + bin/ paths are relative to here.
COPY agent-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && \
    if [ -n "$ORLOP_BIN_URL" ]; then \
        curl -fsSL "$ORLOP_BIN_URL" -o /usr/local/bin/orlop && \
        chmod +x /usr/local/bin/orlop; \
    fi

COPY bin/ /tmp/orlop-binstage/
RUN if [ -f /tmp/orlop-binstage/orlop ]; then \
        install -m 0755 /tmp/orlop-binstage/orlop /usr/local/bin/orlop; \
    fi && \
    rm -rf /tmp/orlop-binstage

RUN mkdir -p /workspace

# HOME points into the Orlop-mounted workspace so agent auth/config/history
# persist on the user's disk. XDG variables match so tools that ignore HOME
# still land in the same tree.
ENV HOME=/workspace/.home \
    XDG_CONFIG_HOME=/workspace/.home/.config \
    XDG_DATA_HOME=/workspace/.home/.local/share \
    XDG_CACHE_HOME=/workspace/.home/.cache \
    ORLOP_MOUNT_POINT=/workspace
WORKDIR /workspace
ENTRYPOINT ["/entrypoint.sh"]
