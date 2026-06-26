#!/usr/bin/env bash
# Container PID 1 for orlop-agent images.
#
# Supports two boot modes, auto-detected from the environment:
#
# Phase 1 (orlop-spawner exec path):
#   Env:  ORLOP_CREDENTIALS_JSON  — the full credentials.json blob from `orlop login`
#   Mode: long-lived container; `orlop mount` runs, then sleeps forever so
#         orlop-spawner can `docker exec` arbitrary commands inside.
#
# Phase 2 (anonymous Try-it sandbox, PTY path):
#   Files: ${ORLOP_SECRETS_DIR}/client.crt   — per-session mTLS leaf cert
#          ${ORLOP_SECRETS_DIR}/client.key   — corresponding private key
#          ${ORLOP_SECRETS_DIR}/allocation_id — UUID of the anonymous allocation
#          ${ORLOP_SECRETS_DIR}/ca.pem        — CA chain for server verification
#                                               (optional; fetched from control if absent)
#   Env:  ORLOP_SECRETS_DIR     — defaults to /run/orlop-secrets
#         ORLOP_CONTROL_URL     — set by the spawner; used to fetch the CA if absent
#         ORLOP_AGENT           — opencode | hermes (default: hermes)
#   Mode: interactive PTY. `orlop mount` runs, then exec the chosen agent as PID 1.
#         Docker sends SIGTERM directly to the agent on `docker stop`; no trap needed.
#
# orlop-spawner mounts the secrets dir read-only under /run/orlop-secrets.
# The Rust `orlop` CLI expects cert_dir/{cert.pem,key.pem,ca.pem}; this script
# replicates the secrets into /run/orlop-certs with the expected names before
# running `orlop mount`.

set -euo pipefail

MOUNT=${ORLOP_MOUNT_POINT:-/workspace}
HOME_DIR=${HOME:-/workspace/.home}
SECRETS_DIR=${ORLOP_SECRETS_DIR:-/run/orlop-secrets}
CREDS_DIR=/run/orlop
CREDS_FILE=$CREDS_DIR/credentials.json
CONFIG_FILE=$CREDS_DIR/config.yaml
CERT_DIR=/run/orlop-certs

# ── Mode detection ──────────────────────────────────────────────────────────
if [[ -n "${ORLOP_CREDENTIALS_JSON:-}" ]]; then
    MODE=phase1
elif [[ -f "${SECRETS_DIR}/client.crt" ]]; then
    MODE=phase2
else
    echo "agent-entrypoint: need either ORLOP_CREDENTIALS_JSON (phase 1) or ${SECRETS_DIR}/client.crt (phase 2)" >&2
    exit 64
fi

if ! command -v orlop >/dev/null 2>&1; then
    echo "agent-entrypoint: orlop binary not on PATH; image is misbuilt" >&2
    exit 65
fi

install -d -m 0700 "$CREDS_DIR"
umask 0177

# ── Phase 1: write credentials.json ─────────────────────────────────────────
if [[ "$MODE" == phase1 ]]; then
    printf '%s' "$ORLOP_CREDENTIALS_JSON" > "$CREDS_FILE"
    # Minimal config — `orlop mount` requires --config (or one at
    # ~/.config/orlop/config.yaml) even when credentials.json already has the
    # control_plane_url. `hosted: {}` is the empty-but-valid marker that tells
    # orlop "yes, this is a hosted deploy; fall back to credentials.json for
    # control_plane_url + server_addr".
    cat > "$CONFIG_FILE" <<YAML
audit_log: /tmp/orlop-audit.log
hosted: {}
policy:
  # readonly defaults to true in src/config.rs (safety-first for an
  # interactive user). The agent container is the opposite case — the
  # entire point is writes — so flip it. The tenant-side policy in
  # orlop-server still has the final say.
  readonly: false
YAML
fi

# ── Phase 2: materialise cert_dir from /run/orlop-secrets ───────────────────
if [[ "$MODE" == phase2 ]]; then
    # The orlop CLI expects cert_dir/{cert.pem, key.pem, ca.pem, enrollment.json}
    # (see src/enroll.rs FILE_CERT / FILE_KEY / FILE_CA / FILE_ENROLLMENT
    # constants). The spawner writes client.crt / client.key / ca.pem /
    # enrollment.json / allocation_id into /run/orlop-secrets.
    install -d -m 0700 "$CERT_DIR"
    cp "${SECRETS_DIR}/client.crt" "${CERT_DIR}/cert.pem"
    chmod 0400 "${CERT_DIR}/cert.pem"
    cp "${SECRETS_DIR}/client.key" "${CERT_DIR}/key.pem"
    chmod 0400 "${CERT_DIR}/key.pem"

    # CA cert: the spawner always bundles it now (Phase 2 cert-only mode
    # requires it — the in-container `orlop mount` never makes an HTTP call
    # to fetch it). Fail loud if absent.
    if [[ -f "${SECRETS_DIR}/ca.pem" ]]; then
        cp "${SECRETS_DIR}/ca.pem" "${CERT_DIR}/ca.pem"
        chmod 0400 "${CERT_DIR}/ca.pem"
    else
        echo "agent-entrypoint: ERROR: ${SECRETS_DIR}/ca.pem missing — spawner is misconfigured" >&2
        exit 68
    fi

    # enrollment.json is the trigger for the CLI's pre-enrolled hosted
    # mode. Its presence tells `orlop mount` to skip the HTTP /agent/enroll
    # round-trip and treat the bundled cert as the session identity.
    if [[ -f "${SECRETS_DIR}/enrollment.json" ]]; then
        cp "${SECRETS_DIR}/enrollment.json" "${CERT_DIR}/enrollment.json"
        chmod 0400 "${CERT_DIR}/enrollment.json"
    else
        echo "agent-entrypoint: ERROR: ${SECRETS_DIR}/enrollment.json missing — spawner is misconfigured" >&2
        exit 69
    fi

    # Read allocation_id; the orlop CLI picks it up from the env var
    # ORLOP_ALLOCATION_ID (set by the spawner directly) but reading from the
    # secrets file provides a belt-and-suspenders fallback.
    if [[ -f "${SECRETS_DIR}/allocation_id" ]]; then
        ALLOC_ID=$(cat "${SECRETS_DIR}/allocation_id")
        export ORLOP_ALLOCATION_ID=${ORLOP_ALLOCATION_ID:-$ALLOC_ID}
    fi

    # Config for phase 2: hosted.cert_dir points at the materialised cert_dir
    # above. control_plane_url comes from ORLOP_CONTROL_URL (set by spawner)
    # and is REQUIRED in pre-enrolled mode — the CLI errors out otherwise
    # because there's no credentials.json to fall back to.
    CTRL_URL=${ORLOP_CONTROL_URL:-}
    if [[ -z "$CTRL_URL" ]]; then
        echo "agent-entrypoint: ERROR: ORLOP_CONTROL_URL unset — required in phase 2" >&2
        exit 70
    fi
    # audit_log defaults to ./audit.log; cwd at exec time is /workspace
    # (Dockerfile WORKDIR), which lives on the read-only rootfs in Phase 2
    # before the FUSE mount comes up. Pin it to /tmp/orlop-audit.log
    # (tmpfs) so the daemonize hand-off can open it.
    cat > "$CONFIG_FILE" <<YAML
audit_log: /tmp/orlop-audit.log
hosted:
  control_plane_url: "${CTRL_URL}"
  cert_dir: "${CERT_DIR}"
policy:
  readonly: false
YAML
fi

umask 0022

mkdir -p "$MOUNT"

# Orlop opens a local chunk cache BEFORE setting up the FUSE mount, and
# the cache root resolves from XDG_CACHE_HOME / HOME. The image's ENV
# points both into /workspace/.home, which is the very mountpoint we're
# trying to bring up — pre-mount that path doesn't exist yet AND the
# container is read-only. Override to a tmpfs path so cache_open succeeds.
# After mount we'll set HOME to /workspace/.home so agent state still
# persists onto the disk.
export XDG_CACHE_HOME=/tmp/orlop-cache
mkdir -p "$XDG_CACHE_HOME"

# ── Mount ───────────────────────────────────────────────────────────────────
# Mount asynchronously; the orlop binary forks the FUSE daemon. Once
# /workspace becomes a mountpoint the daemon is wired up.
# --no-inject is mandatory: orlop's default injects a Orlop stanza into
# the cwd's AGENTS.md, and the cwd inside the container is /workspace —
# the FUSE mount we're setting up. Without --no-inject the daemon
# deadlocks on its own getattr (observed on staging 2026-05-16).
if [[ "$MODE" == phase1 ]]; then
    orlop mount --mountpoint "$MOUNT" \
        --config "$CONFIG_FILE" \
        --credentials "$CREDS_FILE" \
        --no-inject \
        >/tmp/orlop-mount.log 2>&1 &
else
    # Phase 2: no credentials.json; identity comes from cert_dir via config.
    orlop mount --mountpoint "$MOUNT" \
        --config "$CONFIG_FILE" \
        --no-inject \
        >/tmp/orlop-mount.log 2>&1 &
fi
ORLOP_PID=$!

deadline=$((SECONDS + 30))
while ! mountpoint -q "$MOUNT"; do
    if (( SECONDS >= deadline )); then
        echo "agent-entrypoint: orlop mount did not come up in 30s" >&2
        echo "----- /tmp/orlop-mount.log -----" >&2
        cat /tmp/orlop-mount.log >&2 || true
        kill "$ORLOP_PID" 2>/dev/null || true
        exit 66
    fi
    # bail early if the orlop process already died
    if ! kill -0 "$ORLOP_PID" 2>/dev/null; then
        echo "agent-entrypoint: orlop mount exited before $MOUNT was ready" >&2
        cat /tmp/orlop-mount.log >&2 || true
        exit 67
    fi
    sleep 0.1
done

echo "agent-entrypoint: $MOUNT mounted (mode=$MODE pid=$ORLOP_PID session=${ORLOP_SESSION_ID:-unknown})"

# HOME lives on the Orlop disk so agent auth/config/shell history persist
# across spawn cycles. Create it lazily; first-ever mount has no .home/.
mkdir -p "$HOME_DIR" "$HOME_DIR/.config" "$HOME_DIR/.local/share" "$HOME_DIR/.cache"

# ── Phase 1: block forever for docker exec ───────────────────────────────────
if [[ "$MODE" == phase1 ]]; then
    # Hand off to sleep so the container stays alive for docker exec calls.
    # Forward SIGTERM/SIGINT so `docker stop` unmounts cleanly.
    trap 'fusermount3 -u "$MOUNT" 2>/dev/null || true; kill "$ORLOP_PID" 2>/dev/null || true; exit 0' TERM INT
    exec sleep infinity
fi

# ── Phase 2: exec the agent as PID 1 ────────────────────────────────────────
# The trap above is not registered in phase 2 because exec replaces this
# process — Docker sends SIGTERM directly to the agent binary (PID 1), which
# handles its own shutdown. The container exits when the agent exits.
AGENT=${ORLOP_AGENT:-hermes}
cd /workspace
case "$AGENT" in
    opencode)
        exec opencode
        ;;
    hermes)
        exec hermes
        ;;
    *)
        echo "agent-entrypoint: unknown agent: $AGENT" >&2
        exit 64
        ;;
esac

# ── Manual verification ──────────────────────────────────────────────────────
# Syntax check (run from the repo root or docker/ dir):
#
#   bash -n docker/agent-entrypoint.sh
#
# static analysis (skip if not installed):
#
#   command -v shellcheck >/dev/null && shellcheck docker/agent-entrypoint.sh || echo "shellcheck not installed; skipping"
#
# Phase 1 smoke (requires a real credentials.json):
#
#   docker run --rm --cap-add SYS_ADMIN --device /dev/fuse \
#     -e ORLOP_CREDENTIALS_JSON="$(cat ~/.config/orlop/credentials.json)" \
#     orlop-agent:latest
#
# Phase 2 smoke (requires certs from orlop-control):
#
#   docker run --rm -it --cap-add SYS_ADMIN --device /dev/fuse \
#     -v /path/to/secrets:/run/orlop-secrets:ro \
#     -e ORLOP_CONTROL_URL=https://control.example.com \
#     -e ORLOP_AGENT=hermes \
#     orlop-agent:latest
