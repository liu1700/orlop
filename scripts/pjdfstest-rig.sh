#!/usr/bin/env bash
#
# POSIX-completeness rig: run pjdfstest against the full orlop data plane.
#
#   orlop-server (Go, mTLS, local store)  <-- binary dataplane protocol
#   orlop mount (Rust FUSE client, pre-enrolled hosted mode)
#   pjdfstest `prove` suite on the mounted directory
#
# Linux + root only (FUSE mount, multi-uid tests). Normally invoked inside the
# container built by scripts/pjdfstest-docker.sh; can also run on a disposable
# Linux host with cargo/go/fuse3/autotools installed.
#
# Env knobs:
#   RIG_DIR        scratch dir (default /tmp/orlop-pjdfs-rig; wiped on start)
#   RESULTS_DIR    where raw TAP + summary land (default $RIG_DIR/results)
#   PJDFSTEST_DIR  prebuilt pjdfstest checkout (default /opt/pjdfstest;
#                  cloned+built on the fly when absent)
#   PJDFS_FS       fs type reported to pjdfstest's conf (default ext4 — assert
#                  baseline Linux-fs expectations against orlop)
#   PJDFS_TESTS    subset to run, relative to pjdfstest/tests (default: all)
#   ORLOP_BUILD=0  skip cargo/go builds (binaries must already exist)
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

[[ "$(uname)" == "Linux" ]] || { echo "pjdfstest-rig: Linux only" >&2; exit 1; }
[[ "$(id -u)" == "0" ]] || { echo "pjdfstest-rig: must run as root" >&2; exit 1; }

RIG_DIR="${RIG_DIR:-/tmp/orlop-pjdfs-rig}"
RESULTS_DIR="${RESULTS_DIR:-$RIG_DIR/results}"
PJDFSTEST_DIR="${PJDFSTEST_DIR:-/opt/pjdfstest}"
PJDFS_FS="${PJDFS_FS:-ext4}"
PJDFS_TESTS="${PJDFS_TESTS:-}"
ORLOP_BUILD="${ORLOP_BUILD:-1}"

CERT_DIR="$RIG_DIR/certs"
DATA_DIR="$RIG_DIR/data"
LOG_DIR="$RIG_DIR/logs"
MNT="$RIG_DIR/mnt"
CLIENT_CERT_DIR="$RIG_DIR/client-certs"

SERVER_HOST="127.0.0.1"
OPS_PORT=18443
DATA_PORT=18444
TRUST_DOMAIN="orlop.pjdfs"
TENANT_ID="pjdfs-tenant"
AGENT_ID="pjdfs-agent"
ALLOC_ID="a1b2c3d4-0000-4000-8000-pjdfstest000"

SERVER_PID=""
MOUNT_PID=""

log() { printf '\n==> %s\n' "$*"; }
fail() { printf 'pjdfstest-rig: %s\n' "$*" >&2; exit 1; }
require_cmd() { command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"; }

cleanup() {
  if mountpoint -q "$MNT" 2>/dev/null; then
    fusermount3 -u "$MNT" 2>/dev/null || umount "$MNT" 2>/dev/null || true
  fi
  [[ -n "$MOUNT_PID" ]] && kill "$MOUNT_PID" 2>/dev/null || true
  [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null || true
}
trap cleanup EXIT

for c in openssl sqlite3 git prove fusermount3 findmnt; do require_cmd "$c"; done
if [[ "$ORLOP_BUILD" == "1" ]]; then require_cmd cargo; require_cmd go; fi

rm -rf "$RIG_DIR"
mkdir -p "$CERT_DIR" "$DATA_DIR" "$LOG_DIR" "$MNT" "$CLIENT_CERT_DIR" "$RESULTS_DIR"

# ── Binaries ─────────────────────────────────────────────────────────────────
ORLOP_BIN="${ORLOP_BIN:-$ROOT_DIR/target/release/orlop}"
SERVER_BIN="${SERVER_BIN:-$RIG_DIR/orlop-server}"
if [[ "$ORLOP_BUILD" == "1" ]]; then
  log "Building orlop (release) + orlop-server"
  # Drop any prior binary first: with a persistent cargo target volume, a
  # failed rebuild would otherwise leave the stale binary in place and the
  # rig would silently test old code (observed 2026-06-12).
  rm -f "$ORLOP_BIN" "$SERVER_BIN"
  cargo build --release --bin orlop
  ( cd cmd/orlop-server && go build -o "$SERVER_BIN" . )
fi
[[ -x "$ORLOP_BIN" ]] || fail "orlop binary missing at $ORLOP_BIN (build failed?)"
[[ -x "$SERVER_BIN" ]] || fail "orlop-server binary missing at $SERVER_BIN"

# ── Certificates ─────────────────────────────────────────────────────────────
# Plus the agent-scope SAN: the data plane
# rejects any client cert without spiffe://<td>/agent/<id> (single isolation
# policy; see cmd/orlop-server/identity.go certScopedAgentID).
log "Generating CA + server cert + agent-scoped client cert"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -keyout "$CERT_DIR/ca.key" -out "$CERT_DIR/ca.crt" \
  -subj "/CN=pjdfs-rig-ca" >/dev/null 2>&1

cat >"$CERT_DIR/server.cnf" <<EOF
[req]
prompt = no
distinguished_name = req_dn

[req_dn]
CN = $SERVER_HOST

[v3]
subjectAltName = IP:$SERVER_HOST,DNS:localhost
extendedKeyUsage = serverAuth
EOF
openssl req -new -nodes -newkey rsa:2048 \
  -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.csr" \
  -config "$CERT_DIR/server.cnf" >/dev/null 2>&1
openssl x509 -req -in "$CERT_DIR/server.csr" \
  -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
  -out "$CERT_DIR/server.crt" -days 2 -extfile "$CERT_DIR/server.cnf" -extensions v3 >/dev/null 2>&1

cat >"$CERT_DIR/client.cnf" <<EOF
[req]
prompt = no
distinguished_name = req_dn

[req_dn]
CN = pjdfs-user

[v3]
subjectAltName = URI:spiffe://$TRUST_DOMAIN/tenant/$TENANT_ID,URI:spiffe://$TRUST_DOMAIN/agent/$AGENT_ID
extendedKeyUsage = clientAuth
EOF
openssl req -new -nodes -newkey rsa:2048 \
  -keyout "$CERT_DIR/client.key" -out "$CERT_DIR/client.csr" \
  -config "$CERT_DIR/client.cnf" >/dev/null 2>&1
openssl x509 -req -in "$CERT_DIR/client.csr" \
  -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
  -out "$CERT_DIR/client.crt" -days 2 -extfile "$CERT_DIR/client.cnf" -extensions v3 >/dev/null 2>&1

# ── Tenant store + routes ────────────────────────────────────────────────────
log "Provisioning tenant store + routes.db"
TENANT_STORE="$DATA_DIR/tenant-store"
mkdir -p "$TENANT_STORE"
ROUTES_DB="$DATA_DIR/routes.db"
sqlite3 "$ROUTES_DB" <<SQL >/dev/null
create table if not exists entity_routes (
  entity_type text not null,
  entity_id text not null,
  virtual_path text not null,
  physical_uri text,
  metadata_json text,
  created_at text not null,
  updated_at text not null,
  primary key (entity_type, entity_id)
);
create table if not exists manifests (
  path text primary key,
  size integer not null,
  mode integer not null,
  mtime integer not null,
  version integer not null,
  chunks blob not null
);
create table if not exists chunks (
  hash blob primary key,
  size integer not null,
  refcount integer not null,
  added_at integer not null
);
create table if not exists dir_entries (
  parent text not null,
  name text not null,
  primary key (parent, name)
);
SQL

# ── Server ───────────────────────────────────────────────────────────────────
log "Writing orlop-server config"
SERVER_CFG="$RIG_DIR/orlop-server.yaml"
cat >"$SERVER_CFG" <<EOF
audit_log: $LOG_DIR/server-audit.log
server:
  ops_bind: "$SERVER_HOST:$OPS_PORT"
  data_bind: "$SERVER_HOST:$DATA_PORT"
tls:
  cert_file: $CERT_DIR/server.crt
  key_file: $CERT_DIR/server.key
  client_ca_file: $CERT_DIR/ca.crt
  trust_domain: $TRUST_DOMAIN
tenant:
  id: $TENANT_ID
  store:
    type: local
    root: $TENANT_STORE
  routes:
    type: sqlite
    path: $ROUTES_DB
policy:
  allow:
    - "**"
EOF

start_server() {
  "$SERVER_BIN" -config "$SERVER_CFG" >>"$LOG_DIR/server.log" 2>&1 &
  SERVER_PID=$!
  for _ in $(seq 1 100); do
    if (exec 3<>"/dev/tcp/$SERVER_HOST/$DATA_PORT") 2>/dev/null; then exec 3>&-; return 0; fi
    kill -0 "$SERVER_PID" 2>/dev/null || { cat "$LOG_DIR/server.log" >&2; fail "server exited early"; }
    sleep 0.2
  done
  cat "$LOG_DIR/server.log" >&2; fail "data port never came up"
}

log "Starting orlop-server"
start_server

# ── Pre-enrolled client identity ─────────────────────────────────────────────
# Mirrors docker/agent-entrypoint.sh Phase 2: cert.pem/key.pem/ca.pem +
# enrollment.json in cert_dir puts `orlop mount` in pre-enrolled hosted mode —
# no control plane, no /agent/enroll round-trip; the data-plane LeaseGrant
# still enforces the single-writer invariant.
log "Materialising pre-enrolled cert_dir + client config"
install -m 0600 "$CERT_DIR/client.crt" "$CLIENT_CERT_DIR/cert.pem"
install -m 0600 "$CERT_DIR/client.key" "$CLIENT_CERT_DIR/key.pem"
install -m 0600 "$CERT_DIR/ca.crt" "$CLIENT_CERT_DIR/ca.pem"
CERT_SERIAL="$(openssl x509 -in "$CLIENT_CERT_DIR/cert.pem" -noout -serial | cut -d= -f2 | tr 'A-F' 'a-f')"
cat >"$CLIENT_CERT_DIR/enrollment.json" <<EOF
{
  "allocation_id": "$ALLOC_ID",
  "server_addr": "$SERVER_HOST:$DATA_PORT",
  "cert_serial": "$CERT_SERIAL"
}
EOF
chmod 0600 "$CLIENT_CERT_DIR/enrollment.json"

CLIENT_CFG="$RIG_DIR/orlop-config.yaml"
cat >"$CLIENT_CFG" <<EOF
audit_log: $LOG_DIR/client-audit.log
fuse:
  # Conformance mount: let the kernel enforce POSIX uid/gid/mode access checks
  # (the EACCES/EPERM "B-class" assertions). OFF in the product (single-identity
  # disk; nonroot executor reads root-owned files via allow_other).
  enforce_permissions: true
hosted:
  control_plane_url: "http://127.0.0.1:1"
  cert_dir: $CLIENT_CERT_DIR
  mount_root: "/$AGENT_ID"
policy:
  readonly: false
EOF

# ── Mount ────────────────────────────────────────────────────────────────────
export HOME="$RIG_DIR/home" XDG_CACHE_HOME="$RIG_DIR/cache"
mkdir -p "$HOME" "$XDG_CACHE_HOME"

start_mount() {
  "$ORLOP_BIN" --config "$CLIENT_CFG" mount --foreground --mountpoint "$MNT" --no-inject \
    >>"$LOG_DIR/mount.log" 2>&1 &
  MOUNT_PID=$!
  for _ in $(seq 1 150); do
    mountpoint -q "$MNT" && return 0
    kill -0 "$MOUNT_PID" 2>/dev/null || { tail -20 "$LOG_DIR/mount.log" >&2; fail "orlop mount exited early"; }
    sleep 0.2
  done
  tail -20 "$LOG_DIR/mount.log" >&2; fail "mount did not become ready"
}

# Tear down and bring back the whole stack. Used when a test kills the FUSE
# daemon mid-suite (e.g. the truncate-to-huge-size abort): the server restart
# clears the in-memory exclusive "/" mount lease the dead client still holds.
restart_stack() {
  fusermount3 -u "$MNT" 2>/dev/null || umount -l "$MNT" 2>/dev/null || true
  [[ -n "$MOUNT_PID" ]] && kill "$MOUNT_PID" 2>/dev/null || true
  [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null || true
  wait "$MOUNT_PID" "$SERVER_PID" 2>/dev/null || true
  sleep 0.5
  start_server
  start_mount
}

export RUST_BACKTRACE=1
log "Mounting orlop FUSE at $MNT"
start_mount

log "Mount smoke (create/write/read/rename/unlink)"
echo smoke >"$MNT/_rig-smoke"
grep -q smoke "$MNT/_rig-smoke"
mv "$MNT/_rig-smoke" "$MNT/_rig-smoke2"
rm "$MNT/_rig-smoke2"

# ── pjdfstest ────────────────────────────────────────────────────────────────
if [[ ! -x "$PJDFSTEST_DIR/pjdfstest" ]]; then
  log "Building pjdfstest in $PJDFSTEST_DIR"
  if [[ ! -d "$PJDFSTEST_DIR" ]]; then
    git clone --depth 1 https://github.com/pjd/pjdfstest "$PJDFSTEST_DIR"
  fi
  ( cd "$PJDFSTEST_DIR" && autoreconf -ifs && ./configure && make pjdfstest ) \
    >>"$LOG_DIR/pjdfstest-build.log" 2>&1
fi
git -C "$PJDFSTEST_DIR" rev-parse HEAD >"$RESULTS_DIR/pjdfstest-commit.txt" 2>/dev/null || true

# tests/conf detects fs via `df -PT .`, which reports FUSE.ORLOP (or fails —
# no statfs). Patch in an env override so we can assert the EXT4/baseline
# expectation set against the orlop mount.
if ! grep -q PJDFS_FS_OVERRIDE "$PJDFSTEST_DIR/tests/conf"; then
  sed -i 's|^if \[ -z "${fs}" \]; then|fs="${PJDFS_FS_OVERRIDE:-${fs}}"\nif [ -z "${fs}" ]; then|' \
    "$PJDFSTEST_DIR/tests/conf"
  grep -q PJDFS_FS_OVERRIDE "$PJDFSTEST_DIR/tests/conf" || fail "failed to patch pjdfstest tests/conf"
fi

# Run per category so one mount-killing operation doesn't zero out coverage
# for everything after it. Before each category: if the mount is dead, record
# the casualty and restart the full stack.
if [[ -n "$PJDFS_TESTS" ]]; then
  CATEGORIES=("$PJDFS_TESTS")
else
  CATEGORIES=()
  for d in "$PJDFSTEST_DIR/tests"/*/; do CATEGORIES+=("$(basename "$d")"); done
fi

log "Running pjdfstest (fs=$PJDFS_FS) — categories: ${CATEGORIES[*]}"
: >"$RESULTS_DIR/raw.tap"
: >"$RESULTS_DIR/mount-deaths.txt"
PROVE_RC=0
PREV_CAT="(start)"
for cat in "${CATEGORIES[@]}"; do
  # timeout guards: a half-dead mount can hang stat/mkdir indefinitely
  if ! timeout 10 mountpoint -q "$MNT" || ! timeout 15 ls "$MNT" >/dev/null 2>&1; then
    echo "mount died during: $PREV_CAT" | tee -a "$RESULTS_DIR/mount-deaths.txt"
    tail -5 "$LOG_DIR/mount.log" >>"$RESULTS_DIR/mount-deaths.txt" || true
    restart_stack
  fi
  WORKDIR="$MNT/pjdfs-$cat"
  timeout 15 mkdir -p "$WORKDIR" 2>/dev/null || { restart_stack; mkdir -p "$WORKDIR"; }
  log "category: $cat"
  set +e
  ( cd "$WORKDIR" && fs="$PJDFS_FS" os=Linux timeout 1800 \
      prove -rv "$PJDFSTEST_DIR/tests/$cat" ) >>"$RESULTS_DIR/raw.tap" 2>&1
  rc=$?
  set -e
  [[ $rc -ne 0 ]] && PROVE_RC=$rc
  PREV_CAT="$cat"
done
if ! mountpoint -q "$MNT"; then
  echo "mount died during: $PREV_CAT" | tee -a "$RESULTS_DIR/mount-deaths.txt"
  tail -5 "$LOG_DIR/mount.log" >>"$RESULTS_DIR/mount-deaths.txt" || true
fi
echo "$PROVE_RC" >"$RESULTS_DIR/prove-exit-code.txt"

log "Summarising results"
python3 - "$RESULTS_DIR/raw.tap" "$RESULTS_DIR/summary.tsv" <<'PY'
import re, sys
raw, out = sys.argv[1], sys.argv[2]
cur = None
stats = {}   # script -> [ok, notok, failed_descriptions]
for line in open(raw, errors="replace"):
    m = re.match(r"^(/\S+?/tests/\S+?\.t)\s", line)
    if m:
        cur = re.sub(r"^.*?/tests/", "", m.group(1))
        stats.setdefault(cur, [0, 0, []])
        continue
    if cur is None:
        continue
    if re.match(r"^ok\b", line):
        stats[cur][0] += 1
    elif re.match(r"^not ok\b", line):
        stats[cur][1] += 1
        stats[cur][2].append(line.strip())
with open(out, "w") as f:
    f.write("test\tok\tnot_ok\n")
    for k in sorted(stats):
        f.write(f"{k}\t{stats[k][0]}\t{stats[k][1]}\n")
total_ok = sum(v[0] for v in stats.values())
total_bad = sum(v[1] for v in stats.values())
print(f"pjdfstest: {total_ok} ok, {total_bad} not ok across {len(stats)} scripts")
with open(out.replace("summary.tsv", "failures.txt"), "w") as f:
    for k in sorted(stats):
        for d in stats[k][2]:
            f.write(f"{k}\t{d}\n")
PY

cp "$LOG_DIR/mount.log" "$LOG_DIR/server.log" "$RESULTS_DIR/" 2>/dev/null || true
log "Done. Results in $RESULTS_DIR (raw.tap, summary.tsv, failures.txt)"
exit 0
