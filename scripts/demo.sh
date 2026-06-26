#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

CONFIG="${ORLOP_CONFIG:-config.demo.yaml}"
ORLOP="./target/debug/orlop"
MOUNTPOINT="/tmp/orlop-demo/mnt"
DB="/tmp/orlop-demo/orlop.db"
AUDIT_LOG="/tmp/orlop-demo/audit.log"

cleanup() {
  if findmnt "$MOUNTPOINT" >/dev/null 2>&1; then
    "$ORLOP" --config "$CONFIG" unmount >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "Building orlop"
cargo build

echo "Preparing local demo runtime"
mkdir -p /tmp/orlop-demo "$MOUNTPOINT"
rm -f "$DB" "$AUDIT_LOG"

"$ORLOP" --config "$CONFIG" init
"$ORLOP" --config "$CONFIG" route set user user_123 /entities/user_123
"$ORLOP" --config "$CONFIG" route set account account_acme /entities/account_acme
"$ORLOP" --config "$CONFIG" route set ticket ticket_999 /entities/account_acme/tickets/ticket_999

echo "Mounting fixture entity store at $MOUNTPOINT"
"$ORLOP" --config "$CONFIG" mount --foreground &
MOUNT_PID=$!

for _ in $(seq 1 50); do
  if findmnt "$MOUNTPOINT" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$MOUNT_PID" >/dev/null 2>&1; then
    wait "$MOUNT_PID"
  fi
  sleep 0.1
done

if ! findmnt "$MOUNTPOINT" >/dev/null 2>&1; then
  echo "Mount did not become ready at $MOUNTPOINT" >&2
  exit 1
fi

USER_PATH="$("$ORLOP" --config "$CONFIG" entity resolve user user_123)"
ACCOUNT_PATH="$("$ORLOP" --config "$CONFIG" entity resolve account account_acme)"
TICKET_PATH="$("$ORLOP" --config "$CONFIG" entity resolve ticket ticket_999)"

echo
echo "Resolved paths"
printf 'user:    %s\n' "$USER_PATH"
printf 'account: %s\n' "$ACCOUNT_PATH"
printf 'ticket:  %s\n' "$TICKET_PATH"

echo
echo "Checking warm directory walks use kernel cache"
: >"$AUDIT_LOG"
find "$MOUNTPOINT/entities" -maxdepth 4 -print >/tmp/orlop-demo/find-first.out
FIRST_READDIRPLUS_COUNT="$(grep -c '"event":"readdirplus_entry"' "$AUDIT_LOG" || true)"
find "$MOUNTPOINT/entities" -maxdepth 4 -print >/tmp/orlop-demo/find-second.out
SECOND_READDIRPLUS_COUNT="$(grep -c '"event":"readdirplus_entry"' "$AUDIT_LOG" || true)"
OPENDIR_COUNT="$(grep -c '"event":"opendir"' "$AUDIT_LOG" || true)"
if [[ "$FIRST_READDIRPLUS_COUNT" -eq 0 ]]; then
  echo "Expected first find to produce readdirplus_entry events" >&2
  exit 1
fi
if [[ "$SECOND_READDIRPLUS_COUNT" -ne "$FIRST_READDIRPLUS_COUNT" ]]; then
  echo "Expected second find to reuse cached directory entries" >&2
  echo "readdirplus_entry count after first find:  $FIRST_READDIRPLUS_COUNT" >&2
  echo "readdirplus_entry count after second find: $SECOND_READDIRPLUS_COUNT" >&2
  exit 1
fi
if [[ "$OPENDIR_COUNT" -eq 0 ]]; then
  echo "Expected find to produce audited opendir events" >&2
  exit 1
fi

echo
echo "find $MOUNTPOINT/entities"
find "$MOUNTPOINT/entities" -maxdepth 4 -print

echo
echo "cat $USER_PATH/profile.json"
cat "$USER_PATH/profile.json"

echo
echo "rg \"renewal|billing|ticket\" $USER_PATH"
rg "renewal|billing|ticket" "$USER_PATH"

echo
echo "cat $TICKET_PATH/notes.md"
cat "$TICKET_PATH/notes.md"

echo
echo "Checking denied path"
if cat "$ACCOUNT_PATH/secrets/internal.md" >/tmp/orlop-demo/denied.out 2>/tmp/orlop-demo/denied.err; then
  echo "Expected denied path to fail, but it was readable" >&2
  exit 1
fi
cat /tmp/orlop-demo/denied.err

echo
echo "Checking denied content is hidden from rg"
if rg "confidential-payroll-adjustment" "$MOUNTPOINT/entities" >/tmp/orlop-demo/secret-rg.out 2>&1; then
  echo "Denied fixture content appeared in rg results" >&2
  cat /tmp/orlop-demo/secret-rg.out >&2
  exit 1
fi
echo "Denied fixture content is not visible through the mount"

echo
echo "Recent audit events"
"$ORLOP" --config "$CONFIG" audit tail --limit 12

echo
echo "Demo complete"
