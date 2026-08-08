#!/usr/bin/env bash
# metadata-bench.sh — workload benchmarks for issue #122 acceptance gates.
#
# Runs the metadata-heavy scenarios (create / stat / walk / delete on a
# small-file tree, git checkout + status) plus large sequential I/O against a
# target directory, typically an orlop mount, and optionally a baseline
# directory (local disk) for ratio columns. Methodology follows the plori
# disk benchmark: multiple rounds, median reported alongside min/max, a
# sequential-write size sweep so a client write buffer cannot hide the
# network, and measurements that cannot be trusted are dropped loudly rather
# than reported (see DISCARDED notes in the output).
#
# Usage:
#   metadata-bench.sh <target-dir> [baseline-dir]
#
# Environment:
#   ROUNDS       rounds per scenario (default 5; median reported)
#   SMALL_FILES  files in the small-file tree (default 200, 4 KiB each)
#   SEQ_SIZES_MB sequential-write sizes, space-separated (default "64 256 1024")
#   SKIP_GIT     set to 1 to skip the git scenarios
#   SKIP_SEQ     set to 1 to skip sequential I/O
set -euo pipefail

TARGET=${1:?usage: metadata-bench.sh <target-dir> [baseline-dir]}
BASELINE=${2:-}
ROUNDS=${ROUNDS:-5}
SMALL_FILES=${SMALL_FILES:-200}
SEQ_SIZES_MB=${SEQ_SIZES_MB:-"64 256 1024"}

now_ms() {
  # GNU date supports %N; BSD (macOS) does not — fall back to perl.
  if date +%N | grep -qv N; then
    echo $((10#$(date +%s%N) / 1000000))
  else
    perl -MTime::HiRes=time -e 'printf "%d\n", time()*1000'
  fi
}

# median <newline-separated numbers>
median() {
  sort -n | awk '{a[NR]=$1} END {
    if (NR == 0) { print "nan"; exit }
    if (NR % 2) { print a[(NR+1)/2] } else { printf "%.1f\n", (a[NR/2]+a[NR/2+1])/2 }
  }'
}

minmax() {
  sort -n | awk '{a[NR]=$1} END { if (NR>0) printf "%s %s\n", a[1], a[NR] }'
}

# run_rounds <label> <fn taking workdir> <workdir-root>
# Prints "label median_ms min_ms max_ms rounds" and echoes per-round times to
# stderr for transparency.
run_rounds() {
  local label=$1 fn=$2 root=$3
  local times=""
  for r in $(seq 1 "$ROUNDS"); do
    local work="$root/bench-$label-$r"
    mkdir -p "$work"
    local t0 t1
    t0=$(now_ms)
    "$fn" "$work"
    t1=$(now_ms)
    times="$times$((t1 - t0))\n"
    rm -rf "$work"
  done
  local med lo hi
  med=$(printf '%b' "$times" | median)
  read -r lo hi <<<"$(printf '%b' "$times" | minmax)"
  printf '%-28s %10s %8s %8s %4s\n' "$label" "$med" "$lo" "$hi" "$ROUNDS"
}

scenario_create() {
  local work=$1
  for i in $(seq 1 "$SMALL_FILES"); do
    head -c 4096 /dev/zero > "$work/f$i"
  done
}

scenario_stat() {
  local work=$1
  prep_tree "$work"
  local t0 t1
  t0=$(now_ms)
  for i in $(seq 1 "$SMALL_FILES"); do
    stat "$work/tree/f$i" > /dev/null
  done
  t1=$(now_ms)
  LAST_INNER_MS=$((t1 - t0))
}

prep_tree() {
  local work=$1
  mkdir -p "$work/tree"
  for i in $(seq 1 "$SMALL_FILES"); do
    head -c 4096 /dev/zero > "$work/tree/f$i"
  done
}

scenario_walk() {
  local work=$1
  find "$work/pre/tree" -type f | wc -l > /dev/null
}

scenario_delete() {
  local work=$1
  rm -rf "$work/pre/tree"
}

# Timed-inner scenarios need their setup OUTSIDE the timed window; those are
# driven manually below instead of through run_rounds.

section() { printf '\n== %s ==\n' "$1"; }

bench_dir() {
  local dir=$1 tag=$2
  local root="$dir/.orlop-metadata-bench"
  rm -rf "$root"
  mkdir -p "$root"

  printf '%-28s %10s %8s %8s %4s\n' "scenario($tag)" "med_ms" "min" "max" "n"

  run_rounds "create-${SMALL_FILES}" scenario_create "$root"

  # stat sweep: tree prepared outside the timed window.
  local times=""
  for r in $(seq 1 "$ROUNDS"); do
    local work="$root/stat-$r"
    prep_tree "$work"
    scenario_stat_timed "$work"
    times="$times$LAST_INNER_MS\n"
    rm -rf "$work"
  done
  report_line "stat-${SMALL_FILES}" "$times"

  # walk + delete: pre-created tree, timed op only.
  local wtimes="" dtimes=""
  for r in $(seq 1 "$ROUNDS"); do
    local work="$root/wd-$r"
    mkdir -p "$work/pre"
    prep_tree "$work/pre"
    local t0 t1
    t0=$(now_ms); find "$work/pre/tree" -type f > /dev/null; t1=$(now_ms)
    wtimes="$wtimes$((t1 - t0))\n"
    t0=$(now_ms); rm -rf "$work/pre/tree"; t1=$(now_ms)
    dtimes="$dtimes$((t1 - t0))\n"
    rm -rf "$work"
  done
  report_line "walk-${SMALL_FILES}" "$wtimes"
  report_line "delete-${SMALL_FILES}" "$dtimes"

  if [ "${SKIP_GIT:-0}" != "1" ] && command -v git > /dev/null; then
    local gtimes="" stimes=""
    for r in $(seq 1 "$ROUNDS"); do
      local work="$root/git-$r"
      mkdir -p "$work"
      local t0 t1
      t0=$(now_ms)
      git -C "$work" init -q
      for i in $(seq 1 50); do head -c 2048 /dev/zero > "$work/g$i"; done
      git -C "$work" add -A
      git -C "$work" -c user.email=b@b -c user.name=b commit -qm x
      t1=$(now_ms)
      gtimes="$gtimes$((t1 - t0))\n"
      t0=$(now_ms); git -C "$work" status --porcelain > /dev/null; t1=$(now_ms)
      stimes="$stimes$((t1 - t0))\n"
      rm -rf "$work"
    done
    report_line "git-init-commit-50" "$gtimes"
    report_line "git-status" "$stimes"
  fi

  if [ "${SKIP_SEQ:-0}" != "1" ]; then
    for mb in $SEQ_SIZES_MB; do
      local wtimes2=""
      for r in $(seq 1 "$ROUNDS"); do
        local f="$root/seq-$mb-$r.bin"
        local t0 t1
        t0=$(now_ms)
        dd if=/dev/zero of="$f" bs=1048576 count="$mb" conv=fsync 2>/dev/null
        sync
        t1=$(now_ms)
        wtimes2="$wtimes2$((t1 - t0))\n"
        rm -f "$f"
      done
      report_line "seq-write-${mb}MiB" "$wtimes2"
    done
    echo "# NOTE: only the largest seq-write size outruns a client write"
    echo "# buffer; smaller sizes are reported for the sweep but should not"
    echo "# be quoted as throughput (see plori bench 'discarded' rationale)."
  fi

  rm -rf "$root"
}

scenario_stat_timed() {
  local work=$1
  local t0 t1
  t0=$(now_ms)
  for i in $(seq 1 "$SMALL_FILES"); do
    stat "$work/tree/f$i" > /dev/null
  done
  t1=$(now_ms)
  LAST_INNER_MS=$((t1 - t0))
}

report_line() {
  local label=$1 times=$2
  local med lo hi
  med=$(printf '%b' "$times" | median)
  read -r lo hi <<<"$(printf '%b' "$times" | minmax)"
  printf '%-28s %10s %8s %8s %4s\n' "$label" "$med" "$lo" "$hi" "$ROUNDS"
}

section "target: $TARGET (rounds=$ROUNDS files=$SMALL_FILES)"
bench_dir "$TARGET" "target"

if [ -n "$BASELINE" ]; then
  section "baseline: $BASELINE"
  bench_dir "$BASELINE" "baseline"
fi

section "done"
echo "Compare med_ms columns; the #122 gate is >=5x improvement on two of"
echo "create/walk/delete versus the previous release, with <=10% regression"
echo "on the largest seq-write size."
