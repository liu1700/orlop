#!/usr/bin/env bash
# Diff two orlop-bench JSON result files and render a markdown table.
# Highlights p50_ms regressions of more than 5%.
#
# Usage:
#   bench-compare.sh <baseline.json> <candidate.json> [--threshold-pct N]
# Output: markdown to stdout.

set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <baseline.json> <candidate.json> [--threshold-pct N]" >&2
  exit 2
fi

BASELINE="$1"; shift
CANDIDATE="$1"; shift
THRESHOLD=5

while [[ $# -gt 0 ]]; do
  case "$1" in
    --threshold-pct) THRESHOLD="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

if ! command -v jq >/dev/null 2>&1; then
  echo "jq not found; install jq" >&2
  exit 127
fi

[[ -f "$BASELINE"  ]] || { echo "missing $BASELINE"  >&2; exit 1; }
[[ -f "$CANDIDATE" ]] || { echo "missing $CANDIDATE" >&2; exit 1; }

# Build joined rows: name, status, p50/p99/ops/duration_s for both sides.
joined=$(jq -n \
  --slurpfile a "$BASELINE" \
  --slurpfile b "$CANDIDATE" \
  '
  ($a[0].workloads // []) as $A
  | ($b[0].workloads // []) as $B
  | ($A | map({(.name): .}) | add // {}) as $am
  | ($B | map({(.name): .}) | add // {}) as $bm
  | ([$am, $bm] | map(keys) | add | unique) as $names
  | $names
  | map({
      name: .,
      a: $am[.],
      b: $bm[.]
    })
  ')

baseline_meta=$(jq -r '"\(.git_sha[0:8]) \(.timestamp) label=\(.label // "-") data_plane=\(.data_plane // "-")"' "$BASELINE")
candidate_meta=$(jq -r '"\(.git_sha[0:8]) \(.timestamp) label=\(.label // "-") data_plane=\(.data_plane // "-")"' "$CANDIDATE")

printf '## bench compare\n\n'
# shellcheck disable=SC2016  # backticks here are literal markdown, not command sub.
printf -- '- baseline:  %s — `%s`\n' "$baseline_meta" "$BASELINE"
# shellcheck disable=SC2016
printf -- '- candidate: %s — `%s`\n\n' "$candidate_meta" "$CANDIDATE"

printf '| workload | status | p50 ms (a → b) | Δ%%  | p99 ms (a → b) | ops (a → b) |\n'
printf '| --- | --- | --- | --- | --- | --- |\n'

# Render rows. Mark Δ% with a warning prefix if it crosses the threshold.
echo "$joined" | jq -r --argjson thr "$THRESHOLD" '
  .[] | . as $row
  | ($row.a // {}) as $a
  | ($row.b // {}) as $b
  | (
      if $a == {} then "missing-baseline"
      elif $b == {} then "missing-candidate"
      elif ($a.status == "skipped" or $b.status == "skipped") then "skipped"
      elif ($a.status == "error" or $b.status == "error") then "error"
      else "ok"
      end
    ) as $status
  | (($a.p50_ms // 0)) as $ap50
  | (($b.p50_ms // 0)) as $bp50
  | (($a.p99_ms // 0)) as $ap99
  | (($b.p99_ms // 0)) as $bp99
  | (($a.ops    // 0)) as $aops
  | (($b.ops    // 0)) as $bops
  | (
      if $ap50 > 0 then (($bp50 - $ap50) / $ap50 * 100) else 0 end
    ) as $delta
  | (
      if ($delta > $thr) then ":warning: +"
      elif ($delta < (-1 * $thr)) then ":small_red_triangle_down: "
      else ""
      end
    ) as $mark
  | "| \($row.name) | \($status) | \($ap50 | tostring | .[0:7]) → \($bp50 | tostring | .[0:7]) | \($mark)\($delta | tostring | .[0:6]) | \($ap99 | tostring | .[0:7]) → \($bp99 | tostring | .[0:7]) | \($aops) → \($bops) |"
'

# Surface a summary line — useful in CI when this script is captured.
echo
echo "Threshold for p50 regression highlight: ${THRESHOLD}%"
