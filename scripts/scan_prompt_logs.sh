#!/usr/bin/env bash
#
# scan_prompt_logs.sh — batch-scan a directory of text files with promptfirewall
# and print a SOC-style summary table.
#
# Use case: a security/SRE team routinely dumps ingested prompts, chat
# transcripts, support tickets, or retrieved documents to a directory (e.g.
# from a log shipper) and wants a periodic or CI-gated sweep for injection
# attempts — without writing custom Python for the aggregation step.
#
# Usage:
#   ./scripts/scan_prompt_logs.sh <directory> [--fail-on-block]
#
# Exit status:
#   0  scan completed, no BLOCK verdicts (or --fail-on-block not set)
#   1  scan completed, at least one BLOCK verdict AND --fail-on-block was set
#   2  usage error / directory not found
#
# Example (CI step):
#   ./scripts/scan_prompt_logs.sh scripts/sample_logs --fail-on-block

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

usage() {
    echo "Usage: $0 <directory> [--fail-on-block]" >&2
    exit 2
}

[ $# -ge 1 ] || usage

TARGET_DIR="$1"
FAIL_ON_BLOCK=0
if [ "${2:-}" = "--fail-on-block" ]; then
    FAIL_ON_BLOCK=1
fi

if [ ! -d "$TARGET_DIR" ]; then
    echo "error: '$TARGET_DIR' is not a directory" >&2
    exit 2
fi

GREEN='\033[92m'; YELLOW='\033[93m'; RED='\033[91m'; RESET='\033[0m'

allow_count=0
flag_count=0
block_count=0
files_scanned=0

printf "%-45s %-8s %-6s\n" "FILE" "VERDICT" "SCORE"
printf '%.0s-' {1..65}; echo

for f in "$TARGET_DIR"/*.txt; do
    [ -e "$f" ] || continue
    files_scanned=$((files_scanned + 1))

    json_out="$(cd "$REPO_ROOT" && python3 cli.py --json --file "$f")"
    verdict="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['verdict'])" "$json_out")"
    score="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['risk_score'])" "$json_out")"

    case "$verdict" in
        allow) color="$GREEN"; allow_count=$((allow_count + 1)) ;;
        flag)  color="$YELLOW"; flag_count=$((flag_count + 1)) ;;
        block) color="$RED"; block_count=$((block_count + 1)) ;;
        *)     color="$RESET" ;;
    esac

    printf "%-45s ${color}%-8s${RESET} %-6s\n" "$(basename "$f")" "$verdict" "$score/100"
done

echo
printf '%.0s-' {1..65}; echo
echo "Scanned: $files_scanned file(s)   allow=$allow_count  flag=$flag_count  block=$block_count"

if [ "$files_scanned" -eq 0 ]; then
    echo "warning: no .txt files found in '$TARGET_DIR'" >&2
fi

if [ "$block_count" -gt 0 ] && [ "$FAIL_ON_BLOCK" -eq 1 ]; then
    echo -e "${RED}FAILED: ${block_count} file(s) scored BLOCK and --fail-on-block was set.${RESET}" >&2
    exit 1
fi

exit 0
