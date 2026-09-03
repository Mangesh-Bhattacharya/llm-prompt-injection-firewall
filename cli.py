#!/usr/bin/env python3
"""Command-line interface for promptfirewall.

Usage:
    python cli.py "Ignore all previous instructions..."
    python cli.py --file suspicious_prompt.txt
    echo "some text" | python cli.py --stdin
    python cli.py --json "some text"          # machine-readable output
"""

from __future__ import annotations

import argparse
import json
import sys

from src.promptfirewall import PromptFirewall, Verdict

_VERDICT_COLOR = {
    Verdict.ALLOW: "\033[92m",  # green
    Verdict.FLAG: "\033[93m",  # yellow
    Verdict.BLOCK: "\033[91m",  # red
}
_RESET = "\033[0m"


def _print_human(result) -> None:
    color = _VERDICT_COLOR.get(result.verdict, "")
    print(
        f"{color}Verdict: {result.verdict.value.upper()}{_RESET}"
        f"  (risk score: {result.risk_score}/100)"
    )

    if result.matched_patterns:
        print("\nMatched patterns:")
        for m in result.matched_patterns:
            print(f"  [{m.weight:>2}] {m.name} ({m.category})")
            print(f"       {m.description}")
            print(f'       matched: "{m.matched_text}"')

    if result.heuristic_signals:
        print("\nHeuristic signals:")
        for h in result.heuristic_signals:
            print(f"  [{h.score:>2}] {h.name}: {h.detail}")

    if result.similarity and result.similarity.score >= 0.15:
        print(f"\nClosest known injection example (similarity={result.similarity.score:.2f}):")
        print(f'  "{result.similarity.closest_example}"')

    if not result.matched_patterns and not result.heuristic_signals:
        print("\nNo suspicious patterns or heuristics triggered.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze text for prompt-injection risk.")
    parser.add_argument("text", nargs="?", help="Text to analyze.")
    parser.add_argument("--file", help="Read text to analyze from a file.")
    parser.add_argument("--stdin", action="store_true", help="Read text to analyze from stdin.")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON.")
    parser.add_argument(
        "--fail-on-block",
        action="store_true",
        help="Exit with status 1 if the verdict is BLOCK (useful in CI/pre-commit hooks).",
    )
    args = parser.parse_args()

    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                text = f.read()
        except FileNotFoundError:
            print(f"error: file not found: {args.file}", file=sys.stderr)
            return 2
        except IsADirectoryError:
            print(f"error: '{args.file}' is a directory, not a file", file=sys.stderr)
            return 2
        except PermissionError:
            print(f"error: permission denied reading '{args.file}'", file=sys.stderr)
            return 2
        except UnicodeDecodeError:
            print(f"error: '{args.file}' is not valid UTF-8 text", file=sys.stderr)
            return 2
    elif args.stdin:
        text = sys.stdin.read()
    elif args.text:
        text = args.text
    else:
        parser.error("Provide text as an argument, --file, or --stdin.")
        return 2

    firewall = PromptFirewall()
    result = firewall.analyze(text)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        _print_human(result)

    if args.fail_on_block and result.verdict == Verdict.BLOCK:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
