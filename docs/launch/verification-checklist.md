# Pre-publish Verification (every item must be checked)

| # | Claim in the post | Evidence | Verified |
|---|---|---|---|
| 1 | 15 patterns / 6 categories | `len(PATTERNS)`, `patterns.py` categories | ☐ |
| 2 | Thresholds 25 / 50 | `detector.py` | ☐ |
| 3 | Example verdicts (95 / 0 / 25) | run `cli.py --json` on `main` | ☑ 2026-10-17 |
| 4 | 45 tests pass, ruff clean | `pytest`, `ruff check .` | ☑ 2026-10-17 |
| 5 | Eval numbers (1.00/0.05, 0.72/0.65) | re-execute notebook; paste output | ☐ |
| 6 | Latency claim | benchmark script + hardware + method; otherwise delete the claim | ☐ |
| 7 | OWASP ranking / incident stats | primary source link (not secondary blog) | ☐ |
| 8 | Docker quick start works | fresh clone, `docker compose up` | ☐ |
| 9 | Screenshots/links resolve | click every link | ☐ |
| 10 | Contact/“open to roles” line approved by maintainer | — | ☐ |

**Follow-up SLA:** any question needing verification gets a sourced answer within 48 hours; log it in the tracker.
