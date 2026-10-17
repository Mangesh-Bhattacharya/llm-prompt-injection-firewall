# Contributing

Contributions are welcome — especially new detection patterns, corpus entries, false-positive reports, and evaluation improvements.

## Where to start

- Issues labelled **`good first issue`** are scoped for a first PR.
- The [Roadmap](README.md#roadmap) lists larger open items.
- Found a **detection bypass**? Do *not* open a public issue — follow [`SECURITY.md`](SECURITY.md).

## Dev setup

```bash
git clone https://github.com/Mangesh-Bhattacharya/llm-prompt-injection-firewall
cd llm-prompt-injection-firewall
pip install -r requirements-dev.txt
pytest tests/ -v
ruff check .
```

Or run everything in Docker: `docker compose up` (UI at http://localhost:8000/).

## Pull requests

1. Open an issue first for anything beyond a small fix.
2. Branch from `main`; keep PRs small and focused, one concern per PR.
3. Add or update tests. Pattern changes need at least one **positive** and one **benign (negative)** test case.
4. `pytest tests/` and `ruff check .` must pass (CI runs both on Python 3.10–3.12).
5. If you change detection behaviour, re-run the [evaluation notebook](notebooks/detection_evaluation.ipynb) and update README numbers only with the reproduced output.
6. Fill in the PR template.

## Style

- Python ≥3.10, typed, line length 100 (enforced by ruff).
- Comments only for non-obvious intent.
- No new runtime dependencies without discussion — the project is deliberately dependency-light and offline.

## Adding detection patterns

- Add to `src/promptfirewall/patterns.py` with a category, weight, and description.
- Prefer anchored, specific expressions; avoid catastrophic backtracking (add a long-input test).
- Include the false-positive risk in the PR description.

## Conduct

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
