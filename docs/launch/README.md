# Launch & Community Kit

Operational assets for publishing and promoting this project. Nothing here is auto-published; every post is reviewed by the maintainer first.

| File | Purpose |
|---|---|
| [`medium-launch-post.md`](medium-launch-post.md) | Medium launch article (draft) |
| [`linkedin-post.md`](linkedin-post.md) | LinkedIn post + follow-up series (draft) |
| [`comment-playbook.md`](comment-playbook.md) | Reply rules and canned responses for Medium/LinkedIn/GitHub |
| [`verification-checklist.md`](verification-checklist.md) | Pre-publish claim audit + 48h follow-up SLA |
| [`metrics-tracker.csv`](metrics-tracker.csv) | Weekly metrics sheet (import to any spreadsheet) |

## Publish sequence

1. Run the [verification checklist](verification-checklist.md); fill every `TODO`.
2. **Tue–Thu morning (audience local time):** publish Medium with canonical links to GitHub.
3. Same day: LinkedIn post linking Medium + GitHub (3–5 hashtags, tag sparingly).
4. +24–48h: short demo clip to X, Dev.to (canonical → Medium), relevant communities. Read each venue's self-promotion rules first.
5. Respond to comments within 24h using the [playbook](comment-playbook.md).
6. Weekly: update the [tracker](metrics-tracker.csv); ship one follow-up post per 1–2 weeks.

## Follow-up post ideas (all grounded in the repo)

| Post | Source of truth |
|---|---|
| Why FLAG exists: ambiguity as a first-class verdict | README "false positives", `detector.py` thresholds |
| Reading the eval notebook honestly: BLOCK recall 0.05 | `notebooks/detection_evaluation.ipynb` |
| Indirect injection in a telecom NOC copilot | `examples/telecom_network_ops_example.py` |
| Step-up auth on FLAG for fintech agents | `examples/fintech_transaction_assistant_example.py` |
| Roadmap: embedding backend vs. TF-IDF | README Roadmap |
