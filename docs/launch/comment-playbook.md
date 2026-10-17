# Comment & Engagement Playbook

## Rules
1. **Factual only.** Never state a feature, timeline, or number you can't point to in the repo. If unsure: "I'll confirm and update here" → sourced answer within 48h.
2. **Short:** acknowledge → direct answer → evidence link → next step.
3. **Public corrections:** thank, fix, link the PR/issue.
4. **Bypass reports:** never discuss exploit strings publicly; redirect to private advisory.
5. **Recruiters/collabs:** reply once publicly, move to DM/email.
6. **Abuse/spam:** apply `CODE_OF_CONDUCT.md`; log in `metrics-tracker.csv` notes.
7. **Humans send the replies.** Agents draft; the maintainer approves before anything is posted.

## Canned replies

| Situation | Draft |
|---|---|
| Good question | "Thanks, {name} — {one-sentence answer}. Details: {README/code link}. Happy to dig in if you open an issue." |
| False-positive report | "Thanks for the example, {name}. That's the TF-IDF layer alone — documented in the README's false-positives note. If you open a *False positive* issue with the `--json` output I'll add it as a regression case." |
| Bypass claim | "Appreciate it, {name}. Please don't post the input here — report it via the repo's Security tab (private advisory) and I'll triage within 48h." |
| Technical correction | "You're right, {name} — {what was wrong}. Fixed in {PR link}; please review." |
| "Does it beat X?" | "I haven't benchmarked against X. Current measured numbers and their limits are in the evaluation notebook: {link}. A public-dataset benchmark is on the roadmap." |
| "Does it support {language/feature}?" | "Not currently — {limitation from README Limitations}. Tracking: {issue link or 'open to a PR'}." |
| Recruiting | "Thanks — I'd like to learn more. Could you send the role and org details via {approved channel}?" |
| Needs verification | "Good point — I'll verify and update this thread within 48 hours." |
