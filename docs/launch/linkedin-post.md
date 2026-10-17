# LinkedIn drafts (maintainer reviews before posting)

## Launch post (≈ same day as Medium)

I open-sourced a prompt-injection firewall for LLM apps — and published its weak spots next to its strengths.

• Problem: LLMs that read untrusted text and can call tools are exposed to injection (OWASP LLM01).
• What it is: offline Python library + API + web UI. 15 regex signatures, structural heuristics, and TF-IDF similarity → one 0–100 score → ALLOW / FLAG / BLOCK.
• Honest numbers: on my small held-out set, BLOCK-only recall is 0.05 (precision 1.00); FLAG+BLOCK reaches 0.65 recall at 0.72 precision. Method is in the repo — reproduce it, then tell me where it's wrong.

Try it: `docker compose up`
Write-up: [Medium link]
Code: https://github.com/Mangesh-Bhattacharya/llm-prompt-injection-firewall

Looking for contributors on an embedding backend and a public-dataset benchmark. DMs open.

#LLMSecurity #PromptInjection #OpenSource #AISecurity #Python

## Follow-up series (1 per week, each links to a repo artifact)

1. **Why FLAG exists** — three outcomes beat two when stakes differ.
2. **Reading my own eval honestly** — why BLOCK recall is 0.05 and what that implies.
3. **Indirect injection in a telecom NOC copilot** — poisoned ticket walkthrough.
4. **Step-up auth for fintech agents** — treating FLAG as a trigger.
5. **Contributor spotlight / release notes** — name contributors with PR links.
