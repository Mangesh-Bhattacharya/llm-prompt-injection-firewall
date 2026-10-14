# AI-security content series (1–2 posts/day, small POC each)

Each post = one threat, one runnable POC under `examples/`, one measured result (including failures). Post mornings; link the repo, not a pitch.

| # | Topic | POC | Status |
|---|---|---|---|
| 1 | Indirect injection via RAG + taint-aware tool gating | `indirect_injection_rag_poc.py` | drafted |
| 2 | Why regex + TF-IDF misses paraphrases (measured recall from the eval notebook) | notebook | todo |
| 3 | Zero-width / homoglyph smuggling vs. the heuristics layer | `examples/unicode_smuggling_poc.py` | todo |
| 4 | Tool-argument injection: scanning the model's *outputs* | extend `AgentGuard.authorize` | todo |
| 5 | Prompt-leak canaries: detecting system-prompt exfiltration | `examples/canary_token_poc.py` | todo |
| 6 | Scanner as SIEM sensor: JSON-lines logging (roadmap item) | `logging.py` | todo |
| 7 | MCP/tool-description poisoning | `examples/tool_poisoning_poc.py` | todo |

Product direction (pick one, per peer-review feedback): **AgentGuard** — a policy layer that decides which tool calls an LLM agent may make given where its context came from. Scanner = sensor; guard = control.
