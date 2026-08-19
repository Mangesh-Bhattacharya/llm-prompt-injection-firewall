"""Regex-based signatures for known prompt-injection techniques.

Each pattern is tagged with a category (mapped to OWASP LLM01: Prompt Injection
sub-techniques) and a weight used by the heuristic scorer. Patterns are
intentionally broad-but-anchored: they catch the *shape* of an attack
(imperative override, role hijack, delimiter escape, exfiltration request)
rather than any single wording, so paraphrases of a known technique still trip
the rule instead of only an exact string match.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class InjectionPattern:
    name: str
    category: str
    regex: re.Pattern
    weight: int
    description: str


def _p(
    name: str,
    category: str,
    pattern: str,
    weight: int,
    description: str,
    flags=re.IGNORECASE,
) -> InjectionPattern:
    return InjectionPattern(name, category, re.compile(pattern, flags), weight, description)


PATTERNS: list[InjectionPattern] = [
    # --- Instruction override -------------------------------------------------
    _p(
        "ignore_instructions",
        "instruction_override",
        r"\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all)\b[^.\n]{0,40}\b(instructions?|rules?|prompts?|context|directives?)\b",
        35,
        "Attempts to override or discard the system/developer instructions.",
    ),
    _p(
        "new_instructions",
        "instruction_override",
        r"\b(new|updated|real)\s+(instructions?|rules?|system prompt)\s*[:\-]",
        25,
        "Introduces a fake replacement instruction set.",
    ),
    _p(
        "from_now_on",
        "instruction_override",
        r"\bfrom now on\b[^.\n]{0,60}\b(you (will|must|shall)|respond|act|ignore)\b",
        20,
        "Classic 'from now on' behavioral override phrasing.",
    ),
    # --- Role / persona hijacking ----------------------------------------------
    _p(
        "persona_hijack",
        "role_hijack",
        r"\b(you are now|act as|pretend (to be|you are)|roleplay as|simulate being)\b"
        r"[^.\n]{0,60}\b(dan|developer mode|jailbroken|unfiltered|no restrictions|"
        r"without (any )?limits?|evil|opposite)\b",
        40,
        "Attempts to reassign the model's persona to bypass safety behavior.",
    ),
    _p(
        "dan_mode",
        "role_hijack",
        r"\b(dan mode|do anything now|developer mode|god mode|jailbreak(ed)?)\b",
        35,
        "References well-known jailbreak persona names.",
    ),
    _p(
        "dual_response",
        "role_hijack",
        r"\brespond (as|with)\s+(two|2)\b[^.\n]{0,40}"
        r"\b(one (normal|filtered)|one (jailbroken|unfiltered|uncensored))\b",
        30,
        "Dual-response jailbreak pattern (normal answer + 'unlocked' answer).",
    ),
    # --- System prompt / secret exfiltration ------------------------------------
    _p(
        "reveal_system_prompt",
        "exfiltration",
        r"\b(reveal|repeat|print|show|output|leak)\b[^.\n]{0,30}"
        r"\b(your\s+)?(system prompt|initial prompt|instructions|configuration)\b",
        35,
        "Attempts to exfiltrate the hidden system prompt or configuration.",
    ),
    _p(
        "reveal_secrets",
        "exfiltration",
        r"\b(what (is|are) your (api key|secret|token|credentials?))\b",
        35,
        "Attempts to extract secrets/credentials from the model context.",
    ),
    _p(
        "verbatim_above",
        "exfiltration",
        r"\b(repeat|print|output)\b[^.\n]{0,20}\beverything\b[^.\n]{0,20}\b(above|before this)\b",
        25,
        "Requests verbatim repetition of prior hidden context.",
    ),
    # --- Delimiter / context escape --------------------------------------------
    _p(
        "fake_closing_tag",
        "delimiter_escape",
        r"</?(system|assistant|user|instructions?|context|admin)>",
        30,
        "Fake role/context tags used to convince the model the system turn ended.",
    ),
    _p(
        "special_token_injection",
        "delimiter_escape",
        r"(<\|im_start\|>|<\|im_end\|>|\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>)",
        35,
        "Injects raw chat-template control tokens to hijack turn boundaries.",
    ),
    _p(
        "fence_breakout",
        "delimiter_escape",
        r"```[^`]{0,20}(system|end of prompt|ignore above)",
        20,
        "Uses a code fence to simulate a fake system boundary.",
    ),
    # --- Encoding / obfuscation tricks -------------------------------------------
    _p(
        "decode_and_execute",
        "obfuscation",
        r"\b(decode|base64[- ]decode)\b[^.\n]{0,30}\b(and (run|execute|follow|obey))\b",
        30,
        "Asks the model to decode an encoded payload and then act on it.",
    ),
    # --- Tool / agent hijacking (agentic LLM apps) --------------------------------
    _p(
        "tool_hijack",
        "agent_hijack",
        r"\b(call|invoke|use)\s+the\s+\w+\s+tool\s+(with|to)\b[^.\n]{0,60}\b(admin|root|delete|drop|transfer|wire)\b",
        30,
        "Attempts to redirect an agent's tool-calling toward a privileged/destructive action.",
    ),
    _p(
        "grant_permissions",
        "agent_hijack",
        r"\b(grant|give)\s+(me|yourself)\s+(admin|root|full)\s+(access|permissions?)\b",
        30,
        "Requests privilege escalation via natural-language instruction.",
    ),
]

CATEGORY_DESCRIPTIONS = {
    "instruction_override": "Instruction override — tries to discard system/developer rules",
    "role_hijack": "Role hijack — reassigns the model's persona to bypass safety behavior",
    "exfiltration": "Exfiltration — tries to leak the system prompt, secrets, or hidden context",
    "delimiter_escape": "Delimiter escape — injects fake role tags or chat-template tokens",
    "obfuscation": "Obfuscation — hides payloads via encoding to evade keyword filters",
    "agent_hijack": "Agent hijack — redirects tool-calling / actions in agentic LLM apps",
}
