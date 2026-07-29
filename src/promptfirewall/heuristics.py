"""Signal-based heuristics that don't fit a single regex.

These catch attacks that are structurally suspicious even when the wording
doesn't match a known phrase — e.g. a long base64 blob, an unusual density of
imperative verbs, or control characters used to hide text from a human
reviewer while still being parsed by the model.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_IMPERATIVE_VERBS = {
    "ignore", "disregard", "forget", "override", "bypass", "disable",
    "reveal", "print", "output", "leak", "exfiltrate", "execute", "run",
    "grant", "unlock", "jailbreak", "pretend", "act", "roleplay",
}
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_ZERO_WIDTH_RE = re.compile(r"[​-‏‪-‮﻿]")


@dataclass
class HeuristicSignal:
    name: str
    score: int
    detail: str


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def detect_high_entropy_blob(text: str) -> HeuristicSignal | None:
    """Flag long base64-looking runs with high character entropy (likely an
    encoded payload the attacker wants decoded and obeyed downstream)."""
    for match in _BASE64_RE.finditer(text):
        blob = match.group(0)
        entropy = _shannon_entropy(blob)
        if entropy > 4.0 and len(blob) >= 40:
            return HeuristicSignal(
                "high_entropy_blob",
                20,
                f"Found a {len(blob)}-char high-entropy token (entropy={entropy:.2f}) — possible encoded payload.",
            )
    return None


def detect_imperative_density(text: str) -> HeuristicSignal | None:
    """A cluster of injection-flavored imperative verbs close together is a
    stronger signal than any single verb in isolation."""
    words = re.findall(r"[a-zA-Z']+", text.lower())
    if not words:
        return None
    hits = sum(1 for w in words if w in _IMPERATIVE_VERBS)
    density = hits / len(words)
    if hits >= 3 and density > 0.03:
        return HeuristicSignal(
            "imperative_density",
            15,
            f"{hits} injection-flavored imperative verbs found ({density:.1%} of words).",
        )
    return None


def detect_control_characters(text: str) -> HeuristicSignal | None:
    """Zero-width and control characters are used to smuggle instructions
    past human review while a tokenizer still 'sees' them."""
    zero_width_hits = len(_ZERO_WIDTH_RE.findall(text))
    control_hits = len(_CONTROL_CHAR_RE.findall(text))
    if zero_width_hits > 0 or control_hits > 2:
        return HeuristicSignal(
            "hidden_characters",
            25,
            f"Found {zero_width_hits} zero-width and {control_hits} control characters — likely used to hide text from a human reviewer.",
        )
    return None


def detect_excessive_delimiters(text: str) -> HeuristicSignal | None:
    """A burst of markdown/structural delimiters is a common way to fake a
    'new message' boundary the model may treat as authoritative."""
    delimiter_count = text.count("---") + text.count("###") + text.count("```")
    if delimiter_count >= 4:
        return HeuristicSignal(
            "excessive_delimiters",
            10,
            f"{delimiter_count} structural delimiters found — possible attempt to fake a new context boundary.",
        )
    return None


ALL_HEURISTICS = [
    detect_high_entropy_blob,
    detect_imperative_density,
    detect_control_characters,
    detect_excessive_delimiters,
]


def run_heuristics(text: str) -> list[HeuristicSignal]:
    signals = []
    for heuristic in ALL_HEURISTICS:
        result = heuristic(text)
        if result is not None:
            signals.append(result)
    return signals
