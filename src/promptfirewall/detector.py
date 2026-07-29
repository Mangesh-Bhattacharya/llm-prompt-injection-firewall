"""Core detection engine: combines pattern matching, heuristics, and TF-IDF
similarity into a single risk score and verdict.

Usage:
    from promptfirewall import PromptFirewall

    firewall = PromptFirewall()
    result = firewall.analyze("Ignore all previous instructions...")
    if result.verdict == Verdict.BLOCK:
        raise ValueError("blocked: prompt injection detected")
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .heuristics import HeuristicSignal, run_heuristics
from .patterns import PATTERNS, InjectionPattern
from .similarity import SimilarityDetector, SimilarityMatch

# Similarity score above which a near-paraphrase of a known attack counts as
# a matched signal in its own right.
SIMILARITY_MATCH_THRESHOLD = 0.35
SIMILARITY_WEIGHT = 25

# Risk-score thresholds that decide the final verdict. Tuned so a single
# strong signal (e.g. a fake system tag) flags for review, while two or more
# signals — or one very strong one — blocks outright.
FLAG_THRESHOLD = 25
BLOCK_THRESHOLD = 50


class Verdict(str, Enum):
    ALLOW = "allow"
    FLAG = "flag"
    BLOCK = "block"


@dataclass
class MatchedPattern:
    name: str
    category: str
    weight: int
    description: str
    matched_text: str


@dataclass
class AnalysisResult:
    text: str
    risk_score: int
    verdict: Verdict
    matched_patterns: list[MatchedPattern] = field(default_factory=list)
    heuristic_signals: list[HeuristicSignal] = field(default_factory=list)
    similarity: SimilarityMatch | None = None

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "risk_score": self.risk_score,
            "matched_patterns": [
                {
                    "name": m.name,
                    "category": m.category,
                    "weight": m.weight,
                    "description": m.description,
                    "matched_text": m.matched_text,
                }
                for m in self.matched_patterns
            ],
            "heuristic_signals": [
                {"name": h.name, "score": h.score, "detail": h.detail}
                for h in self.heuristic_signals
            ],
            "similarity": (
                {
                    "score": round(self.similarity.score, 3),
                    "closest_known_example": self.similarity.closest_example,
                }
                if self.similarity
                else None
            ),
        }


class PromptFirewall:
    """Analyzes arbitrary text for prompt-injection risk before it reaches an
    LLM (or analyzes LLM *output* before it reaches a downstream tool/action —
    the same techniques apply to indirect injection via retrieved documents)."""

    def __init__(
        self,
        patterns: list[InjectionPattern] | None = None,
        enable_similarity: bool = True,
        flag_threshold: int = FLAG_THRESHOLD,
        block_threshold: int = BLOCK_THRESHOLD,
    ):
        self._patterns = patterns if patterns is not None else PATTERNS
        self._similarity_detector = SimilarityDetector() if enable_similarity else None
        self._flag_threshold = flag_threshold
        self._block_threshold = block_threshold

    def analyze(self, text: str) -> AnalysisResult:
        if not text or not text.strip():
            return AnalysisResult(text=text, risk_score=0, verdict=Verdict.ALLOW)

        matched_patterns = self._match_patterns(text)
        heuristic_signals = run_heuristics(text)

        score = sum(m.weight for m in matched_patterns) + sum(h.score for h in heuristic_signals)

        similarity_match: SimilarityMatch | None = None
        if self._similarity_detector is not None:
            similarity_match = self._similarity_detector.score(text)
            if similarity_match.score >= SIMILARITY_MATCH_THRESHOLD:
                score += SIMILARITY_WEIGHT

        score = min(score, 100)
        verdict = self._score_to_verdict(score)

        return AnalysisResult(
            text=text,
            risk_score=score,
            verdict=verdict,
            matched_patterns=matched_patterns,
            heuristic_signals=heuristic_signals,
            similarity=similarity_match,
        )

    def _match_patterns(self, text: str) -> list[MatchedPattern]:
        matches = []
        for pattern in self._patterns:
            m = pattern.regex.search(text)
            if m:
                matches.append(
                    MatchedPattern(
                        name=pattern.name,
                        category=pattern.category,
                        weight=pattern.weight,
                        description=pattern.description,
                        matched_text=m.group(0)[:120],
                    )
                )
        return matches

    def _score_to_verdict(self, score: int) -> Verdict:
        if score >= self._block_threshold:
            return Verdict.BLOCK
        if score >= self._flag_threshold:
            return Verdict.FLAG
        return Verdict.ALLOW
