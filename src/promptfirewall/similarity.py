"""Semantic-ish similarity detection using TF-IDF + cosine similarity.

This is deliberately lightweight (no embedding model download, no network
call) so the firewall works fully offline and starts in milliseconds. TF-IDF
cosine similarity won't catch a cleverly reworded attack the way a real
sentence-embedding model would, but it generalizes past exact-string matching
enough to catch near-paraphrases of the corpus in `corpus.py` — and it costs
nothing to run inline on every request.
"""

from __future__ import annotations

from dataclasses import dataclass

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from .corpus import KNOWN_INJECTIONS


@dataclass
class SimilarityMatch:
    score: float
    closest_example: str


class SimilarityDetector:
    """Fits a TF-IDF vectorizer on the known-injection corpus once, then
    scores arbitrary input text against it on every call."""

    def __init__(self, corpus: list[str] | None = None):
        self._corpus = corpus if corpus is not None else KNOWN_INJECTIONS
        self._vectorizer = TfidfVectorizer(
            lowercase=True,
            ngram_range=(1, 2),
            stop_words="english",
            min_df=1,
        )
        self._corpus_matrix = self._vectorizer.fit_transform(self._corpus)

    def score(self, text: str) -> SimilarityMatch:
        query_vec = self._vectorizer.transform([text])
        similarities = cosine_similarity(query_vec, self._corpus_matrix)[0]
        best_idx = similarities.argmax()
        return SimilarityMatch(
            score=float(similarities[best_idx]),
            closest_example=self._corpus[best_idx],
        )
