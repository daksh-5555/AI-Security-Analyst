"""Dependency-free retrieval indexes over the knowledge corpus (M11).

- ``LexicalIndex``: Okapi BM25 over normalized tokens. Default, no provider.
- ``VectorIndex``: cosine similarity over embeddings from an
  ``EmbeddingProvider``. The built-in ``HashingEmbedder`` is a deterministic,
  local feature-hashing embedder: no model download and no network. A remote
  embedding provider can implement the same interface later.

Both are pure Python. That is ample for a curated corpus of a few hundred
chunks; a FAISS backend is an optional future change (ADR-0014).
"""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from collections.abc import Sequence
from typing import Final, Protocol

from app.services.knowledge.corpus import Chunk

_TOKEN: Final = re.compile(r"[a-z0-9]+")
_STOPWORDS: Final = frozenset(
    "a an and are as at be by can do does for from has have if in into is it its "
    "not of on or so such than that the their them then there these they this to "
    "use used uses was when where which while with without".split()
)


_SUFFIXES: Final = ("ing", "ed", "es", "s")


def _stem(token: str) -> str:
    """Tiny suffix stripper so "secrets"/"secret" and "encoded"/"encode" match."""
    if token.isdigit():
        return token
    for suffix in _SUFFIXES:
        if len(token) > len(suffix) + 3 and token.endswith(suffix):
            token = token[: -len(suffix)]
            break
    if len(token) > 4 and token.endswith("e"):
        token = token[:-1]
    return token


def tokenize(text: str) -> list[str]:
    return [_stem(t) for t in _TOKEN.findall(text.lower()) if t not in _STOPWORDS and len(t) > 1]


class LexicalIndex:
    name = "lexical"

    def __init__(self, chunks: Sequence[Chunk], *, k1: float = 1.5, b: float = 0.75) -> None:
        self._chunks = list(chunks)
        self._docs = [Counter(tokenize(f"{c.section} {c.text}")) for c in self._chunks]
        self._lengths = [sum(doc.values()) for doc in self._docs]
        self._avg = (sum(self._lengths) / len(self._lengths)) if self._lengths else 0.0
        frequency: Counter[str] = Counter()
        for doc in self._docs:
            frequency.update(doc.keys())
        total = len(self._docs)
        self._idf = {
            term: math.log(1 + (total - count + 0.5) / (count + 0.5))
            for term, count in frequency.items()
        }
        self._k1, self._b = k1, b

    def scores(self, query: str) -> dict[str, float]:
        terms = tokenize(query)
        result: dict[str, float] = {}
        for chunk, doc, length in zip(self._chunks, self._docs, self._lengths, strict=True):
            score = 0.0
            for term in terms:
                tf = doc.get(term, 0)
                if not tf:
                    continue
                norm = tf + self._k1 * (1 - self._b + self._b * length / (self._avg or 1))
                score += self._idf.get(term, 0.0) * tf * (self._k1 + 1) / norm
            if score > 0:
                result[chunk.id] = score
        return result


class EmbeddingError(RuntimeError):
    """The embedding provider could not produce vectors."""


class EmbeddingProvider(Protocol):
    name: str

    def embed(self, texts: Sequence[str]) -> list[list[float]]: ...


class HashingEmbedder:
    """Deterministic local embedding: hashed unigrams and bigrams, L2-normalized."""

    name = "hashing"

    def __init__(self, dimensions: int = 512) -> None:
        self.dimensions = dimensions

    def _bucket(self, feature: str) -> tuple[int, float]:
        digest = hashlib.sha256(feature.encode("utf-8")).digest()
        index = int.from_bytes(digest[:4], "big") % self.dimensions
        sign = 1.0 if digest[4] % 2 == 0 else -1.0
        return index, sign

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        vectors = []
        for text in texts:
            vector = [0.0] * self.dimensions
            tokens = tokenize(text)
            for feature in (
                *tokens,
                *(f"{a}_{b}" for a, b in zip(tokens, tokens[1:], strict=False)),
            ):
                index, sign = self._bucket(feature)
                vector[index] += sign
            norm = math.sqrt(sum(v * v for v in vector)) or 1.0
            vectors.append([v / norm for v in vector])
        return vectors


class VectorIndex:
    name = "vector"

    def __init__(self, chunks: Sequence[Chunk], embedder: EmbeddingProvider) -> None:
        self._chunks = list(chunks)
        self._embedder = embedder
        vectors = embedder.embed([f"{c.section} {c.text}" for c in self._chunks])
        if len(vectors) != len(self._chunks):
            raise EmbeddingError("embedding count does not match chunk count")
        self._vectors = vectors

    def scores(self, query: str) -> dict[str, float]:
        (query_vector,) = self._embedder.embed([query])
        result: dict[str, float] = {}
        for chunk, vector in zip(self._chunks, self._vectors, strict=True):
            score = sum(a * b for a, b in zip(query_vector, vector, strict=True))
            if score > 0:
                result[chunk.id] = score
        return result
