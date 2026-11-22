"""Retrieve a few relevant, attributed guidance chunks for a finding (M11).

Filtering, in order:

1. stale documents (past their review interval) are excluded unless
   ``RAG_INCLUDE_STALE`` is set, in which case they are labelled stale;
2. documents whose categories or CWE identifiers match the finding are
   preferred; general documents (category ``*``) always qualify. Only when
   nothing matches is the whole corpus searched (``filtered=False``).

Failures never break scanning or explanations. A vector backend or embedding
provider failure falls back to the lexical index (``fallback_reason`` is
recorded). An invalid corpus raises ``KnowledgeBaseError``, which callers
treat as "no reference material". Retrieval reads guidance only; it has no
access to findings beyond the query text and cannot change them.
"""

from __future__ import annotations

import fnmatch
import logging
import threading
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import Any

from app.core.config import settings
from app.services.knowledge.corpus import Chunk, Corpus, KnowledgeBaseError, load_corpus
from app.services.knowledge.index import (
    EmbeddingError,
    EmbeddingProvider,
    HashingEmbedder,
    LexicalIndex,
    VectorIndex,
)

logger = logging.getLogger(__name__)

_MATCH_BONUS = 1.0


@dataclass(frozen=True)
class RetrievedChunk:
    id: str
    document_id: str
    title: str
    section: str
    text: str
    score: float
    source_type: str
    document_version: str
    updated_at: str
    license: str
    references: list[dict[str, str]]
    stale: bool

    def as_reference(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "section": self.section,
            "text": self.text,
            "source_type": self.source_type,
            "document_version": self.document_version,
            "updated_at": self.updated_at,
            "stale": self.stale,
        }

    def attribution(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "document_id": self.document_id,
            "title": self.title,
            "document_version": self.document_version,
            "license": self.license,
            "references": self.references,
            "stale": self.stale,
        }


@dataclass
class RetrievalResult:
    chunks: list[RetrievedChunk] = field(default_factory=list)
    backend: str = "lexical"
    fallback_reason: str | None = None
    filtered: bool = True
    knowledge_base_version: str | None = None

    def metadata(self, status: str) -> dict[str, Any]:
        return {
            "status": status,
            "backend": self.backend,
            "fallback_reason": self.fallback_reason,
            "filtered": self.filtered,
            "knowledge_base_version": self.knowledge_base_version,
            "source_ids": [chunk.id for chunk in self.chunks],
            "sources": [chunk.attribution() for chunk in self.chunks],
        }


class KnowledgeService:
    """Corpus plus indexes, built once per configuration and reused."""

    def __init__(self, embedder: EmbeddingProvider | None = None) -> None:
        self.corpus: Corpus = load_corpus(
            settings.rag_corpus_dir, max_chunk_chars=settings.rag_max_chunk_chars
        )
        self.lexical = LexicalIndex(self.corpus.chunks)
        self._embedder = embedder
        self._vector: VectorIndex | None = None
        self._vector_error: str | None = None
        self._by_id = {chunk.id: chunk for chunk in self.corpus.chunks}

    def _vector_index(self) -> VectorIndex:
        if self._vector is None:
            if self._vector_error:
                raise EmbeddingError(self._vector_error)
            try:
                self._vector = VectorIndex(self.corpus.chunks, self._embedder or HashingEmbedder())
            except Exception as exc:
                self._vector_error = "embedding_unavailable"
                raise EmbeddingError(self._vector_error) from exc
        return self._vector

    def _eligible(
        self, *, category: str | None, cwe_ids: set[str], today: date, include_stale: bool
    ) -> tuple[set[str], bool]:
        def fresh(meta) -> bool:  # noqa: ANN001
            return include_stale or not meta.is_stale(today)

        matching: set[str] = set()
        for doc_id, meta in self.corpus.documents.items():
            if not fresh(meta):
                continue
            by_category = category is not None and any(
                fnmatch.fnmatchcase(category, pattern) for pattern in meta.categories
            )
            by_cwe = bool(cwe_ids & set(meta.cwe_ids))
            if by_category or by_cwe or "*" in meta.categories:
                matching.add(doc_id)
        specific = {d for d in matching if "*" not in self.corpus.documents[d].categories}
        if specific:
            return matching, True
        everything = {d for d, m in self.corpus.documents.items() if fresh(m)}
        return everything, False

    def search(
        self,
        query: str,
        *,
        category: str | None = None,
        cwe_ids: set[str] | None = None,
        limit: int | None = None,
        today: date | None = None,
    ) -> RetrievalResult:
        today = today or datetime.now(UTC).date()
        limit = limit or settings.rag_max_chunks
        include_stale = settings.rag_include_stale
        eligible, filtered = self._eligible(
            category=category, cwe_ids=cwe_ids or set(), today=today, include_stale=include_stale
        )
        result = RetrievalResult(
            filtered=filtered, knowledge_base_version=self.corpus.version, backend="lexical"
        )
        scores: dict[str, float]
        if settings.rag_backend == "vector":
            try:
                scores = self._vector_index().scores(query)
                result.backend = "vector"
            except EmbeddingError as exc:
                logger.warning("Vector retrieval unavailable; using lexical index")
                result.fallback_reason = str(exc) or "embedding_unavailable"
                scores = self.lexical.scores(query)
        else:
            scores = self.lexical.scores(query)
        # A category or CWE match is itself strong relevance metadata: chunks of
        # specifically matching documents get a bonus so they surface even when
        # the finding text shares few words with the guidance.
        specific = {
            doc_id
            for doc_id in eligible
            if filtered and "*" not in self.corpus.documents[doc_id].categories
        }
        combined = dict(scores)
        for chunk in self.corpus.chunks:
            if chunk.document_id in specific:
                combined[chunk.id] = combined.get(chunk.id, 0.0) + _MATCH_BONUS
        # Specifically matching documents always rank before general guidance.
        ranked = sorted(
            (
                (0 if self._by_id[chunk_id].document_id in specific else 1, -score, chunk_id)
                for chunk_id, score in combined.items()
                if self._by_id[chunk_id].document_id in eligible
            ),
        )
        for _tier, negative, chunk_id in ranked[:limit]:
            score = -negative
            result.chunks.append(self._retrieved(self._by_id[chunk_id], score, today))
        return result

    def _retrieved(self, chunk: Chunk, score: float, today: date) -> RetrievedChunk:
        meta = self.corpus.documents[chunk.document_id]
        return RetrievedChunk(
            id=chunk.id,
            document_id=chunk.document_id,
            title=meta.title,
            section=chunk.section,
            text=chunk.text,
            score=round(score, 6),
            source_type=meta.source_type,
            document_version=meta.version,
            updated_at=meta.updated_at.isoformat(),
            license=meta.license,
            references=[{"label": r.label, "url": str(r.url)} for r in meta.references],
            stale=meta.is_stale(today),
        )


_lock = threading.Lock()
_service: KnowledgeService | None = None
_service_key: tuple[Any, ...] | None = None


def _config_key() -> tuple[Any, ...]:
    return (str(settings.rag_corpus_dir), settings.rag_max_chunk_chars)


def get_knowledge_service() -> KnowledgeService:
    """Shared service, rebuilt when the corpus configuration changes."""
    global _service, _service_key
    with _lock:
        key = _config_key()
        if _service is None or _service_key != key:
            _service = KnowledgeService()
            _service_key = key
        return _service


def reset_knowledge_service() -> None:
    global _service, _service_key
    with _lock:
        _service = None
        _service_key = None


def finding_query(*, title: str, category: str, summary: str, rule_id: str | None) -> str:
    return " ".join(
        part for part in (title, category.replace("_", " "), rule_id or "", summary) if part
    )


__all__ = [
    "KnowledgeBaseError",
    "KnowledgeService",
    "RetrievalResult",
    "RetrievedChunk",
    "finding_query",
    "get_knowledge_service",
    "reset_knowledge_service",
]
