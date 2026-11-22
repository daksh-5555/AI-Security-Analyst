"""Read-only access to the curated knowledge base (M11, ADR-0014)."""

from collections import Counter
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.api.dependencies import get_current_principal
from app.core.config import settings
from app.services.knowledge.corpus import KnowledgeBaseError, document_summary
from app.services.knowledge.retrieval import get_knowledge_service

router = APIRouter(
    prefix="/api/v1/knowledge",
    tags=["knowledge"],
    dependencies=[Depends(get_current_principal)],
)

KNOWLEDGE_DISABLED_DETAIL = "Knowledge retrieval is not enabled"
KNOWLEDGE_UNAVAILABLE_DETAIL = "Knowledge base is unavailable"


def _service():  # noqa: ANN202
    if not settings.rag_enabled:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=KNOWLEDGE_DISABLED_DETAIL)
    try:
        return get_knowledge_service()
    except KnowledgeBaseError as exc:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, detail=KNOWLEDGE_UNAVAILABLE_DETAIL
        ) from exc


@router.get(
    "",
    responses={
        status.HTTP_404_NOT_FOUND: {"description": "RAG is disabled."},
        status.HTTP_503_SERVICE_UNAVAILABLE: {"description": "The corpus failed validation."},
    },
)
def knowledge_base() -> dict[str, Any]:
    """Version, content hash, and per-document source, license, and freshness."""
    service = _service()
    corpus = service.corpus
    today = datetime.now(UTC).date()
    counts = Counter(chunk.document_id for chunk in corpus.chunks)
    return {
        "name": corpus.name,
        "version": corpus.version,
        "content_hash": corpus.content_hash,
        "backend": settings.rag_backend,
        "include_stale": settings.rag_include_stale,
        "documents": [
            document_summary(corpus.documents[doc_id], today, counts[doc_id])
            for doc_id in sorted(corpus.documents)
        ],
    }


@router.get(
    "/search",
    responses={
        status.HTTP_404_NOT_FOUND: {"description": "RAG is disabled."},
        status.HTTP_503_SERVICE_UNAVAILABLE: {"description": "The corpus failed validation."},
    },
)
def search_knowledge(
    q: Annotated[str, Query(min_length=2, max_length=200)],
    category: Annotated[str | None, Query(max_length=100)] = None,
    cwe: Annotated[str | None, Query(pattern=r"^CWE-\d{1,5}$")] = None,
    limit: Annotated[int, Query(ge=1, le=10)] = 4,
) -> dict[str, Any]:
    """Attributed guidance chunks for a query, filtered by category or CWE."""
    service = _service()
    result = service.search(q, category=category, cwe_ids={cwe} if cwe else set(), limit=limit)
    return {
        **result.metadata("used" if result.chunks else "none_relevant"),
        "results": [
            {
                **chunk.attribution(),
                "section": chunk.section,
                "text": chunk.text,
                "score": chunk.score,
            }
            for chunk in result.chunks
        ],
    }
