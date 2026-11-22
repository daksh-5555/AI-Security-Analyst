"""Generate, validate, and store advisory explanations of findings (M9, ADR-0012).

Guarantees:

- The finding and its evidence are only read. Nothing here writes to them, so
  a provider failure can never lose or alter a deterministic result, and an
  explanation can never change status, severity, or confidence.
- Every attempt is stored, with its outcome: ``available`` with validated
  output, or ``unavailable`` with an error code. Provider message text and
  raw output are never stored or logged.
- Output must parse as JSON, validate against ``FindingExplanationOutput``, and
  reference only the IDs that were supplied (grounding). Any failure makes the
  explanation unavailable. Output strings are scrubbed again before storage.
- Token usage counts against a per-assessment budget.
- With ``RAG_ENABLED``, a few curated guidance chunks are retrieved first
  (M11). Their IDs are the only ``kb:`` IDs the output may cite, and when any
  are supplied the output must cite at least one. Retrieval failure only means
  no reference material; it never blocks the explanation or changes a finding.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.assessment_finding import AssessmentFinding
from app.models.evidence_item import EvidenceItem
from app.models.finding_explanation import FindingExplanation
from app.schemas.enums import (
    AuditAction,
    AuditOutcome,
    AuditResourceType,
    ExplanationStatus,
)
from app.services.audit import record_audit_event
from app.services.explanations.contract import FindingExplanationOutput, provider_json_schema
from app.services.explanations.prompt import PROMPT_TEMPLATE_VERSION, build_explanation_request
from app.services.explanations.provider import (
    ExplanationProvider,
    ProviderError,
    ProviderRequest,
)
from app.services.explanations.redaction import scrub_text
from app.services.knowledge.corpus import KnowledgeBaseError
from app.services.knowledge.retrieval import (
    RetrievalResult,
    finding_query,
    get_knowledge_service,
)

logger = logging.getLogger(__name__)

MIN_OUTPUT_TOKENS = 256


class ExplanationsDisabledError(RuntimeError):
    """LLM explanations are not enabled in this deployment."""


class FindingNotFoundError(LookupError):
    """The finding does not exist or belongs to another assessment."""


class ExplanationBudgetExceededError(RuntimeError):
    """The assessment's explanation token budget is used up."""


def tokens_used(db: Session, assessment_id: uuid.UUID) -> int:
    total = db.scalar(
        select(
            func.coalesce(
                func.sum(FindingExplanation.input_tokens + FindingExplanation.output_tokens), 0
            )
        ).where(FindingExplanation.assessment_id == assessment_id)
    )
    return int(total or 0)


def _validate_output(
    text: str, supplied_ids: set[str], source_ids: set[str] | None = None
) -> tuple[dict[str, Any] | None, str | None]:
    """Return (scrubbed output, None) or (None, error code)."""
    if not text.strip():
        return None, "empty_output"
    if len(text) > settings.llm_max_response_chars:
        return None, "output_too_large"
    try:
        raw = json.loads(text)
    except json.JSONDecodeError:
        return None, "invalid_json"
    try:
        output = FindingExplanationOutput.model_validate(raw)
    except ValidationError:
        return None, "schema_validation_failed"
    sources = source_ids or set()
    if not set(output.evidence_references) <= supplied_ids:
        # Cites evidence that was never supplied: ungrounded.
        return None, "ungrounded_output"
    if not output.claim_ids() <= supplied_ids | sources:
        return None, "ungrounded_output"
    if not set(output.source_references) <= sources:
        return None, "ungrounded_sources"
    if sources and not output.source_references:
        return None, "uncited_sources"
    data = output.model_dump(mode="json")
    return _scrub_strings(data), None


def _scrub_strings(value: Any) -> Any:
    if isinstance(value, str):
        return scrub_text(value)
    if isinstance(value, list):
        return [_scrub_strings(item) for item in value]
    if isinstance(value, dict):
        return {key: _scrub_strings(item) for key, item in value.items()}
    return value


def explain_finding(
    db: Session,
    assessment_id: uuid.UUID,
    finding_id: uuid.UUID,
    *,
    provider: ExplanationProvider,
    actor_user_id: uuid.UUID | None,
) -> FindingExplanation:
    """Request one explanation and store its outcome. Never modifies the finding."""
    if not settings.llm_explanations_enabled:
        raise ExplanationsDisabledError
    finding = db.get(AssessmentFinding, finding_id)
    if finding is None or finding.assessment_id != assessment_id:
        raise FindingNotFoundError
    remaining = settings.llm_assessment_token_budget - tokens_used(db, assessment_id)
    if remaining < MIN_OUTPUT_TOKENS:
        raise ExplanationBudgetExceededError

    evidence_ids = finding.evidence_ids
    items_by_id = {
        item.id: item
        for item in db.scalars(select(EvidenceItem).where(EvidenceItem.id.in_(evidence_ids)))
    }
    evidence = [items_by_id[item_id] for item_id in evidence_ids if item_id in items_by_id]
    retrieval = _retrieve(finding)
    references = [chunk.as_reference() for chunk in retrieval.chunks] if retrieval else []
    request = build_explanation_request(
        finding, evidence, list(finding.evidence), references=references
    )
    retrieval_metadata = _retrieval_metadata(retrieval)
    # Release the read transaction before a potentially slow provider call.
    db.rollback()

    status = ExplanationStatus.UNAVAILABLE
    error_code: str | None = None
    output: dict[str, Any] | None = None
    model = provider.model
    input_tokens = output_tokens = 0
    try:
        response = provider.generate(
            ProviderRequest(
                system=request.system,
                user=request.user,
                json_schema=provider_json_schema(),
                max_output_tokens=min(settings.llm_max_output_tokens, remaining),
            )
        )
    except ProviderError as exc:
        error_code = exc.code.value
        input_tokens, output_tokens = exc.input_tokens, exc.output_tokens
        logger.warning("Explanation provider failed for finding %s: %s", finding_id, error_code)
    except Exception:
        error_code = "provider_error"
        logger.warning("Explanation provider raised unexpectedly for finding %s", finding_id)
    else:
        model = response.model
        input_tokens, output_tokens = response.input_tokens, response.output_tokens
        output, error_code = _validate_output(
            response.text, set(request.supplied_ids), set(request.source_ids)
        )
        if error_code is None:
            status = ExplanationStatus.AVAILABLE
        else:
            logger.warning("Explanation output rejected for finding %s: %s", finding_id, error_code)

    now = datetime.now(UTC)
    explanation = FindingExplanation(
        assessment_id=assessment_id,
        finding_id=finding_id,
        status=status,
        error_code=error_code,
        provider=provider.name,
        model=model,
        prompt_template_version=PROMPT_TEMPLATE_VERSION,
        output=output,
        supplied_evidence_ids=list(request.supplied_ids),
        retrieval=retrieval_metadata,
        input_tokens=max(0, input_tokens),
        output_tokens=max(0, output_tokens),
        requested_by_user_id=actor_user_id,
        created_at=now,
    )
    db.add(explanation)
    db.flush()
    record_audit_event(
        db,
        action=AuditAction.FINDING_EXPLANATION_CREATED,
        outcome=(
            AuditOutcome.SUCCESS if status is ExplanationStatus.AVAILABLE else AuditOutcome.FAILURE
        ),
        resource_type=AuditResourceType.FINDING_EXPLANATION,
        resource_id=explanation.id,
        assessment_id=assessment_id,
        actor_user_id=actor_user_id,
        occurred_at=now,
        context={
            "finding_id": str(finding_id),
            "status": status.value,
            "error_code": error_code,
            "provider": provider.name,
            "model": model,
            "tokens": explanation.input_tokens + explanation.output_tokens,
        },
    )
    db.commit()
    return explanation


def _retrieve(finding: AssessmentFinding) -> RetrievalResult | None:
    if not settings.rag_enabled:
        return None
    try:
        service = get_knowledge_service()
        return service.search(
            finding_query(
                title=finding.title,
                category=finding.category,
                summary=finding.summary,
                rule_id=finding.rule_id,
            ),
            category=finding.category,
            cwe_ids=set(finding.cwe_ids or []),
        )
    except KnowledgeBaseError:
        logger.warning("Knowledge base unavailable; explaining without reference material")
        return RetrievalResult(
            chunks=[], backend="none", fallback_reason="knowledge_base_unavailable"
        )
    except Exception:
        logger.warning("Knowledge retrieval failed; explaining without reference material")
        return RetrievalResult(chunks=[], backend="none", fallback_reason="retrieval_error")


def _retrieval_metadata(result: RetrievalResult | None) -> dict[str, Any]:
    if result is None:
        return {"status": "disabled", "source_ids": [], "sources": []}
    if result.backend == "none":
        return result.metadata("unavailable")
    return result.metadata("used" if result.chunks else "none_relevant")


def list_explanations(
    db: Session, assessment_id: uuid.UUID, finding_id: uuid.UUID
) -> list[FindingExplanation]:
    finding = db.get(AssessmentFinding, finding_id)
    if finding is None or finding.assessment_id != assessment_id:
        raise FindingNotFoundError
    return list(
        db.scalars(
            select(FindingExplanation)
            .where(FindingExplanation.finding_id == finding_id)
            .order_by(FindingExplanation.created_at.desc(), FindingExplanation.id.desc())
        )
    )


__all__ = [
    "ExplanationBudgetExceededError",
    "ExplanationsDisabledError",
    "FindingNotFoundError",
    "explain_finding",
    "list_explanations",
    "tokens_used",
]
