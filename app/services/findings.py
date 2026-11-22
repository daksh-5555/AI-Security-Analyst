import uuid
from collections.abc import Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.models.analysis_run import AnalysisRun
from app.models.assessment import AssessmentJob
from app.models.assessment_finding import AssessmentFinding
from app.models.evidence_item import EvidenceItem, FindingEvidenceLink
from app.models.finding_evidence import FindingEvidence
from app.schemas.enums import AnalysisRunStatus, FindingStatus
from app.schemas.finding import Finding
from app.schemas.tooling import EvidenceRecord
from app.services.finding_normalization import NormalizedFinding


class AssessmentNotFoundError(LookupError):
    """Raised when the assessment does not exist."""

    def __init__(self) -> None:
        super().__init__("Assessment not found")


class AnalysisRunNotFoundError(LookupError):
    """Raised when a run does not exist or belongs to another assessment."""

    def __init__(self) -> None:
        super().__init__("Analysis run not found")


def _get_analysis_run_or_raise(
    db: Session,
    assessment_id: uuid.UUID,
    analysis_run_id: uuid.UUID,
) -> AnalysisRun:
    run = db.get(AnalysisRun, analysis_run_id)
    if run is None or run.assessment_id != assessment_id:
        raise AnalysisRunNotFoundError
    return run


def add_findings(
    db: Session,
    assessment_id: uuid.UUID,
    findings: Sequence[Finding],
    *,
    analysis_run_id: uuid.UUID | None = None,
) -> list[AssessmentFinding]:
    """Add findings and nested evidence without owning the transaction."""
    if db.get(AssessmentJob, assessment_id) is None:
        raise AssessmentNotFoundError
    if analysis_run_id is not None:
        _get_analysis_run_or_raise(db, assessment_id, analysis_run_id)

    finding_list = list(findings)
    if not finding_list:
        return []

    current_max = db.scalar(
        select(func.max(AssessmentFinding.position)).where(
            AssessmentFinding.assessment_id == assessment_id
        )
    )
    next_position = 0 if current_max is None else current_max + 1
    now = datetime.now(UTC)

    orm_findings: list[AssessmentFinding] = []
    for offset, finding in enumerate(finding_list):
        orm_findings.append(
            AssessmentFinding(
                assessment_id=assessment_id,
                analysis_run_id=analysis_run_id,
                position=next_position + offset,
                title=finding.title,
                category=finding.category,
                severity=finding.severity,
                status=finding.status,
                confidence=finding.confidence,
                summary=finding.summary,
                affected_component=finding.affected_component,
                remediation=finding.remediation,
                created_at=now,
                updated_at=now,
                evidence=[
                    FindingEvidence(
                        position=evidence_position,
                        description=evidence.description,
                        source=evidence.source,
                        details=dict(evidence.details) if evidence.details is not None else None,
                        created_at=now,
                    )
                    for evidence_position, evidence in enumerate(finding.evidence)
                ],
            )
        )

    db.add_all(orm_findings)
    db.flush()
    return orm_findings


def persist_findings(
    db: Session,
    assessment_id: uuid.UUID,
    findings: Sequence[Finding],
    *,
    analysis_run_id: uuid.UUID | None = None,
) -> list[AssessmentFinding]:
    """Persist findings and nested evidence for an existing assessment."""
    try:
        orm_findings = add_findings(
            db,
            assessment_id,
            findings,
            analysis_run_id=analysis_run_id,
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    return orm_findings


def list_findings(
    db: Session,
    assessment_id: uuid.UUID,
    *,
    analysis_run_id: uuid.UUID | None = None,
) -> list[AssessmentFinding] | None:
    """Return persisted findings with evidence, optionally filtered by run."""
    if db.get(AssessmentJob, assessment_id) is None:
        return None
    if analysis_run_id is not None:
        _get_analysis_run_or_raise(db, assessment_id, analysis_run_id)

    statement = (
        select(AssessmentFinding)
        .where(AssessmentFinding.assessment_id == assessment_id)
        .options(
            selectinload(AssessmentFinding.evidence),
            selectinload(AssessmentFinding.evidence_links),
        )
        .order_by(AssessmentFinding.position.asc())
    )
    if analysis_run_id is not None:
        statement = statement.where(AssessmentFinding.analysis_run_id == analysis_run_id)
    return list(db.scalars(statement).all())


# -- normalized persistence (M7, ADR-0010) -----------------------------------------

_RETESTABLE_STATUSES = frozenset(
    {FindingStatus.CONFIRMED, FindingStatus.POTENTIAL, FindingStatus.INCONCLUSIVE}
)


@dataclass(frozen=True, slots=True)
class RetestSummary:
    """How this run's findings relate to the previous completed run."""

    previous_run_id: uuid.UUID | None
    new: int
    recurring: int
    not_reproduced: int
    evidence_items: int
    findings: int

    def as_metadata(self) -> dict[str, object]:
        return {
            "previous_run_id": str(self.previous_run_id) if self.previous_run_id else None,
            "new": self.new,
            "recurring": self.recurring,
            "not_reproduced": self.not_reproduced,
            "evidence_items": self.evidence_items,
        }


def _evidence_item(
    record: EvidenceRecord,
    *,
    assessment_id: uuid.UUID,
    analysis_run_id: uuid.UUID,
    now: datetime,
) -> EvidenceItem:
    provenance = record.provenance
    return EvidenceItem(
        assessment_id=assessment_id,
        analysis_run_id=analysis_run_id,
        evidence_key=record.evidence_key,
        source_type=record.source_type.value,
        tool_name=provenance.tool.name,
        tool_version=provenance.tool.version,
        rule_set_version=provenance.tool.rule_set_version,
        rule_id=provenance.rule_id,
        method=provenance.method,
        location_path=record.location.path,
        location_line=record.location.line,
        url_path=record.location.url_path,
        parameter=record.location.parameter,
        summary=record.summary,
        redacted_excerpt=record.redacted_excerpt,
        content_hash=record.content_hash,
        fingerprint=record.fingerprint,
        request_summary=record.request_summary,
        response_summary=record.response_summary,
        limitations=list(record.limitations),
        details=dict(record.metadata),
        observed_at=provenance.observed_at,
        created_at=now,
    )


def _merge(normalized: Sequence[NormalizedFinding]) -> list[NormalizedFinding]:
    """One finding per identity within a run; evidence is unioned in order."""
    merged: dict[str, NormalizedFinding] = {}
    for item in normalized:
        existing = merged.get(item.identity_key)
        if existing is None:
            merged[item.identity_key] = item
            continue
        keys = {record.evidence_key for record in existing.evidence}
        extra = tuple(record for record in item.evidence if record.evidence_key not in keys)
        merged[item.identity_key] = replace(existing, evidence=existing.evidence + extra)
    return list(merged.values())


def add_normalized_findings(
    db: Session,
    assessment_id: uuid.UUID,
    normalized: Sequence[NormalizedFinding],
    *,
    analysis_run_id: uuid.UUID,
    completed_stages: frozenset[str],
    now: datetime | None = None,
) -> RetestSummary:
    """Persist normalized findings, their evidence, links, and retest state.

    Does not own the transaction. Every new finding references at least one evidence
    item. Findings from the previous completed run whose producing stage completed
    again in this run but which were not observed are recorded as
    ``not_reproduced``; they reference the earlier run's evidence. The legacy
    per-finding ``finding_evidence`` rows are still written for API compatibility.
    """
    if db.get(AssessmentJob, assessment_id) is None:
        raise AssessmentNotFoundError
    _get_analysis_run_or_raise(db, assessment_id, analysis_run_id)
    current = now or datetime.now(UTC)
    findings = _merge(normalized)

    previous_run_id = db.scalar(
        select(AnalysisRun.id)
        .where(
            AnalysisRun.assessment_id == assessment_id,
            AnalysisRun.status == AnalysisRunStatus.COMPLETED,
            AnalysisRun.id != analysis_run_id,
        )
        .order_by(AnalysisRun.completed_at.desc(), AnalysisRun.id.desc())
        .limit(1)
    )
    previous: dict[str, AssessmentFinding] = {}
    if previous_run_id is not None:
        rows = db.scalars(
            select(AssessmentFinding)
            .where(
                AssessmentFinding.analysis_run_id == previous_run_id,
                AssessmentFinding.identity_key.is_not(None),
            )
            .options(selectinload(AssessmentFinding.evidence_links))
        ).all()
        previous = {row.identity_key: row for row in rows if row.identity_key}
    identities = [item.identity_key for item in findings] + list(previous)
    first_seen: dict[str, datetime] = {}
    if identities:
        first_seen = {
            key: value
            for key, value in db.execute(
                select(AssessmentFinding.identity_key, func.min(AssessmentFinding.first_seen_at))
                .where(
                    AssessmentFinding.assessment_id == assessment_id,
                    AssessmentFinding.identity_key.in_(identities),
                )
                .group_by(AssessmentFinding.identity_key)
            ).all()
            if key and value
        }

    current_max = db.scalar(
        select(func.max(AssessmentFinding.position)).where(
            AssessmentFinding.assessment_id == assessment_id
        )
    )
    position = 0 if current_max is None else current_max + 1
    items: dict[str, EvidenceItem] = {}
    rows_to_add: list[tuple[AssessmentFinding, list[str]]] = []
    new = recurring = 0

    for item in findings:
        for record in item.evidence:
            if record.evidence_key not in items:
                items[record.evidence_key] = _evidence_item(
                    record,
                    assessment_id=assessment_id,
                    analysis_run_id=analysis_run_id,
                    now=current,
                )
        prior = previous.get(item.identity_key)
        if prior is None:
            new += 1
        else:
            recurring += 1
        finding = item.finding
        row = AssessmentFinding(
            assessment_id=assessment_id,
            analysis_run_id=analysis_run_id,
            position=position,
            title=finding.title,
            category=finding.category,
            severity=finding.severity,
            status=finding.status,
            confidence=finding.confidence,
            summary=finding.summary,
            affected_component=finding.affected_component,
            remediation=finding.remediation,
            rule_id=item.rule_id,
            source_stage=item.source_stage,
            identity_key=item.identity_key,
            verification_method=item.verification_method,
            status_rationale=item.status_rationale,
            cwe_ids=list(item.cwe_ids) or None,
            cve_ids=list(item.cve_ids) or None,
            first_seen_at=first_seen.get(item.identity_key, current),
            last_seen_at=current,
            previous_status=prior.status if prior is not None else None,
            previous_finding_id=prior.id if prior is not None else None,
            created_at=current,
            updated_at=current,
            evidence=[
                FindingEvidence(
                    position=index,
                    description=evidence.description,
                    source=evidence.source,
                    details=dict(evidence.details) if evidence.details is not None else None,
                    created_at=current,
                )
                for index, evidence in enumerate(finding.evidence)
            ],
        )
        rows_to_add.append((row, [record.evidence_key for record in item.evidence]))
        position += 1

    seen_now = {item.identity_key for item in findings}
    not_reproduced: list[tuple[AssessmentFinding, AssessmentFinding]] = []
    for identity, prior in sorted(previous.items()):
        if identity in seen_now or prior.status not in _RETESTABLE_STATUSES:
            continue
        if prior.source_stage not in completed_stages or not prior.evidence_links:
            continue
        row = AssessmentFinding(
            assessment_id=assessment_id,
            analysis_run_id=analysis_run_id,
            position=position,
            title=prior.title,
            category=prior.category,
            severity=prior.severity,
            status=FindingStatus.NOT_REPRODUCED,
            confidence=prior.confidence,
            summary=(
                f"Previously reported as {prior.status.value} in run {previous_run_id}; not "
                f"observed in this run although the {prior.source_stage} check completed."
            ),
            affected_component=prior.affected_component,
            remediation=prior.remediation,
            rule_id=prior.rule_id,
            source_stage=prior.source_stage,
            identity_key=identity,
            verification_method=prior.verification_method,
            status_rationale=(
                "not_reproduced: the producing check ran to completion in this run and did "
                "not observe the earlier signal. Evidence refers to the earlier observation."
            ),
            cwe_ids=prior.cwe_ids,
            cve_ids=prior.cve_ids,
            first_seen_at=prior.first_seen_at,
            last_seen_at=prior.last_seen_at,
            previous_status=prior.status,
            previous_finding_id=prior.id,
            created_at=current,
            updated_at=current,
            evidence=[
                FindingEvidence(
                    position=0,
                    description="Earlier observation (see linked evidence from the previous run).",
                    source=f"retest:{previous_run_id}",
                    details={"previous_finding_id": str(prior.id)},
                    created_at=current,
                )
            ],
        )
        not_reproduced.append((row, prior))
        position += 1

    db.add_all(items.values())
    db.add_all(row for row, _keys in rows_to_add)
    db.add_all(row for row, _prior in not_reproduced)
    db.flush()
    for row, keys in rows_to_add:
        if not keys:
            raise ValueError("every finding must reference at least one evidence item")
        for index, key in enumerate(keys):
            db.add(
                FindingEvidenceLink(
                    finding_id=row.id, evidence_item_id=items[key].id, position=index
                )
            )
    for row, prior in not_reproduced:
        for index, link in enumerate(prior.evidence_links):
            db.add(
                FindingEvidenceLink(
                    finding_id=row.id, evidence_item_id=link.evidence_item_id, position=index
                )
            )
    db.flush()
    return RetestSummary(
        previous_run_id=previous_run_id,
        new=new,
        recurring=recurring,
        not_reproduced=len(not_reproduced),
        evidence_items=len(items),
        findings=len(rows_to_add) + len(not_reproduced),
    )


def list_evidence(
    db: Session,
    assessment_id: uuid.UUID,
    *,
    analysis_run_id: uuid.UUID | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[EvidenceItem]:
    if analysis_run_id is not None:
        _get_analysis_run_or_raise(db, assessment_id, analysis_run_id)
    statement = select(EvidenceItem).where(EvidenceItem.assessment_id == assessment_id)
    if analysis_run_id is not None:
        statement = statement.where(EvidenceItem.analysis_run_id == analysis_run_id)
    statement = (
        statement.order_by(EvidenceItem.created_at, EvidenceItem.id).offset(offset).limit(limit)
    )
    return list(db.scalars(statement).all())


def get_evidence(
    db: Session, assessment_id: uuid.UUID, evidence_id: uuid.UUID
) -> EvidenceItem | None:
    item = db.get(EvidenceItem, evidence_id)
    if item is None or item.assessment_id != assessment_id:
        return None
    return item
