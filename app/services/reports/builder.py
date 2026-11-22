"""Build an assessment report from persisted data only (M12, ADR-0015).

The report never re-runs analysis. It is assembled from the stored
assessment, target, analysis run, findings, evidence, latest explanation per
finding, and the linked workflow plan, so the JSON and HTML renderings always
agree with what is persisted.

Safety:
- Every string passes ``scrub_text`` again (secrets, tokens, cookies,
  e-mail addresses), on top of the redaction applied when evidence was stored.
- Repository targets are shown relative to their allowed root, never as an
  absolute server path. Web targets are shown with credentials and sensitive
  query values removed.
- Only allowlisted request and response summary keys are included; bodies,
  fingerprints, and hashes are never included.

Determinism: findings are ordered by severity, then position. ``content_hash``
is a SHA-256 over the canonical report without ``generated_at``, so the same
persisted data always yields the same hash and the hash changes whenever the
content does.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections import Counter
from datetime import UTC, datetime
from typing import Any, Final

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.analysis_run import AnalysisRun
from app.models.assessment import AssessmentJob
from app.models.assessment_finding import AssessmentFinding
from app.models.assessment_target import AssessmentTarget
from app.models.evidence_item import EvidenceItem
from app.models.finding_explanation import FindingExplanation
from app.models.workflow import AssessmentWorkflow
from app.schemas.enums import (
    AnalysisRunStatus,
    ExplanationStatus,
    FindingSeverity,
    FindingStatus,
    TargetType,
)
from app.services.explanations.redaction import scrub_text
from app.services.repository_targets import repository_target_display_location
from app.services.tooling.redaction import redact_url

REPORT_SCHEMA_VERSION: Final = "assessment-report/1"
AI_LABEL: Final = (
    "AI-generated explanation. Advisory only and grounded in the cited evidence; it "
    "did not determine this finding's status, severity, or confidence."
)
_SEVERITY_ORDER: Final = [
    FindingSeverity.CRITICAL,
    FindingSeverity.HIGH,
    FindingSeverity.MEDIUM,
    FindingSeverity.LOW,
    FindingSeverity.UNKNOWN,
    FindingSeverity.INFORMATIONAL,
]
_SUMMARY_KEYS: Final = ("method", "parameter", "probe_kind", "status_code", "length", "status")
_ADVISORY_ID: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{1,80}$")
_TERMINAL: Final = (
    AnalysisRunStatus.COMPLETED,
    AnalysisRunStatus.FAILED,
    AnalysisRunStatus.CANCELLED,
)


class ReportNotFoundError(LookupError):
    """The assessment or requested run does not exist for this assessment."""


def _t(value: Any, limit: int = 4000) -> str | None:
    if value is None:
        return None
    return scrub_text(str(value), max_length=limit)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _select_run(
    db: Session, assessment_id: uuid.UUID, run_id: uuid.UUID | None
) -> AnalysisRun | None:
    if run_id is not None:
        run = db.get(AnalysisRun, run_id)
        if run is None or run.assessment_id != assessment_id:
            raise ReportNotFoundError
        return run
    for statuses in ((AnalysisRunStatus.COMPLETED,), _TERMINAL):
        run = db.scalar(
            select(AnalysisRun)
            .where(AnalysisRun.assessment_id == assessment_id, AnalysisRun.status.in_(statuses))
            .order_by(AnalysisRun.created_at.desc(), AnalysisRun.id.desc())
            .limit(1)
        )
        if run is not None:
            return run
    return None


def _target(db: Session, assessment_id: uuid.UUID) -> dict[str, Any] | None:
    target = db.scalar(
        select(AssessmentTarget)
        .where(AssessmentTarget.assessment_id == assessment_id)
        .order_by(AssessmentTarget.created_at.desc())
        .limit(1)
    )
    if target is None:
        return None
    if target.target_type is TargetType.REPOSITORY:
        display = repository_target_display_location(target.canonical_target)
    else:
        display = redact_url(target.canonical_target)
    return {
        "type": target.target_type.value,
        "display": _t(display, 500),
        "authorization_status": target.status.value,
        "authorization_basis": target.authorization_basis.value
        if target.authorization_basis
        else None,
        "authorized_at": _iso(target.authorized_at),
        "revoked_at": _iso(target.revoked_at),
    }


def _summary(value: Any) -> dict[str, str] | None:
    if not isinstance(value, dict):
        return None
    kept = {key: _t(value[key], 200) for key in _SUMMARY_KEYS if key in value}
    return {key: item for key, item in kept.items() if item is not None} or None


def _evidence(item: EvidenceItem) -> dict[str, Any]:
    return {
        "id": str(item.id),
        "source_type": item.source_type,
        "tool": _t(f"{item.tool_name} {item.tool_version}", 200),
        "rule_id": _t(item.rule_id, 200),
        "method": _t(item.method, 1000),
        "summary": _t(item.summary, 2000),
        "location_path": _t(item.location_path, 500),
        "location_line": item.location_line,
        "url_path": _t(item.url_path, 500),
        "parameter": _t(item.parameter, 200),
        "redacted_excerpt": _t(item.redacted_excerpt, 1000),
        "request_summary": _summary(item.request_summary),
        "response_summary": _summary(item.response_summary),
        "observed_at": _iso(item.observed_at),
    }


def _advisory(details: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(details, dict) or not details.get("advisory_id"):
        return None
    advisory_id = str(details["advisory_id"])
    reference = (
        f"https://osv.dev/vulnerability/{advisory_id}" if _ADVISORY_ID.match(advisory_id) else None
    )
    return {
        "advisory_id": _t(advisory_id, 100),
        "package": _t(details.get("package"), 200),
        "version": _t(details.get("version"), 100),
        "ecosystem": _t(details.get("ecosystem"), 50),
        "aliases": [_t(a, 100) for a in (details.get("aliases") or [])][:20],
        "cve_ids": [_t(c, 30) for c in (details.get("cve_ids") or [])][:20],
        "reference": reference,
    }


def _explanation(row: FindingExplanation | None) -> dict[str, Any] | None:
    if row is None or row.status is not ExplanationStatus.AVAILABLE or not row.output:
        return None
    output = row.output
    retrieval = row.retrieval or {}
    return {
        "label": AI_LABEL,
        "provider": _t(row.provider, 50),
        "model": _t(row.model, 100),
        "prompt_template_version": row.prompt_template_version,
        "created_at": _iso(row.created_at),
        "summary": _t(output.get("summary")),
        "technical_explanation": _t(output.get("technical_explanation")),
        "impact": _t(output.get("impact")),
        "remediation_steps": [_t(s, 1000) for s in output.get("remediation_steps", [])],
        "validation_guidance": [_t(s, 1000) for s in output.get("validation_guidance", [])],
        "uncertainty": _t(output.get("uncertainty")),
        "evidence_references": list(output.get("evidence_references", [])),
        "source_references": list(output.get("source_references", [])),
        "sources": [
            {
                "id": source.get("id"),
                "title": _t(source.get("title"), 200),
                "license": _t(source.get("license"), 300),
                "references": [
                    {"label": _t(ref.get("label"), 200), "url": ref.get("url")}
                    for ref in source.get("references", [])
                    if str(ref.get("url", "")).startswith("https://")
                ],
            }
            for source in retrieval.get("sources", [])
            if source.get("id") in set(output.get("source_references", []))
        ],
    }


def _executive_summary(
    run: AnalysisRun | None, counts: dict[str, Any], checks_not_run: list[dict[str, Any]]
) -> list[str]:
    if run is None:
        return ["No analysis run has finished for this assessment, so there are no results."]
    lines: list[str] = []
    if run.status is not AnalysisRunStatus.COMPLETED:
        lines.append(
            f"The selected analysis run ended {run.status.value}; no findings were recorded "
            "for it. This is not a clean result."
        )
    total = counts["total"]
    by_status = counts["by_status"]
    lines.append(
        f"{total} finding(s): {by_status.get('confirmed', 0)} confirmed, "
        f"{by_status.get('potential', 0)} potential, "
        f"{by_status.get('inconclusive', 0)} inconclusive, "
        f"{by_status.get('not_tested', 0)} not tested (static evidence only), "
        f"{by_status.get('not_reproduced', 0)} not reproduced."
    )
    high = sum(counts["by_severity"].get(s, 0) for s in ("critical", "high"))
    if high:
        lines.append(f"{high} finding(s) are rated critical or high severity.")
    if checks_not_run:
        names = ", ".join(sorted({item["stage"] for item in checks_not_run}))
        lines.append(
            f"Incomplete or skipped checks: {names}. Absence of findings from these "
            "checks does not mean the issues are absent."
        )
    elif run.status is AnalysisRunStatus.COMPLETED:
        lines.append("All configured checks completed.")
    return lines


def build_report(
    db: Session, assessment_id: uuid.UUID, *, analysis_run_id: uuid.UUID | None = None
) -> dict[str, Any]:
    assessment = db.get(AssessmentJob, assessment_id)
    if assessment is None:
        raise ReportNotFoundError
    run = _select_run(db, assessment_id, analysis_run_id)
    metadata = (run.analysis_metadata or {}) if run else {}

    findings: list[AssessmentFinding] = []
    if run is not None:
        findings = list(
            db.scalars(select(AssessmentFinding).where(AssessmentFinding.analysis_run_id == run.id))
        )
    rank = {severity: index for index, severity in enumerate(_SEVERITY_ORDER)}
    findings.sort(key=lambda f: (rank.get(f.severity, 99), f.position, str(f.id)))
    included = findings[: settings.report_max_findings]

    evidence_ids = {link_id for f in included for link_id in f.evidence_ids}
    evidence_by_id = (
        {e.id: e for e in db.scalars(select(EvidenceItem).where(EvidenceItem.id.in_(evidence_ids)))}
        if evidence_ids
        else {}
    )
    explanations: dict[uuid.UUID, FindingExplanation] = {}
    if included:
        for row in db.scalars(
            select(FindingExplanation)
            .where(
                FindingExplanation.finding_id.in_([f.id for f in included]),
                FindingExplanation.status == ExplanationStatus.AVAILABLE,
            )
            .order_by(FindingExplanation.created_at.desc())
        ):
            explanations.setdefault(row.finding_id, row)

    finding_items: list[dict[str, Any]] = []
    advisories: list[dict[str, Any]] = []
    for finding in included:
        linked = [evidence_by_id[i] for i in finding.evidence_ids if i in evidence_by_id]
        shown = linked[: settings.report_max_evidence_per_finding]
        for item in linked:
            advisory = _advisory(item.details)
            if advisory and finding.category == "dependency":
                advisories.append({"finding_id": str(finding.id), **advisory})
        finding_items.append(
            {
                "id": str(finding.id),
                "title": _t(finding.title, 500),
                "category": _t(finding.category, 100),
                "severity": finding.severity.value,
                "status": finding.status.value,
                "confidence": finding.confidence,
                "summary": _t(finding.summary),
                "affected_component": _t(finding.affected_component, 500),
                "rule_id": _t(finding.rule_id, 200),
                "source_stage": _t(finding.source_stage, 100),
                "verification_method": _t(finding.verification_method),
                "status_rationale": _t(finding.status_rationale),
                "remediation": _t(finding.remediation),
                "cwe_ids": list(finding.cwe_ids or []),
                "cve_ids": list(finding.cve_ids or []),
                "first_seen_at": _iso(finding.first_seen_at),
                "last_seen_at": _iso(finding.last_seen_at),
                "previous_status": finding.previous_status.value
                if finding.previous_status
                else None,
                "evidence": [_evidence(item) for item in shown],
                "evidence_omitted": max(0, len(linked) - len(shown)),
                "ai_explanation": _explanation(explanations.get(finding.id)),
            }
        )

    by_severity = Counter(f.severity.value for f in findings)
    by_status = Counter(f.status.value for f in findings)
    counts = {
        "total": len(findings),
        "by_severity": {s.value: by_severity.get(s.value, 0) for s in _SEVERITY_ORDER},
        "by_status": {s.value: by_status.get(s.value, 0) for s in FindingStatus},
    }
    tools = [
        {
            "stage": tool.get("stage"),
            "tool": _t(tool.get("tool"), 100),
            "version": _t(tool.get("version"), 50),
            "rule_set_version": _t(tool.get("rule_set_version"), 50),
            "status": tool.get("status"),
            "error_code": tool.get("error_code"),
            "limitations": [
                {"code": _t(item.get("code"), 100), "detail": _t(item.get("detail"), 500)}
                for item in (tool.get("limitations") or [])[:20]
            ],
        }
        for tool in metadata.get("tools", [])
    ]
    checks_not_run = [
        {
            "stage": tool["stage"],
            "status": tool["status"],
            "error_code": tool["error_code"],
        }
        for tool in tools
        if tool["status"] != "completed"
        and not (tool["status"] == "skipped" and tool["error_code"] == "not_applicable")
    ]
    completeness = metadata.get("completeness") or {}
    if run is not None and completeness.get("static_analysis_is_complete") is False:
        checks_not_run.append(
            {"stage": "static_analysis", "status": "partial", "error_code": "truncated"}
        )
    workflow = None
    if run is not None:
        workflow = db.scalar(
            select(AssessmentWorkflow)
            .where(AssessmentWorkflow.analysis_run_id == run.id)
            .order_by(AssessmentWorkflow.created_at.desc())
            .limit(1)
        )
    limitations = [
        _t(item, 500)
        for item in ((metadata.get("finding_policy") or {}).get("limitations") or [])[:50]
    ]
    report: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "generator": {"name": settings.app_name, "version": settings.app_version},
        "assessment": {
            "id": str(assessment.id),
            "type": assessment.assessment_type.value,
            "status": assessment.status.value,
            "created_at": _iso(assessment.created_at),
        },
        "target": _target(db, assessment_id),
        "run": None
        if run is None
        else {
            "id": str(run.id),
            "status": run.status.value,
            "created_at": _iso(run.created_at),
            "started_at": _iso(run.started_at),
            "completed_at": _iso(run.completed_at),
            "error_code": run.error_code,
            "error_message": _t(run.error_message, 300),
            "analyzer": metadata.get("analyzer"),
        },
        "scope": {
            "tools": tools,
            "completeness": {
                key: value for key, value in completeness.items() if isinstance(value, bool)
            },
            "workflow": None
            if workflow is None
            else {
                "id": str(workflow.id),
                "graph_version": workflow.graph_version,
                "checks": (workflow.plan or {}).get("checks", []),
                "configuration": (workflow.plan or {}).get("config"),
                "approvals": {
                    check: {"decision": entry.get("decision"), "at": entry.get("at")}
                    for check, entry in (workflow.state.get("approvals") or {}).items()
                },
            },
        },
        "executive_summary": _executive_summary(run, counts, checks_not_run),
        "counts": counts,
        "findings": finding_items,
        "findings_omitted": len(findings) - len(included),
        "checks_not_run": checks_not_run,
        "limitations": limitations,
        "advisories": advisories,
        "retest": metadata.get("retest"),
    }
    canonical = json.dumps(report, sort_keys=True, ensure_ascii=False, default=str)
    report["content_hash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    report["generated_at"] = datetime.now(UTC).isoformat()
    return report


def report_json(report: dict[str, Any]) -> str:
    return json.dumps(report, sort_keys=True, ensure_ascii=False, indent=2, default=str)


__all__ = [
    "AI_LABEL",
    "REPORT_SCHEMA_VERSION",
    "ReportNotFoundError",
    "build_report",
    "report_json",
]
