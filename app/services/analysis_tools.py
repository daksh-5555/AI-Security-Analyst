"""Registry-based tools that run alongside the static pipeline in analysis runs.

M2 introduces the first production use of the tool seam (ADR-0001). The existing
static pipeline still runs directly through ``collect_assessment_analysis``
because its rich intermediate results feed the run metadata and the finding
policy; it moves behind the registry when evidence is normalized (M7). New tools,
starting with the secret scanner, run through ``run_stages`` here.

This module also converts tool evidence into the existing ``Finding`` contract.
Secret findings are always ``potential`` (ADR-0005): detection proves that a
credential-shaped value is committed, not that it is valid.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from typing import Any, Final

from sqlalchemy.orm import Session

from app.core.config import settings
from app.schemas.enums import FindingSeverity, FindingStatus
from app.schemas.finding import Evidence, Finding
from app.schemas.repository_discovery import RepositoryDiscoveryResult
from app.schemas.tooling import EvidenceRecord, ToolResult, ToolStatus
from app.services.analysis_execution_context import AnalysisExecutionContext
from app.services.crawler import CRAWL_STAGE, CrawlerTool
from app.services.dependencies import DEPENDENCY_AUDIT_STAGE, DependencyAuditTool
from app.services.finding_normalization import NormalizedFinding
from app.services.runtime_probes import PROBE_STAGE, RuntimeProbeTool
from app.services.secret_scanning import SECRET_SCAN_STAGE, SecretScannerTool
from app.services.tooling import (
    PipelineConfig,
    PipelineOutcome,
    StageRegistry,
    ToolContext,
    run_stages,
)

SECRET_FINDING_CATEGORY: Final[str] = "secret"
DEPENDENCY_FINDING_CATEGORY: Final[str] = "dependency"
_SEVERITY_RANK: Final[dict[str, int]] = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_MAX_LOCATIONS_IN_SUMMARY: Final[int] = 5


def build_tool_registry() -> StageRegistry:
    """Registry of tools that run in addition to the static pipeline."""
    registry = StageRegistry()
    registry.register(SECRET_SCAN_STAGE, SecretScannerTool(), order=100)
    registry.register(DEPENDENCY_AUDIT_STAGE, DependencyAuditTool(), order=200)
    return registry


def build_web_tool_registry() -> StageRegistry:
    """Registry of tools for web-application assessments."""
    registry = StageRegistry()
    registry.register(CRAWL_STAGE, CrawlerTool(), order=100)
    registry.register(PROBE_STAGE, RuntimeProbeTool(), order=200)
    return registry


def web_tool_pipeline_config(excluded: frozenset[str] = frozenset()) -> PipelineConfig:
    """Crawling always runs for web targets; probes only when explicitly enabled.

    ``excluded`` can only remove stages (e.g. checks a workflow did not approve).
    """
    enabled = {CRAWL_STAGE}
    if settings.runtime_probes_enabled:
        enabled.add(PROBE_STAGE)
    return PipelineConfig(enabled_stages=frozenset(enabled - excluded))


def run_web_tools(
    db: Session,
    assessment_id: uuid.UUID,
    execution_context: AnalysisExecutionContext,
    *,
    analysis_run_id: uuid.UUID | None = None,
    registry: StageRegistry | None = None,
    excluded_stages: frozenset[str] = frozenset(),
) -> tuple[str, PipelineOutcome]:
    """Run web tools against the assessment's authorized target.

    The target is re-checked here (it may have been revoked after the run was
    admitted) and the network client is bound to its host by
    ``build_target_client``; tools never construct clients themselves.
    """
    from app.services.lab_credentials import lab_cookie_header
    from app.services.target_authorization import (
        build_target_client,
        require_authorized_web_target,
    )

    target = require_authorized_web_target(db, assessment_id)
    cookie = lab_cookie_header(db, assessment_id)
    client = build_target_client(db, target, default_headers={"Cookie": cookie} if cookie else None)
    target_url = target.canonical_target
    db.rollback()  # release the read transaction before network work
    context = ToolContext(
        execution=execution_context,
        assessment_id=assessment_id,
        analysis_run_id=analysis_run_id,
        web_target_url=target_url,
        http_client=client,
    )
    return target_url, run_stages(
        registry or build_web_tool_registry(), context, web_tool_pipeline_config(excluded_stages)
    )


def crawl_inventory(outcome: PipelineOutcome, limit: int = 200) -> dict[str, Any]:
    """Bounded crawl inventory for run metadata (paths and names only, no values)."""
    result = outcome.result_for(CRAWL_STAGE)
    inventory: dict[str, Any] = {"pages": [], "forms": [], "auth_boundaries": []}
    if result is None:
        return inventory
    for record in result.evidence:
        meta = record.metadata
        path = record.location.url_path
        if record.provenance.rule_id == "crawler.page":
            entry = {
                "path": path,
                **{
                    k: meta.get(k)
                    for k in ("status", "content_type", "depth", "title", "parameters")
                },
            }
            inventory["pages"].append(entry)
        elif record.provenance.rule_id == "crawler.form":
            entry = {
                "page": path,
                **{
                    k: meta.get(k)
                    for k in ("method", "action", "classification", "fields", "submitted")
                },
            }
            inventory["forms"].append(entry)
        elif record.provenance.rule_id == "crawler.auth_boundary":
            inventory["auth_boundaries"].append({"path": path, "signal": meta.get("signal")})
    for key in inventory:
        inventory[key] = inventory[key][:limit]
    return inventory


def tool_pipeline_config(excluded: frozenset[str] = frozenset()) -> PipelineConfig:
    """Enable each registered tool according to settings; disabled ones are skipped.

    ``excluded`` can only remove stages; it never enables one.
    """
    enabled: set[str] = set()
    if settings.secret_scan_enabled:
        enabled.add(SECRET_SCAN_STAGE)
    if settings.dependency_audit_mode != "disabled":
        enabled.add(DEPENDENCY_AUDIT_STAGE)
    return PipelineConfig(enabled_stages=frozenset(enabled - excluded))


def run_supplementary_tools(
    discovery: RepositoryDiscoveryResult,
    execution_context: AnalysisExecutionContext,
    *,
    assessment_id: uuid.UUID | None = None,
    analysis_run_id: uuid.UUID | None = None,
    registry: StageRegistry | None = None,
    excluded_stages: frozenset[str] = frozenset(),
) -> PipelineOutcome:
    """Run registered tools over an already-validated discovery inventory."""
    context = ToolContext(
        execution=execution_context,
        assessment_id=assessment_id,
        analysis_run_id=analysis_run_id,
        discovery=discovery,
    )
    return run_stages(
        registry or build_tool_registry(), context, tool_pipeline_config(excluded_stages)
    )


def _secret_evidence(record: EvidenceRecord) -> Evidence:
    provenance = record.provenance
    return Evidence(
        description=record.summary,
        source=f"{provenance.tool.name}:{provenance.tool.version}",
        details={
            "evidence_key": record.evidence_key,
            "rule_id": provenance.rule_id,
            "rule_set_version": provenance.tool.rule_set_version,
            "path": record.location.path,
            "line": record.location.line,
            "redacted_excerpt": record.redacted_excerpt,
            "fingerprint": record.fingerprint,
            "file_context": record.metadata.get("file_context"),
            "limitations": list(record.limitations),
        },
    )


def secret_findings_from_result(result: ToolResult) -> list[Finding]:
    """API-compatible view of :func:`secret_normalized_findings`."""
    return [item.finding for item in secret_normalized_findings(result)]


def secret_normalized_findings(result: ToolResult) -> list[NormalizedFinding]:
    """Group secret evidence by fingerprint into ``potential`` findings.

    The same value committed in several places becomes one finding with one
    evidence item per location. Severity comes from the most severe matching
    rule; confidence is the highest rule confidence (lowered for test/example
    paths by the scanner).
    """
    if result.stage != SECRET_SCAN_STAGE or result.status not in {
        ToolStatus.COMPLETED,
        ToolStatus.PARTIAL,
    }:
        return []

    groups: dict[str, list[EvidenceRecord]] = defaultdict(list)
    for record in result.evidence:
        groups[record.fingerprint or record.evidence_key].append(record)

    findings: list[tuple[tuple[int, str, int], NormalizedFinding]] = []
    for group_key, records in groups.items():
        records.sort(key=lambda item: (item.location.path or "", item.location.line or 0))
        lead = min(
            records,
            key=lambda item: (
                _SEVERITY_RANK.get(str(item.metadata.get("severity")), 9),
                -float(item.metadata.get("confidence", 0.0)),
                item.evidence_key,
            ),
        )
        severity = str(lead.metadata.get("severity", "medium"))
        title = str(lead.metadata.get("rule_title", "Secret"))
        locations = [f"{item.location.path}:{item.location.line}" for item in records]
        shown = ", ".join(locations[:_MAX_LOCATIONS_IN_SUMMARY])
        if len(locations) > _MAX_LOCATIONS_IN_SUMMARY:
            shown += f", and {len(locations) - _MAX_LOCATIONS_IN_SUMMARY} more"
        finding = Finding(
            title=f"Committed secret: {title}",
            category=SECRET_FINDING_CATEGORY,
            severity=FindingSeverity(severity),
            status=FindingStatus.POTENTIAL,
            confidence=max(float(item.metadata.get("confidence", 0.0)) for item in records),
            summary=(
                f"A value matching the '{title}' rule is committed at {shown}. Its "
                "validity was not tested; treat it as exposed until it is rotated."
            ),
            affected_component=locations[0],
            remediation=str(lead.metadata.get("remediation", "")) or None,
            evidence=[_secret_evidence(item) for item in records],
        )
        sort_key = (
            _SEVERITY_RANK.get(severity, 9),
            records[0].location.path or "",
            records[0].location.line or 0,
        )
        rule = lead.provenance.rule_id
        normalized = NormalizedFinding(
            finding=finding,
            rule_id=rule,
            source_stage=SECRET_SCAN_STAGE,
            identity=group_key,
            evidence=tuple(records),
            verification_method=(
                f"Pattern rule {rule} ({lead.provenance.tool.rule_set_version}); "
                "credential validity was not tested."
            ),
            status_rationale=(
                "potential: detection proves a credential-shaped value is committed, not "
                f"that it is valid. Severity {severity} comes from rule {rule}."
            ),
            cwe_ids=("CWE-798",),
        )
        findings.append((sort_key, normalized))
    return [finding for _, finding in sorted(findings, key=lambda item: item[0])]


_RANGE_STATUS: Final[dict[str, tuple[FindingStatus, float]]] = {
    "affected": (FindingStatus.CONFIRMED, 0.9),
    "unsupported": (FindingStatus.POTENTIAL, 0.5),
    "not_affected": (FindingStatus.INCONCLUSIVE, 0.2),
}


def dependency_findings_from_result(result: ToolResult) -> list[Finding]:
    """API-compatible view of :func:`dependency_normalized_findings`."""
    return [item.finding for item in dependency_normalized_findings(result)]


def dependency_normalized_findings(result: ToolResult) -> list[NormalizedFinding]:
    """One finding per (package, version, advisory), with one evidence item per manifest.

    ``confirmed`` means the exact locked or pinned version lies inside the
    advisory's affected range by local evaluation (ADR-0007). It does not mean the
    vulnerable code path is reachable in this application.
    """
    if result.stage != DEPENDENCY_AUDIT_STAGE or result.status not in {
        ToolStatus.COMPLETED,
        ToolStatus.PARTIAL,
    }:
        return []

    groups: dict[tuple[str, str, str, str], list[EvidenceRecord]] = defaultdict(list)
    for record in result.evidence:
        meta = record.metadata
        key = (
            str(meta.get("ecosystem")),
            str(meta.get("package")).lower(),
            str(meta.get("version")),
            str(meta.get("advisory_id")),
        )
        groups[key].append(record)

    findings: list[tuple[tuple[int, str, str, str], NormalizedFinding]] = []
    for key, records in groups.items():
        records.sort(key=lambda item: item.location.path or "")
        meta = records[0].metadata
        status, confidence = _RANGE_STATUS.get(
            str(meta.get("range_check")), (FindingStatus.POTENTIAL, 0.5)
        )
        if any(item.metadata.get("freshness") == "stale" for item in records):
            confidence = round(confidence * 0.8, 3)
        severity = str(meta.get("severity", "unknown"))
        package, version, advisory_id = (
            meta.get("package"),
            meta.get("version"),
            meta.get("advisory_id"),
        )
        cves = ", ".join(meta.get("cve_ids") or []) or "no CVE alias"
        fixed = [str(item) for item in meta.get("fixed_versions") or []]
        remediation = (
            f"Upgrade {package} to a fixed version ({', '.join(fixed)}) or later and re-run "
            "the analysis."
            if fixed
            else "The advisory lists no fixed version; review it for mitigations or replace "
            "the dependency."
        )
        finding = Finding(
            title=f"Vulnerable dependency: {package} {version} ({advisory_id})"[:300],
            category=DEPENDENCY_FINDING_CATEGORY,
            severity=FindingSeverity(severity),
            status=status,
            confidence=confidence,
            summary=(
                f"{meta.get('advisory_summary')} ({cves}). {meta.get('match_explanation')}. "
                f"Declared in {', '.join(item.location.path or '' for item in records)}. "
                "Exploitability in this application was not assessed."
            )[:2000],
            affected_component=f"{package}@{version}",
            remediation=remediation,
            evidence=[
                Evidence(
                    description=item.summary,
                    source=f"{item.provenance.tool.name}:{item.provenance.tool.version}",
                    details={
                        "evidence_key": item.evidence_key,
                        "rule_id": item.provenance.rule_id,
                        "path": item.location.path,
                        **{
                            name: item.metadata.get(name)
                            for name in (
                                "ecosystem",
                                "package",
                                "version",
                                "relationship",
                                "dependency_source",
                                "dev",
                                "advisory_id",
                                "aliases",
                                "cve_ids",
                                "range_check",
                                "match_explanation",
                                "fixed_versions",
                                "published",
                                "modified",
                                "source",
                                "source_url",
                                "fetched_at",
                                "freshness",
                                "provider_severity",
                            )
                        },  # fmt: skip
                        "limitations": list(item.limitations),
                    },
                )
                for item in records
            ],
        )
        rationale = {
            FindingStatus.CONFIRMED: (
                "confirmed: the exact locked or pinned version lies inside the advisory's "
                "affected range by local evaluation; reachability was not assessed."
            ),
            FindingStatus.POTENTIAL: (
                "potential: the provider reported a match but the version or a range bound "
                "could not be parsed for local verification."
            ),
            FindingStatus.INCONCLUSIVE: (
                "inconclusive: the provider reported a match that the local range check "
                "did not confirm."
            ),
        }[status]
        normalized = NormalizedFinding(
            finding=finding,
            rule_id=records[0].provenance.rule_id,
            source_stage=DEPENDENCY_AUDIT_STAGE,
            identity="|".join(key),
            evidence=tuple(records),
            verification_method=(
                f"OSV advisory lookup with local affected-range evaluation: "
                f"{meta.get('match_explanation')}"
            ),
            status_rationale=(
                f"{rationale} Severity {severity} from the advisory label "
                f"({meta.get('provider_severity') or 'none'})."
            ),
            cve_ids=tuple(str(cve) for cve in meta.get("cve_ids") or []),
        )
        findings.append(((_SEVERITY_RANK.get(severity, 9), key[1], key[2], key[3]), normalized))
    return [finding for _, finding in sorted(findings, key=lambda item: item[0])]


_RUNTIME_RULES: Final[dict[str, dict[str, tuple[FindingStatus, str, float]]]] = {
    "runtime.xss_reflection": {
        "potential": (FindingStatus.POTENTIAL, "medium", 0.6),
        "inconclusive": (FindingStatus.INCONCLUSIVE, "medium", 0.3),
    },
    "runtime.sqli_boolean": {
        "confirmed": (FindingStatus.CONFIRMED, "high", 0.9),
        "inconclusive": (FindingStatus.INCONCLUSIVE, "high", 0.4),
    },
    "runtime.sqli_error_signal": {
        "potential": (FindingStatus.POTENTIAL, "medium", 0.4),
    },
}
_RUNTIME_TEXT: Final[dict[str, tuple[str, str, str, str]]] = {
    # rule: (category, title prefix, verification method, remediation)
    "runtime.xss_reflection": (
        "xss",
        "Possible reflected XSS",
        "Inert marker reflected without HTML encoding of \" ' < > (CWE-79); script "
        "execution not demonstrated.",
        "Apply context-aware output encoding for every reflected value, validate input, "
        "and add a restrictive Content-Security-Policy.",
    ),
    "runtime.sqli_boolean": (
        "sqli",
        "SQL injection (boolean-based)",
        "Read-only AND true/false pairs against a stable baseline, repeated with new "
        "literals (CWE-89).",
        "Use parameterized queries or a safe query builder for this parameter; never "
        "concatenate request values into SQL.",
    ),
    "runtime.sqli_error_signal": (
        "sqli",
        "Possible SQL injection (database error on quote)",
        "A database error appeared only after a single quote (CWE-89); the boolean test "
        "did not confirm injection.",
        "Use parameterized queries and suppress database error details in responses.",
    ),
}


def runtime_findings_from_result(result: ToolResult) -> list[Finding]:
    """API-compatible view of :func:`runtime_normalized_findings`."""
    return [item.finding for item in runtime_normalized_findings(result)]


_RUNTIME_RATIONALE: Final[dict[str, str]] = {
    "potential": "the signal was observed but does not meet the rule's proof standard",
    "inconclusive": "the signal did not reproduce consistently",
    "confirmed": "two independent boolean pairs reproduced the differential",
}


def runtime_normalized_findings(result: ToolResult) -> list[NormalizedFinding]:
    """One finding per probed parameter and rule, with status from the proof rules."""
    if result.stage != PROBE_STAGE or result.status not in {
        ToolStatus.COMPLETED,
        ToolStatus.PARTIAL,
    }:
        return []
    findings: list[tuple[tuple[int, str, str], NormalizedFinding]] = []
    for record in result.evidence:
        rule = record.provenance.rule_id
        verdict = str(record.metadata.get("verdict"))
        mapping = _RUNTIME_RULES.get(rule, {}).get(verdict)
        if mapping is None:
            continue
        status, severity, confidence = mapping
        category, title, method, remediation = _RUNTIME_TEXT[rule]
        location = record.location.url_path or "/"
        parameter = record.location.parameter or "?"
        finding = Finding(
            title=f"{title}: parameter '{parameter}' at {location.split('?')[0]}"[:300],
            category=category,
            severity=FindingSeverity(severity),
            status=status,
            confidence=confidence,
            summary=f"{record.summary}. Verification: {method}"[:2000],
            affected_component=f"GET {location}",
            remediation=remediation,
            evidence=[
                Evidence(
                    description=record.summary,
                    source=f"{record.provenance.tool.name}:{record.provenance.tool.version}",
                    details={
                        "evidence_key": record.evidence_key,
                        "rule_id": rule,
                        "url_path": location,
                        "parameter": parameter,
                        "verdict": verdict,
                        "request_summary": record.request_summary,
                        "response_summary": record.response_summary,
                        **{k: v for k, v in record.metadata.items() if k != "verdict"},
                        "limitations": list(record.limitations),
                    },
                )
            ],
        )
        normalized = NormalizedFinding(
            finding=finding,
            rule_id=rule,
            source_stage=PROBE_STAGE,
            identity=f"{location}|{parameter}",
            evidence=(record,),
            verification_method=method,
            status_rationale=(
                f"{verdict}: {_RUNTIME_RATIONALE.get(verdict, verdict)} (ADR-0009). "
                f"Severity {severity} is fixed per rule."
            ),
            cwe_ids=tuple(str(cwe) for cwe in record.metadata.get("cwe_ids") or []),
        )
        findings.append(((_SEVERITY_RANK.get(severity, 9), location, parameter), normalized))
    return [finding for _, finding in sorted(findings, key=lambda item: item[0])]


def normalized_findings_from_outcome(outcome: PipelineOutcome) -> list[NormalizedFinding]:
    """All normalized findings produced by registry tools, in deterministic order."""
    findings: list[NormalizedFinding] = []
    for result in outcome.results:
        findings.extend(secret_normalized_findings(result))
        findings.extend(dependency_normalized_findings(result))
        findings.extend(runtime_normalized_findings(result))
    return findings


def findings_from_outcome(outcome: PipelineOutcome) -> list[Finding]:
    """API-compatible view of :func:`normalized_findings_from_outcome`."""
    return [item.finding for item in normalized_findings_from_outcome(outcome)]


def tool_metadata(outcome: PipelineOutcome) -> list[dict[str, Any]]:
    """Bounded, non-sensitive per-tool summary for ``analysis_metadata``."""
    return [
        {
            "stage": result.stage,
            "tool": result.tool.name,
            "version": result.tool.version,
            "rule_set_version": result.tool.rule_set_version,
            "status": result.status.value,
            "error_code": result.error_code.value if result.error_code else None,
            "counts": dict(sorted(result.counts.items())),
            "evidence_count": len(result.evidence),
            "limitations": [
                {"code": item.code, "detail": item.detail} for item in result.limitations[:50]
            ],
        }
        for result in outcome.results
    ]


__all__ = [
    "DEPENDENCY_FINDING_CATEGORY",
    "dependency_normalized_findings",
    "normalized_findings_from_outcome",
    "runtime_normalized_findings",
    "secret_normalized_findings",
    "build_web_tool_registry",
    "crawl_inventory",
    "run_web_tools",
    "runtime_findings_from_result",
    "web_tool_pipeline_config",
    "SECRET_FINDING_CATEGORY",
    "dependency_findings_from_result",
    "build_tool_registry",
    "findings_from_outcome",
    "run_supplementary_tools",
    "secret_findings_from_result",
    "tool_metadata",
    "tool_pipeline_config",
]
