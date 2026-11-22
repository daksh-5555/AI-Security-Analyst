"""The fixed workflow graph and its deterministic check planner (M10).

The graph is a fixed sequence of allowlisted nodes. Nothing in it can create a
target, choose a URL, run a shell, or call an arbitrary tool: the only checks
it can plan are the registered analysis stages below, and only for the
assessment's already-authorized target.

Planning is a pure function of the assessment type, the workflow options, and
a snapshot of the configuration. The snapshot is stored with the plan, so the
decisions can be replayed and explained later. No LLM takes part in planning.
"""

from __future__ import annotations

from typing import Any, Final

from app.core.config import settings
from app.schemas.enums import AssessmentType
from app.services.crawler import CRAWL_STAGE
from app.services.dependencies import DEPENDENCY_AUDIT_STAGE
from app.services.runtime_probes import PROBE_STAGE
from app.services.secret_scanning import SECRET_SCAN_STAGE

GRAPH_VERSION: Final = "assessment-workflow/1"

NODE_SEQUENCE: Final[tuple[str, ...]] = (
    "load_assessment",
    "validate_authorization",
    "plan_enabled_checks",
    "approval_gate",
    "run_analysis",
    "explain_findings",
    "generate_report",
    "finalize_run",
)

RUN = "run"
SKIP = "skip"
NEEDS_APPROVAL = "needs_approval"

# Checks that send active test traffic to a target need a recorded human
# approval for every workflow, even when configuration allows them.
HIGH_RISK_CHECKS: Final = frozenset({PROBE_STAGE})
TOOL_CHECKS: Final = frozenset(
    {SECRET_SCAN_STAGE, DEPENDENCY_AUDIT_STAGE, CRAWL_STAGE, PROBE_STAGE}
)


def next_node(node: str) -> str | None:
    index = NODE_SEQUENCE.index(node)
    return NODE_SEQUENCE[index + 1] if index + 1 < len(NODE_SEQUENCE) else None


def config_snapshot() -> dict[str, Any]:
    return {
        "secret_scan_enabled": settings.secret_scan_enabled,
        "dependency_audit_mode": settings.dependency_audit_mode,
        "runtime_probes_enabled": settings.runtime_probes_enabled,
        "llm_explanations_enabled": settings.llm_explanations_enabled,
        "workflow_max_explanations": settings.workflow_max_explanations,
    }


def _check(check: str, kind: str, risk: str, decision: str, reason: str) -> dict[str, str]:
    return {"check": check, "kind": kind, "risk": risk, "decision": decision, "reason": reason}


def plan_checks(
    assessment_type: AssessmentType, options: dict[str, Any], snapshot: dict[str, Any]
) -> dict[str, Any]:
    """Which pre-approved checks run, are skipped, or need approval, and why."""
    checks: list[dict[str, str]] = []
    if assessment_type is AssessmentType.WEB_SECURITY:
        checks.append(_check(CRAWL_STAGE, "tool", "medium", RUN, "authorized web target"))
        if not snapshot["runtime_probes_enabled"]:
            checks.append(_check(PROBE_STAGE, "tool", "high", SKIP, "disabled_by_configuration"))
        else:
            checks.append(
                _check(
                    PROBE_STAGE,
                    "tool",
                    "high",
                    NEEDS_APPROVAL,
                    "active test traffic requires a recorded human approval",
                )
            )
    else:
        checks.append(_check("static_analysis", "pipeline", "low", RUN, "always on"))
        checks.append(
            _check(
                SECRET_SCAN_STAGE,
                "tool",
                "low",
                RUN if snapshot["secret_scan_enabled"] else SKIP,
                "local, read-only"
                if snapshot["secret_scan_enabled"]
                else "disabled_by_configuration",
            )
        )
        mode = snapshot["dependency_audit_mode"]
        checks.append(
            _check(
                DEPENDENCY_AUDIT_STAGE,
                "tool",
                "low",
                SKIP if mode == "disabled" else RUN,
                "disabled_by_configuration" if mode == "disabled" else f"advisory lookup ({mode})",
            )
        )
    wants = bool(options.get("explain_findings"))
    if not wants:
        explain = _check("explain_findings", "advisory", "low", SKIP, "not_requested")
    elif not snapshot["llm_explanations_enabled"]:
        explain = _check("explain_findings", "advisory", "low", SKIP, "disabled_by_configuration")
    elif snapshot["workflow_max_explanations"] == 0:
        explain = _check("explain_findings", "advisory", "low", SKIP, "limit_is_zero")
    else:
        explain = _check(
            "explain_findings", "advisory", "low", RUN, "requested; advisory and redacted"
        )
    checks.append(explain)
    checks.append(
        _check("generate_report", "report", "low", RUN, "built from persisted results (M12)")
    )
    return {"graph_version": GRAPH_VERSION, "config": snapshot, "checks": checks}


def effective_decision(check: dict[str, Any], approvals: dict[str, Any]) -> str:
    if check["decision"] != NEEDS_APPROVAL:
        return check["decision"]
    approval = approvals.get(check["check"])
    return RUN if approval and approval.get("decision") == "approved" else SKIP


def pending_approvals(plan: dict[str, Any], approvals: dict[str, Any]) -> list[str]:
    return [
        check["check"]
        for check in plan["checks"]
        if check["decision"] == NEEDS_APPROVAL and check["check"] not in approvals
    ]


def excluded_tool_stages(plan: dict[str, Any], approvals: dict[str, Any]) -> frozenset[str]:
    return frozenset(
        check["check"]
        for check in plan["checks"]
        if check["kind"] == "tool" and effective_decision(check, approvals) != RUN
    )
