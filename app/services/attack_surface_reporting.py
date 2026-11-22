"""Read-only orchestration for the attack-surface summary report.

The orchestrator resolves the repository target registered for an assessment and
runs the existing deterministic analysis services in their established dependency
order. It performs no source analysis of its own, does not persist results, and
does not execute or import repository code.
"""

import uuid
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.orm import Session

from app.core.config import settings
from app.schemas.attack_surface import AttackSurfaceResult
from app.schemas.attack_surface_correlation import AttackSurfaceCorrelationResult
from app.schemas.attack_surface_summary import AttackSurfaceSummaryResult
from app.schemas.auth_controls import AuthControlResult
from app.schemas.handler_calls import HandlerCallResult
from app.schemas.input_operation_flow import InputOperationFlowResult
from app.schemas.input_sources import InputSourceResult
from app.schemas.repository_discovery import RepositoryDiscoveryResult
from app.schemas.sensitive_operations import SensitiveOperationResult
from app.schemas.technology import TechnologyDetectionResult
from app.services.analysis_execution_context import AnalysisExecutionContext
from app.services.attack_surface import identify_attack_surface
from app.services.attack_surface_correlation import correlate_attack_surface
from app.services.attack_surface_summary import summarize_attack_surface
from app.services.auth_controls import identify_auth_controls
from app.services.handler_calls import analyze_handler_calls
from app.services.input_operation_flow import analyze_input_operation_flow
from app.services.input_sources import identify_input_sources
from app.services.repository_discovery import discover_registered_repository
from app.services.sensitive_operations import identify_sensitive_operations
from app.services.technology_detector import detect_technologies


@dataclass(frozen=True, slots=True)
class AssessmentAnalysisResults:
    """Complete outputs from the analysis stages for one assessment."""

    discovery: RepositoryDiscoveryResult
    technologies: TechnologyDetectionResult
    attack_surface: AttackSurfaceResult
    auth_controls: AuthControlResult
    input_sources: InputSourceResult
    sensitive_operations: SensitiveOperationResult
    correlation: AttackSurfaceCorrelationResult
    handler_calls: HandlerCallResult
    input_operation_flow: InputOperationFlowResult
    summary: AttackSurfaceSummaryResult


class RepositoryTargetNotFoundError(ValueError):
    """Raised when an assessment has no registered repository target."""

    def __init__(self) -> None:
        super().__init__("Repository target not found")


def collect_assessment_analysis(
    db: Session,
    assessment_id: uuid.UUID,
    *,
    execution_context: AnalysisExecutionContext | None = None,
) -> AssessmentAnalysisResults:
    """Run every analysis stage once and return their complete outputs.

    The assessment is resolved by :func:`discover_registered_repository`, which
    raises ``AssessmentNotFoundError`` when the assessment does not exist. This
    function raises :class:`RepositoryTargetNotFoundError` when the assessment
    exists but has no registered repository target.

    Discovery and every file-reading analysis stage revalidate the repository
    root against ``REPOSITORY_ALLOWED_ROOTS``. Correlation only verifies that its
    inputs share the already-validated root, and the summary revalidates it
    again. No intermediate result is mutated and nothing is persisted.

    The session transaction is rolled back after discovery so the connection
    returns to the pool before the blocking pipeline runs. Callers that have
    pending database state must commit it before calling this function.

    When an execution context is supplied, cooperative checks run at every
    stage boundary and during repository traversal. The context is optional so
    existing direct callers keep their previous behavior.
    """
    if execution_context is not None:
        execution_context.check()
    discovery = discover_registered_repository(
        db,
        assessment_id,
        execution_context=execution_context,
    )
    if discovery is None:
        raise RepositoryTargetNotFoundError
    if execution_context is not None:
        execution_context.check()

    # Discovery has completed and its result is independent of the session.
    # End the read transaction so the connection returns to the pool before the
    # blocking analysis pipeline runs.
    db.rollback()
    return analyze_discovered_repository(discovery, execution_context=execution_context)


def analyze_discovered_repository(
    discovery: RepositoryDiscoveryResult,
    *,
    execution_context: AnalysisExecutionContext | None = None,
) -> AssessmentAnalysisResults:
    """Run every post-discovery analysis stage once over a discovery inventory.

    This is the database-independent half of :func:`collect_assessment_analysis`
    and is shared with the tool adapter in ``app.services.tooling.adapters`` so the
    stage order is defined in exactly one place. Every file-reading stage
    revalidates ``discovery.root`` against ``REPOSITORY_ALLOWED_ROOTS``.
    """
    root = Path(discovery.root)
    technologies = detect_technologies(root, discovery)
    if execution_context is not None:
        execution_context.check()
    attack_surface = identify_attack_surface(root, discovery, technologies)
    if execution_context is not None:
        execution_context.check()

    auth_controls = identify_auth_controls(
        root,
        discovery,
        technologies,
        attack_surface,
    )
    if execution_context is not None:
        execution_context.check()
    input_sources = identify_input_sources(
        root,
        discovery,
        technologies,
        attack_surface,
    )
    if execution_context is not None:
        execution_context.check()
    sensitive_operations = identify_sensitive_operations(
        root,
        discovery,
        technologies,
        attack_surface,
    )
    if execution_context is not None:
        execution_context.check()

    correlation = correlate_attack_surface(
        attack_surface,
        auth_controls,
        input_sources,
        sensitive_operations,
    )
    if execution_context is not None:
        execution_context.check()
    handler_calls = analyze_handler_calls(
        root,
        discovery,
        technologies,
        attack_surface,
    )
    if execution_context is not None:
        execution_context.check()
    input_operation_flow = analyze_input_operation_flow(
        root,
        discovery,
        correlation,
        input_sources,
        sensitive_operations,
        handler_calls,
    )
    if execution_context is not None:
        execution_context.check()
    summary = summarize_attack_surface(
        root,
        attack_surface,
        correlation,
        handler_calls,
        input_operation_flow,
    )
    if execution_context is not None:
        execution_context.check()

    return AssessmentAnalysisResults(
        discovery=discovery,
        technologies=technologies,
        attack_surface=attack_surface,
        auth_controls=auth_controls,
        input_sources=input_sources,
        sensitive_operations=sensitive_operations,
        correlation=correlation,
        handler_calls=handler_calls,
        input_operation_flow=input_operation_flow,
        summary=summary,
    )


def summarize_assessment_repository(
    db: Session,
    assessment_id: uuid.UUID,
    *,
    execution_context: AnalysisExecutionContext | None = None,
) -> AttackSurfaceSummaryResult:
    """Build the summary for an assessment's registered repository.

    Summary requests invoke the same expensive pipeline as analysis runs but do
    not create an AnalysisRun. They still receive a deadline context so an
    unbounded summary cannot occupy a worker indefinitely.
    """
    context = execution_context or AnalysisExecutionContext(
        settings.analysis_execution_timeout_seconds
    )
    return collect_assessment_analysis(
        db,
        assessment_id,
        execution_context=context,
    ).summary
