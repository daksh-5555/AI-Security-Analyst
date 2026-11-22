"""Assessment report downloads (M12, ADR-0015).

Reports are built from persisted data on each request (nothing is re-scanned)
and follow the existing assessment read authorization. They are sent as
attachments with ``no-store`` caching, ``nosniff``, and, for HTML, a strict
Content-Security-Policy header in addition to the one embedded in the document.
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

from app.api.dependencies import ReadableAssessment, get_current_principal
from app.core.config import settings
from app.db.session import get_db
from app.services.reports.builder import ReportNotFoundError, build_report, report_json
from app.services.reports.html import CONTENT_SECURITY_POLICY, render_html

router = APIRouter(
    prefix="/api/v1",
    tags=["reports"],
    dependencies=[Depends(get_current_principal)],
)

REPORT_PATH = "/assessments/{assessment_id}/reports"
REPORT_NOT_FOUND_DETAIL = "Assessment or analysis run not found"
REPORT_TOO_LARGE_DETAIL = "Report exceeds the configured size limit"
_RESPONSES = {
    status.HTTP_404_NOT_FOUND: {"description": REPORT_NOT_FOUND_DETAIL},
    status.HTTP_413_CONTENT_TOO_LARGE: {"description": REPORT_TOO_LARGE_DETAIL},
}


def _build(db: Session, assessment_id: uuid.UUID, run_id: uuid.UUID | None) -> dict:
    try:
        return build_report(db, assessment_id, analysis_run_id=run_id)
    except ReportNotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=REPORT_NOT_FOUND_DETAIL) from exc


def _respond(body: str, media_type: str, filename: str, extra: dict[str, str]) -> Response:
    data = body.encode("utf-8")
    if len(data) > settings.report_max_bytes:
        raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, detail=REPORT_TOO_LARGE_DETAIL)
    return Response(
        content=data,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            **extra,
        },
    )


@router.get(
    f"{REPORT_PATH}/json",
    responses={
        status.HTTP_200_OK: {
            "content": {"application/json": {}},
            "description": "Deterministic JSON report (schema assessment-report/1).",
        },
        **_RESPONSES,
    },
)
def download_json_report(
    db: Annotated[Session, Depends(get_db)],
    assessment: ReadableAssessment,
    analysis_run_id: Annotated[uuid.UUID | None, Query()] = None,
) -> Response:
    """JSON report for the latest finished run, or the given run."""
    report = _build(db, assessment.id, analysis_run_id)
    return _respond(
        report_json(report),
        "application/json",
        f"assessment-{assessment.id}-report.json",
        {},
    )


@router.get(
    f"{REPORT_PATH}/html",
    responses={
        status.HTTP_200_OK: {
            "content": {"text/html": {}},
            "description": "Self-contained, escaped HTML report with no remote resources.",
        },
        **_RESPONSES,
    },
)
def download_html_report(
    db: Annotated[Session, Depends(get_db)],
    assessment: ReadableAssessment,
    analysis_run_id: Annotated[uuid.UUID | None, Query()] = None,
) -> Response:
    """HTML rendering of the same report."""
    report = _build(db, assessment.id, analysis_run_id)
    return _respond(
        render_html(report),
        "text/html; charset=utf-8",
        f"assessment-{assessment.id}-report.html",
        {"Content-Security-Policy": CONTENT_SECURITY_POLICY},
    )
