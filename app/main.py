from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from starlette.responses import JSONResponse, PlainTextResponse

from app.api.admin_audit import router as admin_audit_router
from app.api.admin_security_monitoring import router as admin_security_monitoring_router
from app.api.analysis_runs import router as analysis_runs_router
from app.api.attack_surface import is_summary_request_path
from app.api.attack_surface import router as attack_surface_router
from app.api.auth import router as auth_router
from app.api.evidence import router as evidence_router
from app.api.explanations import router as explanations_router
from app.api.knowledge import router as knowledge_router
from app.api.lab_credentials import router as lab_credentials_router
from app.api.reports import router as reports_router
from app.api.targets import router as targets_router
from app.api.v1 import router as api_v1_router
from app.api.workflows import router as workflows_router
from app.core.config import api_docs_enabled, settings, validate_security_configuration
from app.db.session import engine


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    validate_security_configuration(settings)
    yield
    engine.dispose()


# Validate at import time as well as at startup. Some ASGI hosts and
# ``uvicorn --lifespan off`` never run lifespan events, and a deployed process
# must fail closed rather than serve requests with unsafe configuration.
validate_security_configuration(settings)

_DOCS_ENABLED = api_docs_enabled(settings)

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    lifespan=lifespan,
    docs_url="/docs" if _DOCS_ENABLED else None,
    redoc_url="/redoc" if _DOCS_ENABLED else None,
    openapi_url="/openapi.json" if _DOCS_ENABLED else None,
)


def _apply_cache_control(response: Response, path: str) -> None:
    """Apply no-store to responses that must never be cached."""
    if is_summary_request_path(path):
        response.headers["Cache-Control"] = "no-store"
    if path.startswith("/api/v1/auth/"):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
    if path.startswith("/api/v1/admin/"):
        response.headers["Cache-Control"] = "no-store"


async def handle_unexpected_error(request: Request, _exc: Exception) -> Response:
    """Preserve the generic server-error response and mark summary failures.

    Starlette handles unhandled exceptions in ``ServerErrorMiddleware`` outside
    the normal HTTP middleware response path. Registering this handler keeps the
    default response body while ensuring the summary endpoint still gets
    ``Cache-Control: no-store`` for failures raised before its route function runs.
    """
    response = PlainTextResponse("Internal Server Error", status_code=500)
    _apply_cache_control(response, request.url.path)
    return response


async def handle_request_validation_error(
    _request: Request,
    exc: RequestValidationError,
) -> Response:
    """Return validation errors without echoing any submitted value.

    FastAPI's default handler serializes ``input`` for every error, which would
    echo tokens and passwords on auth routes and repository paths or other
    caller-supplied data elsewhere. The error location, type, and message are
    preserved so clients can still identify the invalid field.
    """
    sanitized = [
        {key: value for key, value in error.items() if key != "input"}
        if isinstance(error, dict)
        else error
        for error in exc.errors()
    ]
    return JSONResponse(status_code=422, content={"detail": jsonable_encoder(sanitized)})


app.add_exception_handler(Exception, handle_unexpected_error)
app.add_exception_handler(RequestValidationError, handle_request_validation_error)


@app.middleware("http")
async def add_summary_cache_control(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    """Apply no-store only to the attack-surface summary, auth, and admin endpoints."""
    response = await call_next(request)
    _apply_cache_control(response, request.url.path)
    return response


app.include_router(api_v1_router)
app.include_router(attack_surface_router)
app.include_router(analysis_runs_router)
app.include_router(targets_router)
app.include_router(evidence_router)
app.include_router(explanations_router)
app.include_router(workflows_router)
app.include_router(knowledge_router)
app.include_router(reports_router)
app.include_router(lab_credentials_router)
app.include_router(auth_router)
app.include_router(admin_audit_router)
app.include_router(admin_security_monitoring_router)


@app.get("/health")
async def health() -> dict[str, str]:
    """Report that the API process is running and able to serve requests."""
    return {"status": "ok"}
