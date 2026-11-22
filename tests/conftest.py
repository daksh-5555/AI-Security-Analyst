# ruff: noqa: E402

import os

# Application settings are constructed at import time, so the test environment
# must be configured before any ``app`` module is imported.
os.environ["APP_ENV"] = "test"


import ipaddress
import socket
import uuid
from collections.abc import AsyncIterator, Generator
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest
from alembic import command
from alembic.config import Config
from pydantic import SecretStr
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.api.dependencies import Principal, get_current_principal
from app.core.config import settings
from app.core.mailer import get_mailer
from app.core.rate_limit import (
    auth_rate_limiter,
    login_failure_limiter,
    unauthenticated_audit_limiter,
)
from app.core.security import create_access_token, decode_access_token
from app.db.session import create_db_engine, get_db
from app.main import app
from app.schemas.enums import RoleName
from app.services.analysis_admission import analysis_admission

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TEST_JWT_SECRET = "test-only-jwt-secret-" + "x" * 40


@pytest.fixture
def configure_jwt(monkeypatch: pytest.MonkeyPatch) -> None:
    """Provide a strong test signing secret for login and principal tests."""
    monkeypatch.setattr(settings, "jwt_secret", SecretStr(TEST_JWT_SECRET))


@pytest.fixture
def low_cost_argon2(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep identity API tests fast without changing production defaults."""
    monkeypatch.setattr(settings, "argon2_time_cost", 1)
    monkeypatch.setattr(settings, "argon2_memory_cost_kib", 8192)
    monkeypatch.setattr(settings, "argon2_parallelism", 1)
    monkeypatch.setattr(settings, "argon2_hash_len", 32)
    monkeypatch.setattr(settings, "argon2_salt_len", 16)


@dataclass(frozen=True)
class SentEmail:
    """One message captured by the recording mailer."""

    to: str
    subject: str
    body: str


class RecordingMailer:
    """In-memory mailer used by API tests."""

    def __init__(self) -> None:
        self.messages: list[SentEmail] = []

    def send(self, *, to: str, subject: str, body: str) -> None:
        self.messages.append(SentEmail(to=to, subject=subject, body=body))


@pytest.fixture(autouse=True)
def reset_auth_rate_limiter() -> Generator[None, None, None]:
    limiters = (auth_rate_limiter, login_failure_limiter, unauthenticated_audit_limiter)
    for limiter in limiters:
        limiter.reset()
    yield
    for limiter in limiters:
        limiter.reset()


def _is_loopback_address(address: object) -> bool:
    if isinstance(address, (str, bytes)):  # AF_UNIX paths
        return True
    host = address[0] if isinstance(address, tuple) and address else None
    try:
        return ipaddress.ip_address(str(host).split("%", 1)[0]).is_loopback
    except ValueError:
        return False


@pytest.fixture(autouse=True)
def block_external_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests are offline: only loopback connections (local fixture servers) are allowed."""
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex

    def guarded_connect(sock: socket.socket, address: object) -> None:
        if not _is_loopback_address(address):
            raise AssertionError("tests must not open non-loopback network connections")
        original_connect(sock, address)

    def guarded_connect_ex(sock: socket.socket, address: object) -> int:
        if not _is_loopback_address(address):
            raise AssertionError("tests must not open non-loopback network connections")
        return original_connect_ex(sock, address)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", guarded_connect_ex)


@pytest.fixture(autouse=True)
def offline_dependency_audit(monkeypatch: pytest.MonkeyPatch) -> None:
    """Dependency advisories come only from local fixtures or caches in tests."""
    monkeypatch.setattr(settings, "dependency_audit_mode", "offline")


@pytest.fixture(autouse=True)
def _workflow_engine(monkeypatch: pytest.MonkeyPatch) -> None:
    """Run the workflow suite under TEST_WORKFLOW_ENGINE (builtin | langgraph)."""
    engine = os.environ.get("TEST_WORKFLOW_ENGINE")
    if engine:
        monkeypatch.setattr(settings, "workflow_engine", engine)


@pytest.fixture(autouse=True)
def reset_analysis_admission() -> Generator[None, None, None]:
    analysis_admission.reset()
    yield
    analysis_admission.reset()


@pytest.fixture
def mailer() -> RecordingMailer:
    return RecordingMailer()


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


# Opt-in PostgreSQL mode (M13): set TEST_POSTGRES_URL to a dedicated, empty
# database (for example postgresql+psycopg://localhost/aisa_test). Each test then
# runs in its own throwaway schema; SQLite remains the default.
TEST_POSTGRES_URL = os.environ.get("TEST_POSTGRES_URL")


def _postgres_schema_url(base_url: str, schema: str) -> str:
    separator = "&" if "?" in base_url else "?"
    return f"{base_url}{separator}options=-csearch_path%3D{schema}"


@pytest.fixture
def db_engine(tmp_path: Path) -> Generator[Engine, None, None]:
    if TEST_POSTGRES_URL:
        yield from _postgres_engine()
        return
    database_path = tmp_path / "test.db"
    database_url = f"sqlite:///{database_path.as_posix()}"

    config = Config(str(PROJECT_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "head")

    engine = create_db_engine(database_url)
    try:
        yield engine
    finally:
        engine.dispose()


def _postgres_engine() -> Generator[Engine, None, None]:
    from sqlalchemy import text

    assert TEST_POSTGRES_URL is not None
    schema = f"t_{uuid.uuid4().hex[:16]}"
    admin = create_db_engine(TEST_POSTGRES_URL)
    with admin.begin() as conn:
        conn.execute(text(f'CREATE SCHEMA "{schema}"'))
    url = _postgres_schema_url(TEST_POSTGRES_URL, schema)
    config = Config(str(PROJECT_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    engine = create_db_engine(url)
    try:
        command.upgrade(config, "head")
        yield engine
    finally:
        engine.dispose()
        with admin.begin() as conn:
            conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()


@pytest.fixture
def session_factory(db_engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=db_engine, autoflush=False, expire_on_commit=False)


@pytest.fixture
async def client(
    session_factory: sessionmaker[Session],
) -> AsyncIterator[httpx.AsyncClient]:
    def override_get_db() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db
    transport = httpx.ASGITransport(app=app)

    try:
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://test",
        ) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()


@pytest.fixture
async def auth_client(
    client: httpx.AsyncClient,
    mailer: RecordingMailer,
) -> AsyncIterator[httpx.AsyncClient]:
    app.dependency_overrides[get_mailer] = lambda: mailer
    yield client


@pytest.fixture
def make_assessment_principal(
    session_factory: sessionmaker[Session],
    configure_jwt: None,
    low_cost_argon2: None,
):
    """Create a verified user with a live session and return auth headers."""

    from auth_helpers import assign_role, create_session, create_user

    def _make(
        *,
        email: str | None = None,
        role: RoleName | None = RoleName.SECURITY_ANALYST,
    ) -> tuple[uuid.UUID, dict[str, str]]:
        user_email = email or f"assessment-{uuid.uuid4().hex}@example.com"
        user_id = create_user(
            session_factory,
            email=user_email,
            is_email_verified=True,
        )
        if role is not None:
            assign_role(session_factory, user_id, role)
        session_id = create_session(session_factory, user_id)
        token = create_access_token(user_id=user_id, session_id=session_id)
        return user_id, {"Authorization": f"Bearer {token}"}

    return _make


@pytest.fixture
def assessment_client(
    make_assessment_principal,
    configure_jwt: None,
) -> Generator[None, None, None]:
    """Authenticate assessment API tests as a Security Analyst.

    The principal is installed as a dependency override rather than as request
    headers so this fixture stays synchronous and can safely apply to the
    existing mix of async API tests and sync service/migration tests. The
    dedicated authorization suite exercises the real token/session path.
    """
    user_id, headers = make_assessment_principal()
    token = headers["Authorization"].removeprefix("Bearer ")
    claims = decode_access_token(token)
    principal = Principal(
        user_id=user_id,
        email=f"assessment-{user_id.hex}@example.com",
        session_id=claims.sid,
        is_active=True,
        is_email_verified=True,
        roles=(RoleName.SECURITY_ANALYST.value,),
        claims=claims,
    )

    app.dependency_overrides[get_current_principal] = lambda: principal
    try:
        yield
    finally:
        app.dependency_overrides.pop(get_current_principal, None)
