from pathlib import Path
from uuid import UUID, uuid4

import pytest
from pydantic import SecretStr, ValidationError

from app.core.config import (
    MIN_JWT_SECRET_BYTES,
    SecurityConfigurationError,
    Settings,
    api_docs_enabled,
    settings,
    validate_security_configuration,
)
from app.core.security import create_access_token, decode_access_token

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TEST_SECRET = "test-only-jwt-secret-" + "x" * 40
# Explicit deployment values that staging and production require.
DEPLOYMENT_SETTINGS = {
    "database_url": "sqlite:////srv/ai-security-analyst/app.db",
    "smtp_host": "smtp.example.com",
    "email_from": "no-reply@example.com",
    "repository_allowed_roots": [Path("/srv/repositories")],
    "evidence_fingerprint_key": "test-only-fingerprint-key-" + "f" * 32,
    "repository_isolation": "per_user",
}
SECURITY_ENV_VARS = (
    "APP_ENV",
    "JWT_SECRET",
    "JWT_ALGORITHM",
    "JWT_ISSUER",
    "JWT_AUDIENCE",
    "ACCESS_TOKEN_TTL_SECONDS",
    "REFRESH_TOKEN_TTL_SECONDS",
    "ABSOLUTE_SESSION_TTL_SECONDS",
    "JWT_CLOCK_SKEW_SECONDS",
    "OPAQUE_TOKEN_BYTES",
    "ARGON2_TIME_COST",
    "ARGON2_MEMORY_COST_KIB",
    "ARGON2_PARALLELISM",
    "ARGON2_HASH_LEN",
    "ARGON2_SALT_LEN",
    "EMAIL_BACKEND",
    "EMAIL_FROM",
    "SMTP_HOST",
    "SMTP_PORT",
    "SMTP_USERNAME",
    "SMTP_PASSWORD",
    "SMTP_STARTTLS",
    "SMTP_SSL",
    "SMTP_TIMEOUT_SECONDS",
    "EMAIL_VERIFICATION_TOKEN_TTL_SECONDS",
    "PASSWORD_RESET_TOKEN_TTL_SECONDS",
    "AUTH_RATE_LIMIT_WINDOW_SECONDS",
    "AUTH_RATE_LIMIT_MAX_REQUESTS",
    "AUTH_TOKEN_REQUEST_COOLDOWN_SECONDS",
    "ANALYSIS_EXECUTION_TIMEOUT_SECONDS",
    "ANALYSIS_HEARTBEAT_INTERVAL_SECONDS",
    "ANALYSIS_STALE_AFTER_SECONDS",
    "ANALYSIS_MAX_CONCURRENT_JOBS",
    "ANALYSIS_MAX_CONCURRENT_JOBS_PER_USER",
    "ANALYSIS_QUEUE_WAIT_SECONDS",
    "ANALYSIS_RATE_LIMIT_MAX_REQUESTS",
    "ANALYSIS_RATE_LIMIT_WINDOW_SECONDS",
)


@pytest.fixture(autouse=True)
def clean_security_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in SECURITY_ENV_VARS:
        monkeypatch.delenv(name, raising=False)


def test_security_defaults_are_safe() -> None:
    config = Settings(_env_file=None, app_env="test")

    assert config.app_env == "test"
    assert config.email_backend == "smtp"
    assert config.jwt_secret is None
    assert config.jwt_algorithm == "HS256"
    assert config.jwt_issuer == "ai-security-analyst"
    assert config.jwt_audience == "ai-security-analyst-api"
    assert config.access_token_ttl_seconds == 600
    assert config.refresh_token_ttl_seconds == 1_209_600
    assert config.absolute_session_ttl_seconds == 2_592_000
    assert config.jwt_clock_skew_seconds == 30
    assert config.opaque_token_bytes == 48
    assert config.argon2_time_cost == 3
    assert config.argon2_memory_cost_kib == 65536
    assert config.argon2_parallelism == 4
    assert config.argon2_hash_len == 32
    assert config.argon2_salt_len == 16
    assert config.analysis_execution_timeout_seconds == 300
    assert config.analysis_heartbeat_interval_seconds == 15
    assert config.analysis_stale_after_seconds == 420
    assert config.analysis_max_concurrent_jobs == 2
    assert config.analysis_max_concurrent_jobs_per_user == 1
    assert config.analysis_queue_wait_seconds == 2
    assert config.analysis_rate_limit_max_requests == 10
    assert config.analysis_rate_limit_window_seconds == 60


def test_missing_app_env_is_rejected() -> None:
    with pytest.raises(ValidationError) as exc_info:
        Settings(_env_file=None)

    assert "app_env" in str(exc_info.value).lower()


def test_invalid_app_env_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, app_env="qa")


def test_env_example_parses_with_required_settings() -> None:
    config = Settings(_env_file=PROJECT_ROOT / ".env.example")

    assert config.app_env == "development"
    assert config.email_backend == "console"
    assert config.refresh_token_ttl_seconds == 1_209_600
    assert config.absolute_session_ttl_seconds == 2_592_000


def test_secret_str_does_not_expose_value() -> None:
    config = Settings(_env_file=None, app_env="test", jwt_secret=TEST_SECRET)

    assert config.jwt_secret is not None
    assert config.jwt_secret.get_secret_value() == TEST_SECRET
    assert str(config.jwt_secret) == "**********"
    assert TEST_SECRET not in repr(config)
    assert TEST_SECRET not in str(config)


def test_ttl_must_be_within_five_to_ten_minutes() -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, app_env="test", access_token_ttl_seconds=299)
    with pytest.raises(ValidationError):
        Settings(_env_file=None, app_env="test", access_token_ttl_seconds=901)


@pytest.mark.parametrize("value", [299, 7_776_001])
def test_refresh_ttl_bounds(value: int) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, app_env="test", refresh_token_ttl_seconds=value)


@pytest.mark.parametrize("value", [3_599, 7_776_001])
def test_absolute_session_ttl_bounds(value: int) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, app_env="test", absolute_session_ttl_seconds=value)


def test_refresh_ttl_cannot_exceed_absolute_session_ttl() -> None:
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            _env_file=None,
            app_env="test",
            refresh_token_ttl_seconds=7_200,
            absolute_session_ttl_seconds=3_600,
        )

    assert "REFRESH_TOKEN_TTL_SECONDS" in str(exc_info.value)


def test_refresh_ttl_cannot_be_lower_than_access_ttl() -> None:
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            _env_file=None,
            app_env="test",
            access_token_ttl_seconds=900,
            refresh_token_ttl_seconds=600,
        )

    assert "REFRESH_TOKEN_TTL_SECONDS" in str(exc_info.value)


def test_refresh_ttl_equal_to_access_ttl_is_allowed() -> None:
    config = Settings(
        _env_file=None,
        app_env="test",
        access_token_ttl_seconds=600,
        refresh_token_ttl_seconds=600,
        absolute_session_ttl_seconds=3_600,
    )

    assert config.refresh_token_ttl_seconds == config.access_token_ttl_seconds


@pytest.mark.parametrize(
    "field",
    [
        "opaque_token_bytes",
        "argon2_time_cost",
        "argon2_memory_cost_kib",
        "argon2_parallelism",
        "argon2_hash_len",
        "argon2_salt_len",
    ],
)
def test_security_numeric_bounds_reject_zero(field: str) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, app_env="test", **{field: 0})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("analysis_execution_timeout_seconds", 0),
        ("analysis_execution_timeout_seconds", 3_601),
        ("analysis_heartbeat_interval_seconds", 0),
        ("analysis_heartbeat_interval_seconds", 301),
        ("analysis_stale_after_seconds", 4),
        ("analysis_stale_after_seconds", 86_401),
        ("analysis_max_concurrent_jobs", 0),
        ("analysis_max_concurrent_jobs", 33),
        ("analysis_max_concurrent_jobs_per_user", 0),
        ("analysis_max_concurrent_jobs_per_user", 9),
        ("analysis_queue_wait_seconds", -1),
        ("analysis_queue_wait_seconds", 31),
        ("analysis_rate_limit_max_requests", 0),
        ("analysis_rate_limit_max_requests", 1_001),
        ("analysis_rate_limit_window_seconds", 0),
        ("analysis_rate_limit_window_seconds", 3_601),
    ],
)
def test_analysis_execution_bounds_reject_out_of_range_values(
    field: str,
    value: int,
) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, app_env="test", **{field: value})


def test_analysis_heartbeat_must_be_less_than_execution_timeout() -> None:
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            _env_file=None,
            app_env="test",
            analysis_execution_timeout_seconds=30,
            analysis_heartbeat_interval_seconds=30,
        )

    assert "ANALYSIS_HEARTBEAT_INTERVAL_SECONDS" in str(exc_info.value)


def test_analysis_stale_threshold_must_exceed_execution_timeout() -> None:
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            _env_file=None,
            app_env="test",
            analysis_execution_timeout_seconds=300,
            analysis_stale_after_seconds=300,
        )

    assert "ANALYSIS_STALE_AFTER_SECONDS" in str(exc_info.value)


def test_analysis_stale_threshold_must_cover_two_heartbeats() -> None:
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            _env_file=None,
            app_env="test",
            analysis_execution_timeout_seconds=300,
            analysis_heartbeat_interval_seconds=15,
            analysis_stale_after_seconds=329,
        )

    assert "ANALYSIS_STALE_AFTER_SECONDS" in str(exc_info.value)


def test_analysis_per_user_concurrency_cannot_exceed_global() -> None:
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            _env_file=None,
            app_env="test",
            analysis_max_concurrent_jobs=2,
            analysis_max_concurrent_jobs_per_user=3,
        )

    assert "ANALYSIS_MAX_CONCURRENT_JOBS_PER_USER" in str(exc_info.value)


def test_analysis_queue_wait_must_be_less_than_execution_timeout() -> None:
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            _env_file=None,
            app_env="test",
            analysis_execution_timeout_seconds=30,
            analysis_heartbeat_interval_seconds=1,
            analysis_queue_wait_seconds=30,
        )

    assert "ANALYSIS_QUEUE_WAIT_SECONDS" in str(exc_info.value)


def test_analysis_execution_boundary_configuration_is_allowed() -> None:
    config = Settings(
        _env_file=None,
        app_env="test",
        analysis_execution_timeout_seconds=30,
        analysis_heartbeat_interval_seconds=1,
        analysis_stale_after_seconds=32,
        analysis_max_concurrent_jobs=2,
        analysis_max_concurrent_jobs_per_user=2,
        analysis_queue_wait_seconds=29,
    )

    assert config.analysis_stale_after_seconds == 32
    assert config.analysis_max_concurrent_jobs_per_user == 2


def test_analysis_execution_settings_are_read_from_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANALYSIS_EXECUTION_TIMEOUT_SECONDS", "600")
    monkeypatch.setenv("ANALYSIS_HEARTBEAT_INTERVAL_SECONDS", "20")
    monkeypatch.setenv("ANALYSIS_STALE_AFTER_SECONDS", "900")
    monkeypatch.setenv("ANALYSIS_MAX_CONCURRENT_JOBS", "4")
    monkeypatch.setenv("ANALYSIS_MAX_CONCURRENT_JOBS_PER_USER", "2")
    monkeypatch.setenv("ANALYSIS_QUEUE_WAIT_SECONDS", "5")
    monkeypatch.setenv("ANALYSIS_RATE_LIMIT_MAX_REQUESTS", "7")
    monkeypatch.setenv("ANALYSIS_RATE_LIMIT_WINDOW_SECONDS", "30")

    config = Settings(_env_file=None, app_env="test")

    assert config.analysis_execution_timeout_seconds == 600
    assert config.analysis_heartbeat_interval_seconds == 20
    assert config.analysis_stale_after_seconds == 900
    assert config.analysis_max_concurrent_jobs == 4
    assert config.analysis_max_concurrent_jobs_per_user == 2
    assert config.analysis_queue_wait_seconds == 5
    assert config.analysis_rate_limit_max_requests == 7
    assert config.analysis_rate_limit_window_seconds == 30


def test_analysis_rate_limits_do_not_inherit_auth_rate_limits() -> None:
    config = Settings(
        _env_file=None,
        app_env="test",
        auth_rate_limit_max_requests=2,
        auth_rate_limit_window_seconds=5,
    )

    assert config.analysis_rate_limit_max_requests == 10
    assert config.analysis_rate_limit_window_seconds == 60


def test_algorithm_is_pinned_to_hs256() -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, app_env="test", jwt_algorithm="RS256")


def test_short_secret_is_rejected_without_disclosure() -> None:
    short_secret = "s" * (MIN_JWT_SECRET_BYTES - 1)

    with pytest.raises(ValidationError) as exc_info:
        Settings(_env_file=None, app_env="test", jwt_secret=short_secret)

    assert short_secret not in str(exc_info.value)


def test_blank_secret_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, app_env="test", jwt_secret=" " * 40)


def test_secret_length_uses_utf8_bytes_not_characters() -> None:
    # 16 characters encoded as two bytes each equals exactly 32 UTF-8 bytes.
    config = Settings(_env_file=None, app_env="test", jwt_secret="é" * 16)
    assert config.jwt_secret is not None
    assert len(config.jwt_secret.get_secret_value().encode("utf-8")) == 32

    with pytest.raises(ValidationError):
        Settings(_env_file=None, app_env="test", jwt_secret="é" * 15)


def test_production_requires_secret() -> None:
    config = Settings(_env_file=None, app_env="production")

    with pytest.raises(SecurityConfigurationError) as exc_info:
        validate_security_configuration(config)

    assert "JWT_SECRET" in str(exc_info.value)
    assert "None" not in str(exc_info.value)


def test_staging_requires_secret() -> None:
    config = Settings(_env_file=None, app_env="staging")

    with pytest.raises(SecurityConfigurationError):
        validate_security_configuration(config)


def test_development_and_test_do_not_require_secret() -> None:
    for app_env in ("development", "test"):
        config = Settings(_env_file=None, app_env=app_env)
        validate_security_configuration(config)


def test_valid_production_configuration_passes() -> None:
    config = Settings(
        _env_file=None,
        app_env="production",
        jwt_secret=TEST_SECRET,
        email_backend="smtp",
        **DEPLOYMENT_SETTINGS,
    )

    validate_security_configuration(config)


def test_production_rejects_non_secure_refresh_cookie() -> None:
    config = Settings(
        _env_file=None,
        app_env="production",
        jwt_secret=TEST_SECRET,
        email_backend="smtp",
        auth_refresh_cookie_enabled=True,
        auth_cookie_secure=False,
        **DEPLOYMENT_SETTINGS,
    )

    with pytest.raises(SecurityConfigurationError) as exc_info:
        validate_security_configuration(config)

    assert "AUTH_COOKIE_SECURE" in str(exc_info.value)


def test_production_allows_non_secure_cookie_when_feature_disabled() -> None:
    config = Settings(
        _env_file=None,
        app_env="production",
        jwt_secret=TEST_SECRET,
        email_backend="smtp",
        auth_refresh_cookie_enabled=False,
        auth_cookie_secure=False,
        **DEPLOYMENT_SETTINGS,
    )

    validate_security_configuration(config)


@pytest.mark.parametrize("app_env", ["staging", "production"])
@pytest.mark.parametrize(
    ("omitted", "env_name"),
    [
        ("database_url", "DATABASE_URL"),
        ("smtp_host", "SMTP_HOST"),
        ("email_from", "EMAIL_FROM"),
        ("repository_allowed_roots", "REPOSITORY_ALLOWED_ROOTS"),
        ("repository_isolation", "REPOSITORY_ISOLATION"),
    ],
)
def test_deployed_environments_reject_development_defaults(
    app_env: str,
    omitted: str,
    env_name: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Environment variables count as explicit settings; keep the test hermetic.
    for variable in (
        "DATABASE_URL",
        "SMTP_HOST",
        "EMAIL_FROM",
        "REPOSITORY_ALLOWED_ROOTS",
        "REPOSITORY_ISOLATION",
    ):
        monkeypatch.delenv(variable, raising=False)
    values = {key: value for key, value in DEPLOYMENT_SETTINGS.items() if key != omitted}
    config = Settings(_env_file=None, app_env=app_env, jwt_secret=TEST_SECRET, **values)

    with pytest.raises(SecurityConfigurationError) as exc_info:
        validate_security_configuration(config)

    assert env_name in str(exc_info.value)
    assert TEST_SECRET not in str(exc_info.value)


def test_deployment_settings_from_environment_count_as_explicit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("JWT_SECRET", TEST_SECRET)
    monkeypatch.setenv("DATABASE_URL", "sqlite:////srv/ai-security-analyst/app.db")
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("EMAIL_FROM", "no-reply@example.com")
    monkeypatch.setenv("REPOSITORY_ALLOWED_ROOTS", '["/srv/repositories"]')
    monkeypatch.setenv("EVIDENCE_FINGERPRINT_KEY", "test-only-fingerprint-key-" + "f" * 32)
    monkeypatch.setenv("REPOSITORY_ISOLATION", "per_user")

    validate_security_configuration(Settings(_env_file=None))


def test_explicit_loopback_smtp_relay_is_allowed_in_production() -> None:
    config = Settings(
        _env_file=None,
        app_env="production",
        jwt_secret=TEST_SECRET,
        **{**DEPLOYMENT_SETTINGS, "smtp_host": "localhost"},
    )

    validate_security_configuration(config)


@pytest.mark.parametrize("sender", ["no-reply@localhost", "alerts@mail.localhost"])
def test_production_rejects_localhost_sender(sender: str) -> None:
    config = Settings(
        _env_file=None,
        app_env="production",
        jwt_secret=TEST_SECRET,
        **{**DEPLOYMENT_SETTINGS, "email_from": sender},
    )

    with pytest.raises(SecurityConfigurationError) as exc_info:
        validate_security_configuration(config)

    assert "EMAIL_FROM" in str(exc_info.value)


def test_production_rejects_relative_repository_roots() -> None:
    config = Settings(
        _env_file=None,
        app_env="production",
        jwt_secret=TEST_SECRET,
        **{**DEPLOYMENT_SETTINGS, "repository_allowed_roots": [Path("repositories")]},
    )

    with pytest.raises(SecurityConfigurationError) as exc_info:
        validate_security_configuration(config)

    assert "REPOSITORY_ALLOWED_ROOTS" in str(exc_info.value)


@pytest.mark.parametrize(
    ("app_env", "explicit", "expected"),
    [
        ("development", None, True),
        ("test", None, True),
        ("staging", None, True),
        ("production", None, False),
        ("production", True, True),
        ("development", False, False),
    ],
)
def test_api_docs_exposure_defaults_off_in_production(
    app_env: str,
    explicit: bool | None,
    expected: bool,
) -> None:
    config = Settings(_env_file=None, app_env=app_env, api_docs_enabled=explicit)

    assert api_docs_enabled(config) is expected


def test_console_email_backend_is_allowed_in_development_and_test() -> None:
    for app_env in ("development", "test"):
        config = Settings(_env_file=None, app_env=app_env, email_backend="console")
        validate_security_configuration(config)


def test_staging_rejects_console_email_backend() -> None:
    config = Settings(
        _env_file=None,
        app_env="staging",
        jwt_secret=TEST_SECRET,
        email_backend="console",
    )

    with pytest.raises(SecurityConfigurationError) as exc_info:
        validate_security_configuration(config)

    assert "EMAIL_BACKEND" in str(exc_info.value)


def test_production_rejects_console_email_backend() -> None:
    config = Settings(
        _env_file=None,
        app_env="production",
        jwt_secret=TEST_SECRET,
        email_backend="console",
    )

    with pytest.raises(SecurityConfigurationError) as exc_info:
        validate_security_configuration(config)

    assert "EMAIL_BACKEND" in str(exc_info.value)


def test_production_requires_smtp_tls() -> None:
    config = Settings(
        _env_file=None,
        app_env="production",
        jwt_secret=TEST_SECRET,
        email_backend="smtp",
        smtp_starttls=False,
        smtp_ssl=False,
    )

    with pytest.raises(SecurityConfigurationError):
        validate_security_configuration(config)


def test_production_requires_smtp_host() -> None:
    config = Settings(
        _env_file=None,
        app_env="production",
        jwt_secret=TEST_SECRET,
        email_backend="smtp",
        smtp_host=" ",
    )

    with pytest.raises(SecurityConfigurationError):
        validate_security_configuration(config)


def test_smtp_ssl_and_starttls_are_mutually_exclusive() -> None:
    config = Settings(
        _env_file=None,
        app_env="test",
        smtp_ssl=True,
        smtp_starttls=True,
    )

    with pytest.raises(SecurityConfigurationError):
        validate_security_configuration(config)


def test_smtp_username_requires_password() -> None:
    config = Settings(
        _env_file=None,
        app_env="test",
        smtp_username="user",
        smtp_password=None,
    )

    with pytest.raises(SecurityConfigurationError):
        validate_security_configuration(config)


def test_smtp_password_is_masked() -> None:
    config = Settings(
        _env_file=None,
        app_env="test",
        smtp_password="super-secret-smtp-password",
    )

    assert "super-secret-smtp-password" not in repr(config)
    assert "super-secret-smtp-password" not in str(config)


def test_invalid_email_from_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, app_env="test", email_from="not-an-address")

    with pytest.raises(ValidationError):
        Settings(_env_file=None, app_env="test", email_from="line\nbreak@example.com")


def test_import_compatibility_without_secret() -> None:
    import app.core.security
    import app.main

    assert app.main.app is not None
    assert app.core.security.MAX_PASSWORD_BYTES > 0


def test_token_creation_fails_clearly_without_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "jwt_secret", None)

    with pytest.raises(SecurityConfigurationError):
        create_access_token(user_id=uuid4(), session_id=uuid4())

    with pytest.raises(SecurityConfigurationError):
        decode_access_token("not-a-token")


def test_configured_secret_is_used_by_token_primitives(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "jwt_secret", SecretStr(TEST_SECRET))
    user_id = UUID("11111111-1111-4111-8111-111111111111")
    session_id = UUID("22222222-2222-4222-8222-222222222222")

    token = create_access_token(user_id=user_id, session_id=session_id)
    claims = decode_access_token(token)

    assert claims.sub == user_id
    assert claims.sid == session_id


def _import_app_in_subprocess(tmp_path: Path, extra_env: dict[str, str]):
    """Import ``app.main`` in a clean interpreter with only the given settings."""
    import os
    import subprocess
    import sys

    project_root = Path(__file__).resolve().parents[1]
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("APP_", "JWT_", "SMTP_", "EMAIL_", "DATABASE_", "REPOSITORY_"))
    }
    env.update(extra_env)
    env["PYTHONPATH"] = str(project_root)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    script = (
        "from app.main import app; "
        "print(app.docs_url, app.redoc_url, app.openapi_url, "
        "any(getattr(r, 'path', None) == '/docs' for r in app.routes))"
    )
    # Run from an empty directory so no developer .env file is read.
    return subprocess.run(
        [sys.executable, "-c", script],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def test_application_import_fails_closed_with_unsafe_production_config(tmp_path: Path) -> None:
    result = _import_app_in_subprocess(tmp_path, {"APP_ENV": "production"})

    assert result.returncode != 0
    assert "SecurityConfigurationError" in result.stderr
    assert "JWT_SECRET" in result.stderr


def test_production_application_does_not_expose_api_docs(tmp_path: Path) -> None:
    result = _import_app_in_subprocess(
        tmp_path,
        {
            "APP_ENV": "production",
            "JWT_SECRET": TEST_SECRET,
            "DATABASE_URL": f"sqlite:///{(tmp_path / 'app.db').as_posix()}",
            "SMTP_HOST": "smtp.example.com",
            "EMAIL_FROM": "no-reply@example.com",
            "REPOSITORY_ALLOWED_ROOTS": f'["{tmp_path.as_posix()}"]',
            "EVIDENCE_FINGERPRINT_KEY": "test-only-fingerprint-key-" + "f" * 32,
            "REPOSITORY_ISOLATION": "per_user",
        },
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.split() == ["None", "None", "None", "False"]
    assert TEST_SECRET not in result.stdout + result.stderr


@pytest.mark.parametrize("app_env", ["staging", "production"])
def test_deployed_environments_require_fingerprint_key(
    app_env: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("EVIDENCE_FINGERPRINT_KEY", raising=False)
    values = {k: v for k, v in DEPLOYMENT_SETTINGS.items() if k != "evidence_fingerprint_key"}
    config = Settings(_env_file=None, app_env=app_env, jwt_secret=TEST_SECRET, **values)

    with pytest.raises(SecurityConfigurationError) as exc_info:
        validate_security_configuration(config)

    assert "EVIDENCE_FINGERPRINT_KEY" in str(exc_info.value)


def test_short_fingerprint_key_is_rejected_without_disclosure() -> None:
    with pytest.raises(ValidationError) as exc_info:
        Settings(_env_file=None, app_env="test", evidence_fingerprint_key="too-short-key")
    assert "too-short-key" not in str(exc_info.value)


@pytest.mark.parametrize(
    "entry",
    [
        {"rule_id": "*", "path_glob": "docs/*.md", "reason": "documentation example"},
        {"rule_id": "secret.jwt", "path_glob": "**", "reason": "documentation example"},
        {"rule_id": "secret.jwt", "path_glob": "/etc/*", "reason": "documentation example"},
        {"rule_id": "secret.jwt", "path_glob": "docs/*.md", "reason": "short"},
    ],
)
def test_secret_allowlist_entries_must_be_narrow_and_justified(entry: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, app_env="test", secret_scan_allowlist=[entry])


@pytest.mark.parametrize(
    "rule",
    [
        {"rule_id": "secret.mine", "title": "Mine", "pattern": "abc"},
        {"rule_id": "custom.bad", "title": "Bad", "pattern": "(unclosed"},
        {"rule_id": "custom.empty", "title": "Empty", "pattern": "a*"},
        {"rule_id": "custom.groups", "title": "Groups", "pattern": "(a)(b)"},
    ],
)
def test_custom_secret_rules_are_validated(rule: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, app_env="test", secret_scan_custom_rules=[rule])


@pytest.mark.parametrize(
    "url",
    [
        "http://api.osv.dev",
        "https://user:pass@api.osv.dev",
        "https://api.osv.dev/?x=1",
        "ftp://api.osv.dev",
        "https://",
    ],
)
def test_advisory_url_must_be_plain_https(url: str) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, app_env="test", advisory_osv_base_url=url)


def test_advisory_url_is_normalized_and_mode_is_validated() -> None:
    config = Settings(_env_file=None, app_env="test", advisory_osv_base_url="https://osv.example/")
    assert config.advisory_osv_base_url == "https://osv.example"
    with pytest.raises(ValidationError):
        Settings(_env_file=None, app_env="test", dependency_audit_mode="sometimes")


def test_production_refuses_local_web_target_networks() -> None:
    config = Settings(
        _env_file=None,
        app_env="production",
        jwt_secret=TEST_SECRET,
        **{**DEPLOYMENT_SETTINGS, "web_target_allowed_local_networks": ["127.0.0.0/8"]},
    )
    with pytest.raises(SecurityConfigurationError) as exc_info:
        validate_security_configuration(config)
    assert "WEB_TARGET_ALLOWED_LOCAL_NETWORKS" in str(exc_info.value)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("web_target_allowed_hosts", ["https://dvwa.test"]),
        ("web_target_allowed_hosts", ["*.example.test"]),
        ("web_target_allowed_hosts", ["dvwa.test:8080"]),
        ("web_target_allowed_local_networks", ["not-a-network"]),
        ("web_target_allowed_local_networks", ["0.0.0.0/0"]),
    ],
)
def test_web_target_settings_are_validated(field: str, value: list[str]) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, app_env="test", **{field: value})


def test_web_target_hosts_are_normalized() -> None:
    config = Settings(
        _env_file=None, app_env="test", web_target_allowed_hosts=["DVWA.test.", "127.0.0.1"]
    )
    assert config.web_target_allowed_hosts == ["127.0.0.1", "dvwa.test"]
