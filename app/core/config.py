import os
import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

MIN_JWT_SECRET_BYTES = 32
MIN_FINGERPRINT_KEY_BYTES = 32
_RULE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.\-]{1,99}$")
_BROAD_GLOBS = frozenset({"*", "**", "**/*", "*/**", "./**", "**/**"})

# The automated test suite sets APP_ENV=test before any app module is imported
# (see tests/conftest.py). In that mode the local developer ``.env`` is ignored so
# the suite never depends on developer-specific values (e.g. a demo
# AUTH_COOKIE_SECURE=false); every other environment loads ``.env`` as usual.
_ENV_FILE: str | None = None if os.environ.get("APP_ENV") == "test" else ".env"


class SecretAllowlistEntry(BaseModel):
    """One narrow, justified suppression of a secret-scanner rule.

    Every suppression names exactly one rule and one path pattern and must state
    why. Suppressed matches are counted and reported in the run metadata, so an
    allowlist entry never makes a result look silently clean.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str
    path_glob: str = Field(min_length=1, max_length=300)
    reason: str = Field(min_length=10, max_length=500)

    @field_validator("rule_id")
    @classmethod
    def _rule(cls, value: str) -> str:
        if not _RULE_ID_PATTERN.fullmatch(value):
            raise ValueError("rule_id must name exactly one rule (no wildcards)")
        return value

    @field_validator("path_glob")
    @classmethod
    def _glob(cls, value: str) -> str:
        normalized = value.strip().replace("\\", "/")
        if normalized in _BROAD_GLOBS or normalized.startswith("/"):
            raise ValueError("path_glob must be a narrow repository-relative pattern")
        return normalized


class CustomSecretRule(BaseModel):
    """A project-specific secret pattern. The whole match, or group 1, is the secret."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str
    title: str = Field(min_length=3, max_length=120)
    pattern: str = Field(min_length=4, max_length=300)
    severity: Literal["critical", "high", "medium", "low"] = "high"

    @field_validator("rule_id")
    @classmethod
    def _rule(cls, value: str) -> str:
        if not value.startswith("custom.") or not _RULE_ID_PATTERN.fullmatch(value):
            raise ValueError("custom rule_id must start with 'custom.'")
        return value

    @field_validator("pattern")
    @classmethod
    def _pattern(cls, value: str) -> str:
        try:
            compiled = re.compile(value)
        except re.error as exc:
            raise ValueError("pattern must be a valid regular expression") from exc
        if compiled.groups > 1:
            raise ValueError("pattern may contain at most one capturing group")
        if compiled.match(""):
            raise ValueError("pattern must not match the empty string")
        return value


class SecurityConfigurationError(RuntimeError):
    """Raised when security configuration is missing or unsafe."""


class Settings(BaseSettings):
    """Application settings loaded from environment variables and `.env`."""

    model_config = SettingsConfigDict(
        env_file=_ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
        hide_input_in_errors=True,
    )

    @field_validator("jwt_secret")
    @classmethod
    def _validate_jwt_secret(cls, value: SecretStr | None) -> SecretStr | None:
        """Require configured secrets to contain at least 32 UTF-8 bytes."""
        if value is None:
            return None
        secret = value.get_secret_value()
        if not secret.strip():
            raise ValueError("JWT_SECRET must not be blank.")
        try:
            secret_bytes = secret.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("JWT_SECRET must be valid UTF-8.") from exc
        if len(secret_bytes) < MIN_JWT_SECRET_BYTES:
            raise ValueError(
                f"JWT_SECRET must contain at least {MIN_JWT_SECRET_BYTES} UTF-8 bytes."
            )
        return value

    @field_validator("evidence_fingerprint_key")
    @classmethod
    def _validate_fingerprint_key(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None:
            return None
        if len(value.get_secret_value().strip().encode("utf-8")) < MIN_FINGERPRINT_KEY_BYTES:
            raise ValueError(
                f"EVIDENCE_FINGERPRINT_KEY must contain at least {MIN_FINGERPRINT_KEY_BYTES} "
                "UTF-8 bytes."
            )
        return value

    @field_validator("advisory_osv_base_url")
    @classmethod
    def _validate_advisory_url(cls, value: str) -> str:
        from urllib.parse import urlsplit

        parts = urlsplit(value.strip())
        if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
            raise ValueError("ADVISORY_OSV_BASE_URL must be an https URL without credentials")
        if parts.query or parts.fragment:
            raise ValueError("ADVISORY_OSV_BASE_URL must not contain a query or fragment")
        return value.strip().rstrip("/")

    @field_validator("web_target_allowed_hosts")
    @classmethod
    def _validate_web_hosts(cls, value: list[str]) -> list[str]:
        hosts = []
        for raw in value:
            host = raw.strip().lower().rstrip(".")
            if not host or any(char in host for char in "/:@*?# ") and not host.startswith("["):
                raise ValueError("WEB_TARGET_ALLOWED_HOSTS entries must be bare hostnames")
            hosts.append(host.strip("[]"))
        return sorted(set(hosts))

    @field_validator("web_target_allowed_local_networks")
    @classmethod
    def _validate_local_networks(cls, value: list[str]) -> list[str]:
        import ipaddress

        networks = []
        for raw in value:
            try:
                network = ipaddress.ip_network(raw.strip(), strict=False)
            except ValueError as exc:
                raise ValueError("WEB_TARGET_ALLOWED_LOCAL_NETWORKS entries must be CIDRs") from exc
            if network.prefixlen < (8 if network.version == 4 else 32):
                raise ValueError("WEB_TARGET_ALLOWED_LOCAL_NETWORKS entries must be narrow")
            networks.append(str(network))
        return networks

    @field_validator("crawler_excluded_paths")
    @classmethod
    def _validate_excluded_paths(cls, value: list[str]) -> list[str]:
        for path in value:
            if not path.startswith("/") or any(ord(char) < 33 for char in path):
                raise ValueError("CRAWLER_EXCLUDED_PATHS entries must be paths starting with '/'")
        return value

    @field_validator("email_from")
    @classmethod
    def _validate_email_from(cls, value: str) -> str:
        candidate = value.strip()
        if not candidate or "\r" in candidate or "\n" in candidate:
            raise ValueError("EMAIL_FROM must be a single non-blank address.")
        if candidate.count("@") != 1:
            raise ValueError("EMAIL_FROM must contain exactly one '@'.")
        local, domain = candidate.split("@", 1)
        if not local or not domain or any(character.isspace() for character in candidate):
            raise ValueError("EMAIL_FROM must be a valid email address.")
        return candidate

    @model_validator(mode="after")
    def _validate_session_ttls(self) -> "Settings":
        """Keep access and refresh lifetimes bounded by the session lifetime."""
        if self.refresh_token_ttl_seconds > self.absolute_session_ttl_seconds:
            raise ValueError(
                "REFRESH_TOKEN_TTL_SECONDS must not exceed ABSOLUTE_SESSION_TTL_SECONDS."
            )
        if self.refresh_token_ttl_seconds < self.access_token_ttl_seconds:
            raise ValueError(
                "REFRESH_TOKEN_TTL_SECONDS must be greater than or equal to "
                "ACCESS_TOKEN_TTL_SECONDS."
            )
        return self

    @model_validator(mode="after")
    def _validate_analysis_execution_limits(self) -> "Settings":
        """Keep lease, deadline, and admission limits mutually consistent."""
        if self.analysis_heartbeat_interval_seconds >= self.analysis_execution_timeout_seconds:
            raise ValueError(
                "ANALYSIS_HEARTBEAT_INTERVAL_SECONDS must be less than "
                "ANALYSIS_EXECUTION_TIMEOUT_SECONDS."
            )
        if self.analysis_stale_after_seconds <= self.analysis_execution_timeout_seconds:
            raise ValueError(
                "ANALYSIS_STALE_AFTER_SECONDS must exceed ANALYSIS_EXECUTION_TIMEOUT_SECONDS."
            )
        minimum_stale_after = (
            self.analysis_execution_timeout_seconds + 2 * self.analysis_heartbeat_interval_seconds
        )
        if self.analysis_stale_after_seconds < minimum_stale_after:
            raise ValueError(
                "ANALYSIS_STALE_AFTER_SECONDS must be at least "
                "ANALYSIS_EXECUTION_TIMEOUT_SECONDS + "
                "2 * ANALYSIS_HEARTBEAT_INTERVAL_SECONDS."
            )
        if self.analysis_max_concurrent_jobs_per_user > self.analysis_max_concurrent_jobs:
            raise ValueError(
                "ANALYSIS_MAX_CONCURRENT_JOBS_PER_USER must not exceed "
                "ANALYSIS_MAX_CONCURRENT_JOBS."
            )
        if self.analysis_queue_wait_seconds >= self.analysis_execution_timeout_seconds:
            raise ValueError(
                "ANALYSIS_QUEUE_WAIT_SECONDS must be less than ANALYSIS_EXECUTION_TIMEOUT_SECONDS."
            )
        return self

    app_name: str = "AI Security Analyst"
    app_version: str = "0.1.0"
    database_url: str = "sqlite:///./ai_security_analyst.db"
    app_env: Literal["development", "test", "staging", "production"] = Field(
        description=(
            "Deployment environment used for security configuration validation. "
            "Required; there is no implicit default."
        ),
    )
    jwt_secret: SecretStr | None = Field(
        default=None,
        description="HMAC secret for access tokens. Required outside development and test.",
    )
    jwt_algorithm: Literal["HS256"] = Field(
        default="HS256",
        description="JWT signing algorithm. Only HS256 is currently supported.",
    )
    jwt_issuer: str = Field(
        default="ai-security-analyst",
        min_length=1,
        max_length=255,
        description="Expected JWT issuer claim.",
    )
    jwt_audience: str = Field(
        default="ai-security-analyst-api",
        min_length=1,
        max_length=255,
        description="Expected JWT audience claim.",
    )
    access_token_ttl_seconds: int = Field(
        default=600,
        ge=300,
        le=900,
        description="Maximum access-token lifetime in seconds (5 to 10 minutes).",
    )
    refresh_token_ttl_seconds: int = Field(
        default=14 * 24 * 60 * 60,
        ge=300,
        le=7_776_000,
        description="Refresh-token and idle-session lifetime in seconds (14 days).",
    )
    absolute_session_ttl_seconds: int = Field(
        default=30 * 24 * 60 * 60,
        ge=3_600,
        le=7_776_000,
        description="Maximum total session lifetime in seconds (30 days).",
    )
    jwt_clock_skew_seconds: int = Field(
        default=30,
        ge=0,
        le=120,
        description="Allowed clock skew when validating JWT time claims.",
    )
    opaque_token_bytes: int = Field(
        default=48,
        ge=32,
        le=64,
        description="Entropy in bytes for generated opaque tokens.",
    )
    argon2_time_cost: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Argon2id time cost for password hashing.",
    )
    argon2_memory_cost_kib: int = Field(
        default=65536,
        ge=8192,
        le=262144,
        description="Argon2id memory cost in kibibytes.",
    )
    argon2_parallelism: int = Field(
        default=4,
        ge=1,
        le=8,
        description="Argon2id parallelism for password hashing.",
    )
    argon2_hash_len: int = Field(
        default=32,
        ge=16,
        le=64,
        description="Argon2id output hash length in bytes.",
    )
    argon2_salt_len: int = Field(
        default=16,
        ge=8,
        le=32,
        description="Argon2id random salt length in bytes.",
    )
    email_backend: Literal["console", "smtp"] = Field(
        default="smtp",
        description=(
            "Outbound email backend. Console must be requested explicitly and is "
            "restricted to development/test."
        ),
    )
    email_from: str = Field(
        default="no-reply@localhost",
        description="Sender address used for verification and reset messages.",
    )
    smtp_host: str = Field(
        default="localhost",
        min_length=1,
        max_length=255,
        description="SMTP server hostname.",
    )
    smtp_port: int = Field(
        default=587,
        ge=1,
        le=65535,
        description="SMTP server port.",
    )
    smtp_username: str | None = Field(
        default=None,
        max_length=255,
        description="Optional SMTP authentication username.",
    )
    smtp_password: SecretStr | None = Field(
        default=None,
        description="Optional SMTP authentication password.",
    )
    smtp_starttls: bool = Field(
        default=True,
        description="Upgrade SMTP connections with STARTTLS.",
    )
    smtp_ssl: bool = Field(
        default=False,
        description="Use an implicit TLS SMTP connection (SMTP_SSL).",
    )
    smtp_timeout_seconds: int = Field(
        default=10,
        ge=1,
        le=60,
        description="SMTP network timeout in seconds.",
    )
    email_verification_token_ttl_seconds: int = Field(
        default=86400,
        ge=300,
        le=604800,
        description="Lifetime of an email verification token in seconds.",
    )
    password_reset_token_ttl_seconds: int = Field(
        default=3600,
        ge=300,
        le=86400,
        description="Lifetime of a password reset token in seconds.",
    )
    auth_rate_limit_window_seconds: int = Field(
        default=60,
        ge=1,
        le=3600,
        description="Window used by the process-local auth rate limiter.",
    )
    auth_rate_limit_max_requests: int = Field(
        default=10,
        ge=1,
        le=1000,
        description="Maximum auth requests per client and endpoint within the window.",
    )
    auth_token_request_cooldown_seconds: int = Field(
        default=60,
        ge=0,
        le=3600,
        description="Minimum interval between verification or reset token emails.",
    )
    auth_login_failure_max_attempts: int = Field(
        default=5,
        ge=1,
        le=100,
        description=(
            "Failed logins allowed for one account from one client address within the "
            "failure window before that account/address pair is throttled. Scoping by "
            "both values means a third party cannot lock a user out of their own address."
        ),
    )
    auth_login_failure_window_seconds: int = Field(
        default=900,
        ge=60,
        le=86400,
        description="Window for per-account failed-login throttling and alerting.",
    )
    auth_login_account_alert_threshold: int = Field(
        default=50,
        ge=1,
        le=100_000,
        description=(
            "Failed logins for one account from any address within the failure window "
            "that trigger a security warning log. Alert only: it never blocks, so it "
            "cannot be abused to lock an account out."
        ),
    )
    auth_refresh_cookie_enabled: bool = Field(
        default=True,
        description=(
            "Also deliver the rotated refresh token as an HttpOnly cookie on login and "
            "refresh, and accept it from that cookie on refresh and logout. Additive: "
            "the header-bearer flow and the body refresh token are unaffected. Lets a "
            "browser single-page app keep the access token in memory and never expose "
            "the refresh token to JavaScript."
        ),
    )
    auth_refresh_in_response_body: bool = Field(
        default=True,
        description=(
            "Keep returning the refresh token in the login and refresh JSON body. True "
            "preserves the existing API contract (and the test suite). A browser app "
            "that relies on the refresh cookie sets this false so the refresh token is "
            "never placed where JavaScript can read it."
        ),
    )
    auth_cookie_secure: bool = Field(
        default=True,
        description=(
            "Set the Secure attribute on the refresh and CSRF cookies. Required in "
            "staging and production. Only set false for a local same-origin http dev "
            "proxy, where the browser would otherwise refuse to return a Secure cookie."
        ),
    )
    auth_cookie_samesite: Literal["strict", "lax"] = Field(
        default="strict",
        description=(
            "SameSite attribute for the refresh and CSRF cookies. 'strict' is the safe "
            "default for a same-origin app; 'lax' only if a cross-site top-level flow "
            "must carry the cookie. 'none' is intentionally not permitted."
        ),
    )
    auth_cookie_domain: str | None = Field(
        default=None,
        description=(
            "Explicit Domain attribute for the refresh and CSRF cookies. Default (unset) "
            "scopes them to the exact response host, which is preferred."
        ),
    )
    auth_refresh_cookie_name: str = Field(
        default="aisa_refresh",
        min_length=1,
        max_length=64,
        description="Name of the HttpOnly refresh-token cookie.",
    )
    auth_csrf_cookie_name: str = Field(
        default="aisa_csrf",
        min_length=1,
        max_length=64,
        description=(
            "Name of the readable double-submit CSRF cookie that guards cookie-sourced "
            "refresh requests. The client echoes its value in the X-CSRF-Token header."
        ),
    )
    audit_unauthenticated_denials_per_client: int = Field(
        default=20,
        ge=1,
        le=10_000,
        description=(
            "Unauthenticated assessment-route denials recorded in the audit table per "
            "client address within the audit denial window. Further denials still "
            "return 401 but are not persisted. Process-local."
        ),
    )
    audit_unauthenticated_denials_global: int = Field(
        default=600,
        ge=1,
        le=1_000_000,
        description=(
            "Unauthenticated denials recorded across all clients within the audit "
            "denial window. Bounds audit-table writes from distributed floods."
        ),
    )
    audit_unauthenticated_denial_window_seconds: int = Field(
        default=60,
        ge=1,
        le=3600,
        description="Window used to bound unauthenticated denial audit writes.",
    )
    evidence_fingerprint_key: SecretStr | None = Field(
        default=None,
        description=(
            "HMAC key (at least 32 UTF-8 bytes) used to fingerprint sensitive evidence "
            "such as detected secrets. Required in staging and production. When unset "
            "in development/test, an ephemeral per-process key is used and "
            "fingerprints are not comparable across processes."
        ),
    )
    secret_scan_enabled: bool = Field(
        default=True,
        description="Run the repository secret scanner during analysis runs.",
    )
    secret_scan_max_file_size_bytes: int = Field(
        default=1024 * 1024,
        ge=1,
        le=16 * 1024 * 1024,
        description="Files larger than this are skipped (reported) by the secret scanner.",
    )
    secret_scan_max_total_bytes: int = Field(
        default=64 * 1024 * 1024,
        ge=1,
        le=1024 * 1024 * 1024,
        description="Total bytes the secret scanner reads in one run before stopping (partial).",
    )
    secret_scan_max_files: int = Field(
        default=5_000,
        ge=1,
        le=100_000,
        description="Files the secret scanner reads in one run before stopping (partial).",
    )
    secret_scan_max_matches: int = Field(
        default=1_000,
        ge=1,
        le=100_000,
        description="Matches recorded in one run before the scanner stops (partial).",
    )
    secret_scan_allowlist: list[SecretAllowlistEntry] = Field(
        default_factory=list,
        description=(
            "JSON array of {rule_id, path_glob, reason} suppressions. Each entry is "
            "narrow (one rule, one non-global path pattern) and suppressed matches are "
            "reported as counts."
        ),
    )
    secret_scan_custom_rules: list[CustomSecretRule] = Field(
        default_factory=list,
        description="JSON array of project-specific {rule_id, title, pattern, severity} rules.",
    )
    dependency_audit_mode: Literal["online", "offline", "disabled"] = Field(
        default="online",
        description=(
            "Dependency advisory lookup. 'online' queries the advisory provider through "
            "the guarded client; 'offline' uses only the local cache and reports "
            "uncached packages as unchecked; 'disabled' skips the tool (reported)."
        ),
    )
    advisory_osv_base_url: str = Field(
        default="https://api.osv.dev",
        description="OSV API base URL. Must be https; its host is the only egress allowed.",
    )
    advisory_cache_dir: Path | None = Field(
        default=None,
        description=(
            "Directory for the advisory response cache. Unset keeps the cache in "
            "process memory only."
        ),
    )
    advisory_cache_ttl_seconds: int = Field(
        default=86_400,
        ge=60,
        le=30 * 86_400,
        description="Advisory cache freshness. Older entries are used only if labelled stale.",
    )
    advisory_max_packages: int = Field(
        default=2_000,
        ge=1,
        le=50_000,
        description="Resolved packages checked per run; the rest are reported as unchecked.",
    )
    advisory_request_timeout_seconds: int = Field(
        default=20,
        ge=1,
        le=120,
        description="Total time budget for one advisory request, including redirects.",
    )
    dependency_manifest_max_size_bytes: int = Field(
        default=10 * 1024 * 1024,
        ge=1024,
        le=64 * 1024 * 1024,
        description="Largest manifest or lock file parsed by the dependency inventory.",
    )
    repository_isolation: Literal["shared", "per_user"] = Field(
        default="shared",
        description=(
            "'per_user' confines each assessment owner's repository targets to "
            "<allowed root>/<owner user id>/, so users cannot register or analyse each "
            "other's repositories. 'shared' lets every analyst use the whole allowed "
            "root (single-team deployments only). Must be set explicitly in staging "
            "and production."
        ),
    )
    web_target_allowed_hosts: list[str] = Field(
        default_factory=list,
        description=(
            "Exact hostnames (or IP literals) that may be registered as web assessment "
            "targets. Empty means no web target can be registered."
        ),
    )
    web_target_allowed_local_networks: list[str] = Field(
        default_factory=list,
        description=(
            "CIDR ranges of local test networks (for example 127.0.0.0/8 for a DVWA lab) "
            "that authorized web targets may resolve to. Refused in staging/production."
        ),
    )
    crawler_max_depth: int = Field(
        default=3, ge=0, le=10, description="Link depth followed from the target base URL."
    )
    crawler_max_pages: int = Field(
        default=50, ge=1, le=500, description="Pages fetched per crawl before stopping (partial)."
    )
    crawler_max_requests: int = Field(
        default=150,
        ge=1,
        le=2_000,
        description="HTTP requests per crawl, including redirects and robots.txt.",
    )
    crawler_max_variants_per_path: int = Field(
        default=3,
        ge=1,
        le=50,
        description="Distinct query-value variants fetched per path and parameter-name set.",
    )
    crawler_respect_robots: bool = Field(
        default=True,
        description=(
            "Honour robots.txt disallow rules. This is courtesy, not authorization: "
            "targets must still be explicitly authorized."
        ),
    )
    crawler_excluded_paths: list[str] = Field(
        default_factory=list,
        description="Path prefixes (starting with '/') that the crawler never requests.",
    )
    web_target_max_requests_per_second: float = Field(
        default=2.0,
        ge=0.1,
        le=50.0,
        description="Request rate per web target for the crawler and runtime probes.",
    )
    runtime_probes_enabled: bool = Field(
        default=False,
        description=(
            "Run bounded, non-destructive XSS and SQL injection probes against GET "
            "parameters of authorized web targets. Off by default; when off the tool is "
            "reported as skipped (disabled)."
        ),
    )
    runtime_probe_max_parameters: int = Field(
        default=10,
        ge=1,
        le=200,
        description="Parameters probed per run; the rest are reported as not tested.",
    )
    runtime_probe_max_requests: int = Field(
        default=200,
        ge=1,
        le=5_000,
        description="Probe requests per run before stopping (partial).",
    )
    api_docs_enabled: bool | None = Field(
        default=None,
        description=(
            "Expose /docs, /redoc, and /openapi.json. Unset means enabled outside "
            "production and disabled in production."
        ),
    )
    repository_allowed_roots: list[Path] = Field(
        default_factory=lambda: [Path("repositories")],
        description="Filesystem roots under which repository targets may be registered.",
    )
    repository_max_file_count: int = Field(
        default=10_000,
        ge=0,
        description="Maximum number of regular files included in a discovery inventory.",
    )
    repository_max_depth: int = Field(
        default=50,
        ge=0,
        description="Maximum directory depth traversed below a repository root.",
    )
    repository_max_total_size_bytes: int = Field(
        default=512 * 1024 * 1024,
        ge=0,
        description="Maximum combined size of files included in a discovery inventory.",
    )
    technology_manifest_max_size_bytes: int = Field(
        default=1024 * 1024,
        ge=0,
        description="Maximum size of a single manifest read during technology detection.",
    )
    technology_max_manifest_files: int = Field(
        default=100,
        ge=0,
        description="Maximum number of manifests inspected during one technology detection run.",
    )
    attack_surface_source_max_size_bytes: int = Field(
        default=1024 * 1024,
        ge=0,
        description="Maximum size of a single source file read during attack surface analysis.",
    )
    attack_surface_max_source_files: int = Field(
        default=2_000,
        ge=0,
        description="Maximum number of source files inspected during one attack surface run.",
    )
    auth_control_source_max_size_bytes: int = Field(
        default=1024 * 1024,
        ge=0,
        description=(
            "Maximum size of a single source file read during authentication control analysis."
        ),
    )
    auth_control_max_source_files: int = Field(
        default=2_000,
        ge=0,
        description=(
            "Maximum number of source files inspected during one authentication control run."
        ),
    )
    input_source_max_size_bytes: int = Field(
        default=1024 * 1024,
        ge=0,
        description="Maximum size of a single source file read during input extraction.",
    )
    input_source_max_source_files: int = Field(
        default=2_000,
        ge=0,
        description="Maximum number of source files inspected during one input extraction run.",
    )
    sensitive_operation_source_max_size_bytes: int = Field(
        default=1024 * 1024,
        ge=0,
        description=(
            "Maximum size of a single source file read during sensitive operation analysis."
        ),
    )
    sensitive_operation_max_source_files: int = Field(
        default=2_000,
        ge=0,
        description=(
            "Maximum number of source files inspected during one sensitive operation run."
        ),
    )
    handler_call_source_max_size_bytes: int = Field(
        default=1024 * 1024,
        ge=0,
        description=(
            "Maximum size of a single source file read during handler and local call analysis."
        ),
    )
    handler_call_max_source_files: int = Field(
        default=2_000,
        ge=0,
        description=(
            "Maximum number of source files inspected during one handler and local call run."
        ),
    )
    input_operation_source_max_size_bytes: int = Field(
        default=1024 * 1024,
        ge=0,
        description=(
            "Maximum size of a single source file read during input-to-operation flow analysis."
        ),
    )
    input_operation_max_source_files: int = Field(
        default=2_000,
        ge=0,
        description=(
            "Maximum number of referenced source files inspected during one flow analysis run."
        ),
    )
    input_operation_max_propagation_depth: int = Field(
        default=12,
        ge=0,
        description=(
            "Maximum interprocedural call depth traversed while propagating an input value."
        ),
    )
    input_operation_max_propagation_states: int = Field(
        default=5_000,
        ge=0,
        description=("Maximum number of distinct function and parameter-taint states analyzed."),
    )
    input_operation_max_relationships: int = Field(
        default=10_000,
        ge=0,
        description=("Maximum number of input-to-operation relationships emitted in one run."),
    )
    analysis_execution_timeout_seconds: int = Field(
        default=300,
        ge=1,
        le=3600,
        description=(
            "Cooperative execution deadline for one analysis run, measured from the "
            "committed RUNNING state. Checked at pipeline stage boundaries and during "
            "repository traversal; a single long stage can exceed it."
        ),
    )
    analysis_heartbeat_interval_seconds: int = Field(
        default=15,
        ge=1,
        le=300,
        description=(
            "Interval at which a running analysis renews its heartbeat_at lease "
            "from a dedicated thread."
        ),
    )
    analysis_stale_after_seconds: int = Field(
        default=420,
        ge=5,
        le=86400,
        description=(
            "Lease length and heartbeat age after which a RUNNING run is stale. "
            "The worker's recovery sweep requeues a stale worker run while retry "
            "attempts remain and otherwise marks it failed (error code "
            "lease_expired); a stale synchronous run is marked failed."
        ),
    )
    analysis_max_concurrent_jobs: int = Field(
        default=2,
        ge=1,
        le=32,
        description=(
            "Maximum concurrent expensive analysis pipelines per process. "
            "Enforced by the process-local analysis admission controller; this is "
            "not a deployment-wide limit."
        ),
    )
    analysis_max_concurrent_jobs_per_user: int = Field(
        default=1,
        ge=1,
        le=8,
        description=(
            "Maximum concurrent analysis runs per authenticated user per process. "
            "Applies only to analysis-run creation; summary requests never consume "
            "this quota."
        ),
    )
    analysis_queue_wait_seconds: int = Field(
        default=2,
        ge=0,
        le=30,
        description=(
            "Maximum time a synchronous analysis request blocks a worker thread "
            "waiting for global capacity. The wait is excluded from the execution "
            "deadline, so worst-case request duration is approximately this value "
            "plus ANALYSIS_EXECUTION_TIMEOUT_SECONDS."
        ),
    )
    analysis_rate_limit_max_requests: int = Field(
        default=10,
        ge=1,
        le=1000,
        description=(
            "Maximum analysis requests per authenticated user and scope within the "
            "analysis rate-limit window. Process-local and independent from the "
            "authentication rate limiter."
        ),
    )
    analysis_rate_limit_window_seconds: int = Field(
        default=60,
        ge=1,
        le=3600,
        description=("Sliding window used by the process-local per-user analysis rate limiter."),
    )
    analysis_async_enabled: bool = Field(
        default=False,
        description=(
            "Allow POST .../analysis-runs?mode=async, which queues the run for the "
            "background worker (python -m app.worker) and returns 202. Off by default "
            "because queued runs only progress while a worker is running."
        ),
    )
    analysis_worker_max_attempts: int = Field(
        default=3,
        ge=1,
        le=10,
        description=(
            "Maximum claims of one queued run. Lease expiry and transient database "
            "errors requeue the run until this is reached; then it is marked failed."
        ),
    )
    analysis_worker_max_running: int = Field(
        default=2,
        ge=1,
        le=64,
        description=(
            "Deployment-wide cap on worker-claimed RUNNING runs, checked atomically in "
            "the claim (exact on SQLite and PostgreSQL; ADR-0011, ADR-0016)."
        ),
    )
    analysis_worker_poll_interval_seconds: float = Field(
        default=2.0,
        gt=0,
        le=60,
        description="Idle sleep between worker queue polls.",
    )
    # --- Bounded assessment workflows (M10, ADR-0013) ---------------------------
    workflow_max_steps: int = Field(
        default=20,
        ge=8,
        le=100,
        description="Maximum node executions per workflow, retries included.",
    )
    workflow_max_node_attempts: int = Field(
        default=2,
        ge=1,
        le=5,
        description="Maximum attempts of one workflow node before the workflow fails.",
    )
    workflow_engine: Literal["builtin", "langgraph"] = Field(
        default="builtin",
        description=(
            "Orchestration engine for assessment workflows. 'builtin' loops in process; "
            "'langgraph' drives the same bounded, allowlisted nodes through a LangGraph "
            "StateGraph (needs the optional [orchestration] extra). Both enforce the same "
            "approval gates, budgets, and security checks."
        ),
    )
    workflow_max_explanations: int = Field(
        default=5,
        ge=0,
        le=50,
        description="Maximum findings the explain_findings node sends to the LLM per workflow.",
    )
    # --- Reports (M12, ADR-0015) -------------------------------------------------
    report_max_findings: int = Field(
        default=500,
        ge=1,
        le=5000,
        description="Findings included in one report; the rest are counted as omitted.",
    )
    report_max_evidence_per_finding: int = Field(
        default=10, ge=1, le=50, description="Evidence items shown per finding."
    )
    report_max_bytes: int = Field(
        default=5_000_000,
        ge=100_000,
        le=50_000_000,
        description="Reports larger than this are refused (413) instead of being sent.",
    )
    # --- Curated knowledge retrieval (M11, ADR-0014) ----------------------------
    rag_enabled: bool = Field(
        default=True,
        description=(
            "Ground LLM explanations in the curated, local knowledge base. Local only; "
            "has no effect on scanning or finding status."
        ),
    )
    rag_backend: Literal["lexical", "vector"] = Field(
        default="lexical",
        description=(
            "lexical: BM25. vector: cosine over local hashing embeddings, falling back "
            "to lexical if embeddings are unavailable."
        ),
    )
    rag_max_chunks: int = Field(default=4, ge=1, le=10, description="Chunks retrieved per query.")
    rag_max_chunk_chars: int = Field(
        default=900, ge=200, le=4000, description="Upper bound on one chunk's text."
    )
    rag_include_stale: bool = Field(
        default=False,
        description="Include documents past their review interval (labelled stale).",
    )
    rag_corpus_dir: Path | None = Field(
        default=None,
        description=(
            "Optional operator corpus directory (manifest.json plus Markdown) with "
            "licensed, reviewed sources. Loaded in addition to the built-in guidance."
        ),
    )
    # --- Authenticated local lab targets (M15, ADR-0018) ------------------------
    web_auth_lab_enabled: bool = Field(
        default=False,
        description=(
            "Allow establishing an authenticated session against an authorized LOCAL "
            "web lab (e.g. DVWA on loopback) with operator-supplied known credentials. "
            "Off by default and forbidden in staging/production; lab use only. Never "
            "performs credential guessing."
        ),
    )
    web_auth_lab_login_path: str = Field(
        default="/login.php",
        min_length=1,
        max_length=300,
        description="Path of the lab login form (DVWA default).",
    )
    web_auth_lab_csrf_field: str = Field(
        default="user_token",
        max_length=100,
        description="Hidden anti-CSRF field read from the login page; empty disables it.",
    )
    web_auth_lab_username_field: str = Field(
        default="username", min_length=1, max_length=100, description="Login form username field."
    )
    web_auth_lab_password_field: str = Field(
        default="password", min_length=1, max_length=100, description="Login form password field."
    )
    web_auth_lab_extra_fields: dict[str, str] = Field(
        default_factory=lambda: {"Login": "Login"},
        description="Fixed extra form fields posted with the login (DVWA submit button).",
    )

    @field_validator("web_auth_lab_login_path")
    @classmethod
    def _validate_lab_login_path(cls, value: str) -> str:
        if not value.startswith("/"):
            raise ValueError("WEB_AUTH_LAB_LOGIN_PATH must start with '/'")
        return value

    # --- Optional LLM explanations (M9, ADR-0012) ------------------------------
    llm_explanations_enabled: bool = Field(
        default=False,
        description=(
            "Allow advisory LLM explanations of existing findings. Off by default; the "
            "deterministic pipeline never depends on it."
        ),
    )
    llm_provider: Literal["anthropic", "deepseek"] = Field(
        default="anthropic",
        description=(
            "Explanation provider adapter (needs the optional [ai] extra). 'anthropic' "
            "calls Anthropic's API with native structured output; 'deepseek' reuses the "
            "same SDK against DeepSeek's Anthropic-compatible endpoint (set LLM_BASE_URL "
            "and LLM_MODEL=deepseek-flash)."
        ),
    )
    llm_model: str = Field(
        default="claude-opus-5-5",
        min_length=1,
        max_length=100,
        description=(
            "Provider model identifier used for explanations. Use 'deepseek-flash' when "
            "LLM_PROVIDER=deepseek."
        ),
    )
    llm_base_url: str | None = Field(
        default=None,
        max_length=2000,
        description=(
            "Base URL for the provider API. Leave unset for Anthropic (the SDK default). "
            "Required for DeepSeek: 'https://api.deepseek.com/anthropic' (its "
            "Anthropic-compatible endpoint). Never derived from analysed content."
        ),
    )
    llm_api_key: SecretStr | None = Field(
        default=None,
        description="Provider API key. Secret; never logged, stored, or sent anywhere else.",
    )
    llm_effort: Literal["low", "medium", "high"] = Field(
        default="medium",
        description="Provider reasoning effort for explanations.",
    )
    llm_refusal_fallback: bool = Field(
        default=True,
        description=(
            "Let the provider retry a declined request on its default fallback model "
            "(Anthropic server-side fallbacks)."
        ),
    )
    llm_timeout_seconds: float = Field(
        default=60.0,
        gt=0,
        le=600,
        description="Per-attempt provider timeout. Wall clock can reach timeout x (retries + 1).",
    )
    llm_max_retries: int = Field(
        default=2,
        ge=0,
        le=5,
        description="Provider retries for timeouts, rate limits, and server errors.",
    )
    llm_max_output_tokens: int = Field(
        default=16000,
        ge=256,
        le=64000,
        description="Per-finding output token ceiling (max_tokens).",
    )
    llm_max_prompt_chars: int = Field(
        default=24000,
        ge=2000,
        le=200000,
        description="Upper bound on the redacted evidence sent for one finding.",
    )
    llm_max_evidence_items: int = Field(
        default=10,
        ge=1,
        le=50,
        description="Maximum evidence items sent for one finding (newest first are dropped).",
    )
    llm_max_response_chars: int = Field(
        default=40000,
        ge=1000,
        le=400000,
        description="Responses longer than this are rejected as malformed.",
    )
    llm_assessment_token_budget: int = Field(
        default=500000,
        ge=1000,
        le=50_000_000,
        description=(
            "Total provider tokens (input + output) all explanations of one assessment "
            "may consume; further requests are refused."
        ),
    )


settings = Settings()


def validate_security_configuration(config: Settings | None = None) -> None:
    """Reject missing or weak security configuration in staging and production.

    Development and test remain importable without a JWT secret so that
    configuration-only commands and the existing test suite do not require
    provisioning secrets. Token creation and validation still fail clearly when
    no secret is configured.
    """
    target = settings if config is None else config
    if target.smtp_ssl and target.smtp_starttls:
        raise SecurityConfigurationError("SMTP_SSL and SMTP_STARTTLS cannot both be enabled.")
    if target.smtp_username and target.smtp_password is None:
        raise SecurityConfigurationError(
            "SMTP_PASSWORD is required when SMTP_USERNAME is configured."
        )
    if target.workflow_engine == "langgraph":
        import importlib.util

        if importlib.util.find_spec("langgraph") is None:
            raise SecurityConfigurationError(
                "WORKFLOW_ENGINE=langgraph requires the optional [orchestration] extra "
                '(pip install ".[orchestration]").'
            )
    if target.app_env not in {"staging", "production"}:
        return
    if target.jwt_secret is None:
        raise SecurityConfigurationError(
            "JWT_SECRET must be configured when APP_ENV is staging or production."
        )
    secret = target.jwt_secret.get_secret_value()
    if not secret.strip():
        raise SecurityConfigurationError(
            "JWT_SECRET must not be blank when APP_ENV is staging or production."
        )
    try:
        secret_bytes = secret.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise SecurityConfigurationError("JWT_SECRET must be valid UTF-8.") from exc
    if len(secret_bytes) < MIN_JWT_SECRET_BYTES:
        raise SecurityConfigurationError(
            f"JWT_SECRET must contain at least {MIN_JWT_SECRET_BYTES} UTF-8 bytes "
            "when APP_ENV is staging or production."
        )
    if target.email_backend == "console":
        raise SecurityConfigurationError(
            "EMAIL_BACKEND=console is not permitted when APP_ENV is staging or production."
        )
    if not (target.smtp_ssl or target.smtp_starttls):
        raise SecurityConfigurationError(
            "SMTP_SSL or SMTP_STARTTLS must be enabled when APP_ENV is staging or production."
        )
    if not target.smtp_host.strip():
        raise SecurityConfigurationError(
            "SMTP_HOST must not be blank when APP_ENV is staging or production."
        )
    _validate_explicit_deployment_settings(target)


_DEPLOYMENT_REQUIRED_SETTINGS: tuple[tuple[str, str], ...] = (
    ("database_url", "DATABASE_URL"),
    ("repository_isolation", "REPOSITORY_ISOLATION"),
    ("smtp_host", "SMTP_HOST"),
    ("email_from", "EMAIL_FROM"),
    ("repository_allowed_roots", "REPOSITORY_ALLOWED_ROOTS"),
)


def _validate_explicit_deployment_settings(target: Settings) -> None:
    """Refuse development defaults in staging and production.

    The defaults (a relative SQLite file, a localhost SMTP server and sender, and
    a relative repository root resolved from the working directory) are only
    meaningful on a developer machine. Deployed environments must state each of
    them explicitly. A loopback SMTP host is still accepted when it is set
    explicitly, because a local mail relay is a legitimate deployment.
    """
    missing = [
        env_name
        for field_name, env_name in _DEPLOYMENT_REQUIRED_SETTINGS
        if field_name not in target.model_fields_set
    ]
    if missing:
        raise SecurityConfigurationError(
            "These settings must be set explicitly when APP_ENV is staging or production: "
            + ", ".join(missing)
            + "."
        )
    sender_domain = target.email_from.rsplit("@", 1)[-1].strip().lower()
    if sender_domain == "localhost" or sender_domain.endswith(".localhost"):
        raise SecurityConfigurationError(
            "EMAIL_FROM must use a deliverable domain when APP_ENV is staging or production."
        )
    if target.web_target_allowed_local_networks:
        raise SecurityConfigurationError(
            "WEB_TARGET_ALLOWED_LOCAL_NETWORKS must be empty when APP_ENV is staging or "
            "production; local test networks are for development labs only."
        )
    if target.web_auth_lab_enabled:
        raise SecurityConfigurationError(
            "WEB_AUTH_LAB_ENABLED must be false when APP_ENV is staging or production; "
            "authenticated lab targets are for development labs only."
        )
    if target.auth_refresh_cookie_enabled and not target.auth_cookie_secure:
        raise SecurityConfigurationError(
            "AUTH_COOKIE_SECURE must be true when AUTH_REFRESH_COOKIE_ENABLED is true in "
            "staging or production; a non-Secure refresh cookie is only for local dev."
        )
    if target.llm_explanations_enabled and target.llm_api_key is None:
        raise SecurityConfigurationError(
            "LLM_API_KEY must be configured when LLM_EXPLANATIONS_ENABLED is true in "
            "staging or production."
        )
    if (
        target.llm_explanations_enabled
        and target.llm_provider == "deepseek"
        and not (target.llm_base_url or "").strip()
    ):
        raise SecurityConfigurationError(
            "LLM_BASE_URL must be configured when LLM_PROVIDER=deepseek and "
            "LLM_EXPLANATIONS_ENABLED is true in staging or production."
        )
    if target.evidence_fingerprint_key is None:
        raise SecurityConfigurationError(
            "EVIDENCE_FINGERPRINT_KEY must be configured when APP_ENV is staging or production."
        )
    if not target.repository_allowed_roots or not all(
        root.expanduser().is_absolute() for root in target.repository_allowed_roots
    ):
        raise SecurityConfigurationError(
            "REPOSITORY_ALLOWED_ROOTS must contain only absolute paths when APP_ENV is "
            "staging or production."
        )


def api_docs_enabled(config: Settings | None = None) -> bool:
    """Return whether interactive API documentation should be exposed."""
    target = settings if config is None else config
    if target.api_docs_enabled is not None:
        return target.api_docs_enabled
    return target.app_env != "production"
