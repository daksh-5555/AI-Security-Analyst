"""Pure security primitives for password hashing, JWTs, and opaque tokens.

This module deliberately has no SQLAlchemy, FastAPI, database-model, or email
dependencies. Persistence, request handling, and delivery belong to later
subphases.
"""

import hashlib
import hmac
import re
import secrets
import threading
from collections import OrderedDict
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid4

import jwt
from pwdlib import PasswordHash
from pwdlib.exceptions import UnknownHashError
from pwdlib.hashers.argon2 import Argon2Hasher

from app.core.config import (
    MIN_JWT_SECRET_BYTES,
    SecurityConfigurationError,
    settings,
)

MAX_PASSWORD_BYTES = 1024
MIN_PASSWORD_CHARS = 12
MAX_OPAQUE_TOKEN_LENGTH = 512
DUMMY_HASH_CACHE_MAX_ENTRIES = 8
_DUMMY_PASSWORD = "timing-equalization-dummy-password"
_MIN_OPAQUE_TOKEN_BYTES = 32
_MAX_OPAQUE_TOKEN_BYTES = 64
_OPAQUE_PREFIX_PATTERN = re.compile(r"[a-z][a-z0-9]{0,15}\Z")
_OPAQUE_TOKEN_PATTERN = re.compile(r"[a-z][a-z0-9]{0,15}_[A-Za-z0-9_-]+\Z")
_JWT_ALGORITHM = "HS256"
_REQUIRED_CLAIMS = ("sub", "sid", "iss", "aud", "iat", "exp", "jti", "typ")

_dummy_hash_cache: OrderedDict[tuple[int, int, int, int, int], str] = OrderedDict()
_dummy_hash_cache_lock = threading.Lock()


class InvalidAccessTokenError(ValueError):
    """Raised when an access token is missing, malformed, or invalid."""


@dataclass(frozen=True, slots=True)
class AccessTokenClaims:
    """Validated access-token claims. Roles are intentionally not represented."""

    sub: UUID
    sid: UUID
    iss: str
    aud: str
    iat: int
    exp: int
    jti: str
    typ: str


def _password_hasher() -> PasswordHash:
    return PasswordHash(
        (
            Argon2Hasher(
                time_cost=settings.argon2_time_cost,
                memory_cost=settings.argon2_memory_cost_kib,
                parallelism=settings.argon2_parallelism,
                hash_len=settings.argon2_hash_len,
                salt_len=settings.argon2_salt_len,
            ),
        )
    )


def _validate_password_input(password: str) -> None:
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    try:
        encoded = password.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("password must be valid UTF-8") from exc
    if len(encoded) > MAX_PASSWORD_BYTES:
        raise ValueError(f"password must not exceed {MAX_PASSWORD_BYTES} UTF-8 bytes")


def validate_password_size(password: str) -> None:
    """Enforce only the type and UTF-8 byte-size limits for a password.

    Authentication must reject oversized inputs without applying the
    registration policy, so callers that verify existing credentials use this
    narrower check.
    """
    _validate_password_input(password)


def _argon2_parameters() -> tuple[int, int, int, int, int]:
    return (
        settings.argon2_time_cost,
        settings.argon2_memory_cost_kib,
        settings.argon2_parallelism,
        settings.argon2_hash_len,
        settings.argon2_salt_len,
    )


def clear_dummy_password_hash_cache() -> None:
    """Clear the cached dummy hash. Intended for tests and parameter changes."""
    with _dummy_hash_cache_lock:
        _dummy_hash_cache.clear()


def dummy_password_hash() -> str:
    """Return a cached Argon2id hash used to equalize unknown-account logins.

    The cache key is the complete active Argon2 parameter set, and the cache is
    bounded so that configuration churn cannot grow it without limit. Only the
    hash is cached; no credential or identity data is stored.
    """
    key = _argon2_parameters()
    with _dummy_hash_cache_lock:
        cached = _dummy_hash_cache.get(key)
        if cached is not None:
            _dummy_hash_cache.move_to_end(key)
            return cached

        password_hash = _password_hasher().hash(_DUMMY_PASSWORD)
        _dummy_hash_cache[key] = password_hash
        if len(_dummy_hash_cache) > DUMMY_HASH_CACHE_MAX_ENTRIES:
            _dummy_hash_cache.popitem(last=False)
        return password_hash


def validate_password_policy(password: str) -> None:
    """Enforce the application password policy before hashing.

    Existing ``hash_password`` remains a sizing/type primitive so historical
    hashes and low-cost test fixtures are unaffected. New credentials must pass
    this policy at the identity service boundary.
    """
    _validate_password_input(password)
    if not password.strip():
        raise ValueError("password must not be blank")
    if len(password) < MIN_PASSWORD_CHARS:
        raise ValueError(f"password must contain at least {MIN_PASSWORD_CHARS} characters")


def hash_password(password: str) -> str:
    """Hash a password with Argon2id and a fresh random salt."""
    _validate_password_input(password)
    return _password_hasher().hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify an Argon2id password hash without leaking parse failures."""
    if not isinstance(password, str) or not isinstance(password_hash, str):
        return False
    try:
        _validate_password_input(password)
    except (TypeError, ValueError):
        return False
    if not password_hash.startswith("$argon2id$"):
        return False
    try:
        return _password_hasher().verify(password, password_hash)
    except (UnknownHashError, TypeError, ValueError):
        return False


def password_needs_rehash(password_hash: str) -> bool:
    """Report whether a stored hash should be replaced with current settings.

    Malformed or unsupported hashes report ``True`` so callers can replace them
    after a successful verification with an updated algorithm or cost.
    """
    if not isinstance(password_hash, str) or not password_hash.startswith("$argon2id$"):
        return True
    try:
        hasher = Argon2Hasher(
            time_cost=settings.argon2_time_cost,
            memory_cost=settings.argon2_memory_cost_kib,
            parallelism=settings.argon2_parallelism,
            hash_len=settings.argon2_hash_len,
            salt_len=settings.argon2_salt_len,
        )
        return hasher.check_needs_rehash(password_hash)
    except (TypeError, ValueError, UnknownHashError):
        return True


def _jwt_secret_bytes() -> bytes:
    secret = settings.jwt_secret
    if secret is None:
        raise SecurityConfigurationError(
            "JWT_SECRET is not configured; access tokens cannot be created or validated."
        )
    raw_secret = secret.get_secret_value().encode("utf-8")
    if not raw_secret.strip():
        raise SecurityConfigurationError("JWT_SECRET must not be blank.")
    if len(raw_secret) < MIN_JWT_SECRET_BYTES:
        raise SecurityConfigurationError(
            f"JWT_SECRET must contain at least {MIN_JWT_SECRET_BYTES} UTF-8 bytes."
        )
    return raw_secret


def _utc_now(now: datetime | None) -> datetime:
    if now is None:
        return datetime.now(UTC)
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    return now.astimezone(UTC)


def _require_int_claim(payload: dict[str, object], name: str) -> int:
    value = payload.get(name)
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidAccessTokenError(f"Invalid access token: {name} must be an integer.")
    return value


def create_access_token(
    *,
    user_id: UUID,
    session_id: UUID,
    now: datetime | None = None,
    ttl_seconds: int | None = None,
    jti: str | None = None,
) -> str:
    """Create a short-lived HS256 access token.

    The payload deliberately contains no authoritative role or permission
    claims. Authorization data must be loaded from the database by later layers.
    """
    if not isinstance(user_id, UUID):
        raise TypeError("user_id must be a UUID")
    if not isinstance(session_id, UUID):
        raise TypeError("session_id must be a UUID")

    issued_at = _utc_now(now)
    maximum_ttl = settings.access_token_ttl_seconds
    ttl = maximum_ttl if ttl_seconds is None else ttl_seconds
    if isinstance(ttl, bool) or not isinstance(ttl, int):
        raise TypeError("ttl_seconds must be an integer")
    if ttl <= 0 or ttl > maximum_ttl:
        raise ValueError(f"ttl_seconds must be between 1 and {maximum_ttl}")

    token_jti = str(uuid4()) if jti is None else jti
    if not isinstance(token_jti, str) or not token_jti:
        raise ValueError("jti must be a non-empty string")

    issued_at_timestamp = int(issued_at.timestamp())
    payload: dict[str, object] = {
        "sub": str(user_id),
        "sid": str(session_id),
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": issued_at_timestamp,
        "exp": issued_at_timestamp + ttl,
        "jti": token_jti,
        "typ": "access",
    }
    return jwt.encode(payload, _jwt_secret_bytes(), algorithm=_JWT_ALGORITHM)


def decode_access_token(token: str, *, now: datetime | None = None) -> AccessTokenClaims:
    """Validate a token signature, standard claims, and time bounds.

    Time validation is performed against an injectable ``now`` value so tests do
    not need to sleep. PyJWT still validates the signature, issuer, audience,
    subject type, and required-claim presence.
    """
    if not isinstance(token, str) or not token.strip():
        raise InvalidAccessTokenError("Invalid access token.")

    current = _utc_now(now)
    try:
        payload = jwt.decode(
            token,
            _jwt_secret_bytes(),
            algorithms=[_JWT_ALGORITHM],
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
            options={
                "require": list(_REQUIRED_CLAIMS),
                "verify_signature": True,
                "verify_exp": False,
                "verify_iat": False,
                "verify_nbf": False,
            },
        )
    except jwt.InvalidTokenError as exc:
        raise InvalidAccessTokenError("Invalid access token.") from exc

    issuer = payload.get("iss")
    audience = payload.get("aud")
    if not isinstance(issuer, str) or issuer != settings.jwt_issuer:
        raise InvalidAccessTokenError("Invalid access token: unexpected issuer.")
    if not isinstance(audience, str) or audience != settings.jwt_audience:
        raise InvalidAccessTokenError("Invalid access token: unexpected audience.")

    issued_at = _require_int_claim(payload, "iat")
    expires_at = _require_int_claim(payload, "exp")
    if expires_at <= issued_at:
        raise InvalidAccessTokenError("Invalid access token: invalid lifetime.")
    if expires_at - issued_at > settings.access_token_ttl_seconds:
        raise InvalidAccessTokenError(
            "Invalid access token: lifetime exceeds the configured maximum."
        )

    now_timestamp = current.timestamp()
    leeway = settings.jwt_clock_skew_seconds
    if issued_at > now_timestamp + leeway:
        raise InvalidAccessTokenError("Invalid access token: token issued in the future.")
    if expires_at + leeway < now_timestamp:
        raise InvalidAccessTokenError("Invalid access token: token expired.")

    token_type = payload.get("typ")
    if token_type != "access":
        raise InvalidAccessTokenError("Invalid access token: incorrect token type.")

    subject_value = payload.get("sub")
    session_value = payload.get("sid")
    try:
        subject = UUID(subject_value) if isinstance(subject_value, str) else None
        session = UUID(session_value) if isinstance(session_value, str) else None
    except (AttributeError, TypeError, ValueError) as exc:
        raise InvalidAccessTokenError("Invalid access token: malformed identifier.") from exc
    if subject is None or session is None:
        raise InvalidAccessTokenError("Invalid access token: malformed identifier.")

    jti = payload.get("jti")
    if not isinstance(jti, str) or not jti:
        raise InvalidAccessTokenError("Invalid access token: malformed token identifier.")

    return AccessTokenClaims(
        sub=subject,
        sid=session,
        iss=issuer,
        aud=audience,
        iat=issued_at,
        exp=expires_at,
        jti=jti,
        typ=token_type,
    )


def _validate_prefix(prefix: str) -> None:
    if not isinstance(prefix, str) or not _OPAQUE_PREFIX_PATTERN.fullmatch(prefix):
        raise ValueError(
            "prefix must start with a lowercase letter and contain only "
            "lowercase letters and digits (maximum 16 characters)"
        )


def _resolve_opaque_token_bytes(nbytes: int | None) -> int:
    resolved = settings.opaque_token_bytes if nbytes is None else nbytes
    if isinstance(resolved, bool) or not isinstance(resolved, int):
        raise TypeError("nbytes must be an integer")
    if resolved < _MIN_OPAQUE_TOKEN_BYTES or resolved > _MAX_OPAQUE_TOKEN_BYTES:
        raise ValueError(
            f"nbytes must be between {_MIN_OPAQUE_TOKEN_BYTES} and {_MAX_OPAQUE_TOKEN_BYTES}"
        )
    return resolved


def generate_opaque_token(prefix: str, *, nbytes: int | None = None) -> str:
    """Generate a prefixed cryptographically secure opaque token."""
    _validate_prefix(prefix)
    entropy_bytes = _resolve_opaque_token_bytes(nbytes)
    return f"{prefix}_{secrets.token_urlsafe(entropy_bytes)}"


def _validate_opaque_token(token: str) -> None:
    if not isinstance(token, str):
        raise TypeError("token must be a string")
    if not token or len(token) > MAX_OPAQUE_TOKEN_LENGTH:
        raise ValueError("token has an invalid length")
    try:
        token.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("token must contain only ASCII characters") from exc
    if not _OPAQUE_TOKEN_PATTERN.fullmatch(token):
        raise ValueError("token has an invalid format")


def hash_opaque_token(token: str) -> str:
    """Return the SHA-256 hex digest stored for a high-entropy opaque token."""
    _validate_opaque_token(token)
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def verify_opaque_token(token: str, expected_hash: str) -> bool:
    """Compare a presented opaque token with a stored SHA-256 hex digest."""
    if not isinstance(token, str) or not isinstance(expected_hash, str):
        return False
    if len(expected_hash) != 64:
        return False
    try:
        actual_hash = hash_opaque_token(token)
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(actual_hash, expected_hash.lower())
