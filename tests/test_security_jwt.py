import base64
import json
from datetime import UTC, datetime, timedelta
from uuid import UUID

import jwt
import pytest
from pydantic import SecretStr

from app.core.config import settings
from app.core.security import (
    AccessTokenClaims,
    InvalidAccessTokenError,
    create_access_token,
    decode_access_token,
)

TEST_SECRET = "test-only-jwt-secret-" + "x" * 40
OTHER_SECRET = "other-test-jwt-secret-" + "y" * 40
USER_ID = UUID("11111111-1111-4111-8111-111111111111")
SESSION_ID = UUID("22222222-2222-4222-8222-222222222222")
JWT_ID = "33333333-3333-4333-8333-333333333333"
BASE_TIME = datetime(2030, 1, 1, tzinfo=UTC)
ISSUER = "test-issuer"
AUDIENCE = "test-audience"
TTL = 600
LEEWAY = 30


@pytest.fixture(autouse=True)
def configure_jwt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "jwt_secret", SecretStr(TEST_SECRET))
    monkeypatch.setattr(settings, "jwt_issuer", ISSUER)
    monkeypatch.setattr(settings, "jwt_audience", AUDIENCE)
    monkeypatch.setattr(settings, "access_token_ttl_seconds", TTL)
    monkeypatch.setattr(settings, "jwt_clock_skew_seconds", LEEWAY)


def _payload(**overrides: object) -> dict[str, object]:
    issued_at = int(BASE_TIME.timestamp())
    payload: dict[str, object] = {
        "sub": str(USER_ID),
        "sid": str(SESSION_ID),
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": issued_at,
        "exp": issued_at + TTL,
        "jti": JWT_ID,
        "typ": "access",
    }
    payload.update(overrides)
    return payload


def _encode(payload: dict[str, object], secret: str = TEST_SECRET) -> str:
    return jwt.encode(payload, secret, algorithm="HS256")


def _base64_json(value: dict[str, object]) -> str:
    encoded = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(encoded).rstrip(b"=").decode("ascii")


def _manual_token(header: dict[str, object], payload: dict[str, object], signature: str) -> str:
    return f"{_base64_json(header)}.{_base64_json(payload)}.{signature}"


def _created_token(**kwargs: object) -> str:
    return create_access_token(
        user_id=USER_ID,
        session_id=SESSION_ID,
        now=BASE_TIME,
        jti=JWT_ID,
        **kwargs,
    )


def test_valid_token_contains_required_claims() -> None:
    token = _created_token()
    payload = jwt.decode(
        token,
        TEST_SECRET,
        algorithms=["HS256"],
        audience=AUDIENCE,
        issuer=ISSUER,
        options={"verify_exp": False, "verify_iat": False},
    )

    assert payload["sub"] == str(USER_ID)
    assert payload["sid"] == str(SESSION_ID)
    assert payload["iss"] == ISSUER
    assert payload["aud"] == AUDIENCE
    assert payload["iat"] == int(BASE_TIME.timestamp())
    assert payload["exp"] == int(BASE_TIME.timestamp()) + TTL
    assert payload["jti"] == JWT_ID
    assert payload["typ"] == "access"


def test_decode_returns_validated_claims() -> None:
    claims = decode_access_token(_created_token(), now=BASE_TIME)

    assert isinstance(claims, AccessTokenClaims)
    assert claims.sub == USER_ID
    assert claims.sid == SESSION_ID
    assert claims.iss == ISSUER
    assert claims.aud == AUDIENCE
    assert claims.iat == int(BASE_TIME.timestamp())
    assert claims.exp == int(BASE_TIME.timestamp()) + TTL
    assert claims.jti == JWT_ID
    assert claims.typ == "access"


def test_invalid_signature_is_rejected() -> None:
    token = _created_token()
    replacement = "A" if token[-1] != "A" else "B"
    tampered = token[:-1] + replacement

    with pytest.raises(InvalidAccessTokenError):
        decode_access_token(tampered, now=BASE_TIME)


def test_different_secret_is_rejected() -> None:
    token = _encode(_payload(), secret=OTHER_SECRET)

    with pytest.raises(InvalidAccessTokenError):
        decode_access_token(token, now=BASE_TIME)


def test_expired_token_is_rejected() -> None:
    token = _created_token()

    with pytest.raises(InvalidAccessTokenError):
        decode_access_token(token, now=BASE_TIME + timedelta(seconds=TTL + LEEWAY + 1))


def test_expiry_within_clock_skew_is_accepted() -> None:
    token = _created_token()

    claims = decode_access_token(token, now=BASE_TIME + timedelta(seconds=TTL + LEEWAY))

    assert claims.sub == USER_ID


def test_future_issued_token_outside_clock_skew_is_rejected() -> None:
    token = _created_token()

    with pytest.raises(InvalidAccessTokenError):
        decode_access_token(token, now=BASE_TIME - timedelta(seconds=LEEWAY + 1))


def test_future_issued_token_within_clock_skew_is_accepted() -> None:
    token = _created_token()

    claims = decode_access_token(token, now=BASE_TIME - timedelta(seconds=LEEWAY))

    assert claims.sub == USER_ID


def test_wrong_issuer_is_rejected() -> None:
    token = _encode(_payload(iss="different-issuer"))

    with pytest.raises(InvalidAccessTokenError):
        decode_access_token(token, now=BASE_TIME)


def test_wrong_audience_is_rejected() -> None:
    token = _encode(_payload(aud="different-audience"))

    with pytest.raises(InvalidAccessTokenError):
        decode_access_token(token, now=BASE_TIME)


@pytest.mark.parametrize("claim", ["sub", "sid", "iss", "aud", "iat", "exp", "jti", "typ"])
def test_missing_required_claim_is_rejected(claim: str) -> None:
    payload = _payload()
    del payload[claim]

    with pytest.raises(InvalidAccessTokenError):
        decode_access_token(_encode(payload), now=BASE_TIME)


@pytest.mark.parametrize(
    ("claim", "value"),
    [
        ("sub", "not-a-uuid"),
        ("sid", "not-a-uuid"),
        ("sid", 12345),
        ("jti", ""),
    ],
)
def test_invalid_claim_values_are_rejected(claim: str, value: object) -> None:
    payload = _payload(**{claim: value})

    with pytest.raises(InvalidAccessTokenError):
        decode_access_token(_encode(payload), now=BASE_TIME)


def test_incorrect_token_type_is_rejected() -> None:
    token = _encode(_payload(typ="refresh"))

    with pytest.raises(InvalidAccessTokenError):
        decode_access_token(token, now=BASE_TIME)


def test_alg_none_is_rejected() -> None:
    token = _manual_token({"alg": "none", "typ": "JWT"}, _payload(), "")

    with pytest.raises(InvalidAccessTokenError):
        decode_access_token(token, now=BASE_TIME)


def test_algorithm_confusion_is_rejected() -> None:
    token = _manual_token({"alg": "RS256", "typ": "JWT"}, _payload(), "c2lnbmF0dXJl")

    with pytest.raises(InvalidAccessTokenError):
        decode_access_token(token, now=BASE_TIME)


@pytest.mark.parametrize(
    "token",
    [
        "",
        "   ",
        "not-a-token",
        "a.b.c",
        "..",
    ],
)
def test_malformed_tokens_are_rejected(token: str) -> None:
    with pytest.raises(InvalidAccessTokenError):
        decode_access_token(token, now=BASE_TIME)


def test_lifetime_longer_than_configured_maximum_is_rejected() -> None:
    issued_at = int(BASE_TIME.timestamp())
    token = _encode(_payload(exp=issued_at + TTL + 1))

    with pytest.raises(InvalidAccessTokenError):
        decode_access_token(token, now=BASE_TIME)


def test_creating_token_longer_than_configured_maximum_is_rejected() -> None:
    with pytest.raises(ValueError):
        _created_token(ttl_seconds=TTL + 1)


def test_token_payload_has_no_authoritative_role_claims() -> None:
    token = _created_token()
    payload = jwt.decode(
        token,
        TEST_SECRET,
        algorithms=["HS256"],
        audience=AUDIENCE,
        issuer=ISSUER,
        options={"verify_exp": False, "verify_iat": False},
    )

    assert "roles" not in payload
    assert "permissions" not in payload
    assert "is_admin" not in payload


def test_role_claims_in_external_token_are_not_exposed() -> None:
    token = _encode(_payload(roles=["Admin"], permissions=["*"], is_admin=True))

    claims = decode_access_token(token, now=BASE_TIME)

    assert not hasattr(claims, "roles")
    assert not hasattr(claims, "permissions")
    assert not hasattr(claims, "is_admin")


def test_naive_now_is_rejected() -> None:
    with pytest.raises(ValueError):
        decode_access_token(_created_token(), now=datetime(2030, 1, 1))


def test_create_rejects_non_uuid_identifiers() -> None:
    with pytest.raises(TypeError):
        create_access_token(user_id="not-a-uuid", session_id=SESSION_ID)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        create_access_token(user_id=USER_ID, session_id="not-a-uuid")  # type: ignore[arg-type]
