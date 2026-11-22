"""Target canonicalization, policy evaluation, and target-bound clients (M4)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.models.assessment import AssessmentJob
from app.models.assessment_target import AssessmentTarget
from app.schemas.enums import (
    AssessmentStatus,
    AssessmentType,
    AuthorizationBasis,
    TargetStatus,
    TargetType,
)
from app.services import target_authorization as service
from app.services.net import EgressError, EgressErrorCode
from app.services.tooling.target_policy import (
    TargetAuthorizationPolicy,
    TargetDecisionReason,
    TargetKind,
    TargetRequest,
)

NOW = datetime(2026, 11, 16, tzinfo=UTC)


@pytest.mark.parametrize(
    ("raw", "url"),
    [
        ("https://DVWA.test", "https://dvwa.test/"),
        ("http://dvwa.test:80/app/", "http://dvwa.test/app/"),
        ("http://dvwa.test:8080/a/./b/../c", "http://dvwa.test:8080/a/c"),
        ("http://dvwa.test//x//", "http://dvwa.test/x/"),
        ("https://bücher.test/", "https://xn--bcher-kva.test/"),
        ("http://127.0.0.1:8080/", "http://127.0.0.1:8080/"),
        ("http://[::1]:8080/", "http://[::1]:8080/"),
        ("http://dvwa.test/%2e%2e/secret", "http://dvwa.test/secret"),
    ],
)
def test_canonicalization(raw: str, url: str) -> None:
    assert service.canonicalize_web_target(raw).url == url


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        ("ftp://dvwa.test/", "scheme_not_allowed"),
        ("file:///etc/passwd", "scheme_not_allowed"),
        ("http://user:pw@dvwa.test/", "credentials_in_target"),
        ("http://dvwa.test/?id=1", "query_or_fragment_not_allowed"),
        ("http://dvwa.test/#x", "query_or_fragment_not_allowed"),
        ("http:///nohost", "invalid_target"),
        ("http://dvwa.test:99999/", "invalid_target"),
        ("http://dvwa.test/a b", "invalid_target"),
        ("http://" + "a" * 3000 + ".test/", "invalid_target"),
    ],
)
def test_invalid_targets_are_rejected(raw: str, code: str) -> None:
    with pytest.raises(service.InvalidTargetError) as excinfo:
        service.canonicalize_web_target(raw)
    assert excinfo.value.code == code


def test_base_path_containment_is_segment_aware() -> None:
    assert service._within_base_path("/app/x", "/app")  # noqa: SLF001
    assert service._within_base_path("/app/", "/app/")  # noqa: SLF001
    assert not service._within_base_path("/application", "/app")  # noqa: SLF001
    assert service._within_base_path("/anything", "/")  # noqa: SLF001


def _web_target(
    session_factory: sessionmaker[Session],
    *,
    status: TargetStatus,
    url: str = "http://dvwa.test/app/",
) -> tuple[uuid.UUID, AssessmentTarget]:
    with session_factory() as session:
        assessment = AssessmentJob(
            assessment_type=AssessmentType.WEB_SECURITY,
            status=AssessmentStatus.QUEUED,
            created_at=NOW,
            updated_at=NOW,
        )
        session.add(assessment)
        session.flush()
        target = AssessmentTarget(
            assessment_id=assessment.id,
            target_type=TargetType.WEB_APPLICATION,
            canonical_target=url,
            status=status,
            authorization_basis=AuthorizationBasis.EXPLICIT_CONFIRMATION,
            created_at=NOW,
            updated_at=NOW,
        )
        session.add(target)
        session.commit()
        return assessment.id, target


def _request(assessment_id: uuid.UUID, url: str) -> TargetRequest:
    return TargetRequest(
        kind=TargetKind.WEB_APPLICATION,
        canonical_target=url,
        assessment_id=assessment_id,
        requested_by=uuid.uuid4(),
    )


def test_database_policy_allows_only_authorized_allowlisted_scope(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "web_target_allowed_hosts", ["dvwa.test"])
    assessment_id, _target = _web_target(session_factory, status=TargetStatus.AUTHORIZED)
    with session_factory() as session:
        policy = service.DatabaseTargetAuthorizationPolicy(session)
        assert isinstance(policy, TargetAuthorizationPolicy)
        assert policy.evaluate(_request(assessment_id, "http://dvwa.test/app/login.php")).allowed
        for url in (
            "http://dvwa.test/application",
            "http://other.test/app/",
            "https://dvwa.test/app/",
        ):
            assert not policy.evaluate(_request(assessment_id, url)).allowed
        assert not policy.evaluate(_request(uuid.uuid4(), "http://dvwa.test/app/")).allowed

    monkeypatch.setattr(settings, "web_target_allowed_hosts", [])
    with session_factory() as session:
        decision = service.DatabaseTargetAuthorizationPolicy(session).evaluate(
            _request(assessment_id, "http://dvwa.test/app/")
        )
    assert decision.reason is TargetDecisionReason.NOT_ALLOWLISTED


@pytest.mark.parametrize("status", [TargetStatus.PENDING_AUTHORIZATION, TargetStatus.REVOKED])
def test_policy_denies_pending_and_revoked_targets(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch, status: TargetStatus
) -> None:
    monkeypatch.setattr(settings, "web_target_allowed_hosts", ["dvwa.test"])
    assessment_id, target = _web_target(session_factory, status=status)
    with session_factory() as session:
        assert (
            not service.DatabaseTargetAuthorizationPolicy(session)
            .evaluate(_request(assessment_id, "http://dvwa.test/app/"))
            .allowed
        )
        with pytest.raises(service.TargetNotAuthorizedError):
            service.build_target_client(session, session.get(AssessmentTarget, target.id))


def test_target_client_is_bound_to_the_target_host(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "web_target_allowed_hosts", ["dvwa.test"])
    monkeypatch.setattr(settings, "web_target_allowed_local_networks", ["127.0.0.0/8"])
    _assessment_id, target = _web_target(session_factory, status=TargetStatus.AUTHORIZED)
    with session_factory() as session:
        client = service.build_target_client(session, session.get(AssessmentTarget, target.id))
    assert client._allowed_hosts == frozenset({"dvwa.test"})  # noqa: SLF001
    assert [str(net) for net in client.policy.allowed_local_networks] == ["127.0.0.0/8"]
    with pytest.raises(EgressError) as excinfo:
        client.request("GET", "http://other.test/")
    assert excinfo.value.code is EgressErrorCode.HOST_NOT_ALLOWED


def test_policy_snapshot_records_the_policy_in_force(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "repository_isolation", "per_user")
    assert service.policy_snapshot(TargetType.REPOSITORY)["repository_isolation"] == "per_user"
    web = service.policy_snapshot(TargetType.WEB_APPLICATION)
    assert web["allowed_schemes"] == ["http", "https"]
    assert web["policy_version"] == service.POLICY_VERSION
