"""Regression tests: only the expected constraint race is treated as benign."""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from auth_helpers import create_user
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.db.integrity import (
    ACTIVE_ACTION_TOKEN,
    USER_ROLE_ASSIGNMENT,
    USERS_EMAIL_NORMALIZED,
    violates,
)
from app.models.user import User
from app.schemas.enums import UserActionTokenPurpose
from app.services import identity
from app.services.roles import assign_default_role_if_unassigned
from app.services.user_action_tokens import issue_action_token

UNEXPECTED = "unexpected_integrity_error"


def _unexpected_records(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [
        record for record in caplog.records if getattr(record, "security_event", None) == UNEXPECTED
    ]


def _duplicate_email_error(session_factory: sessionmaker[Session]) -> IntegrityError:
    create_user(session_factory, email="dup@example.com")
    now = datetime.now(UTC)
    with session_factory() as session:
        session.add(
            User(
                email="dup@example.com",
                email_normalized="dup@example.com",
                password_hash="x",
                is_active=True,
                is_email_verified=False,
                created_at=now,
                updated_at=now,
            )
        )
        with pytest.raises(IntegrityError) as exc_info:
            session.flush()
        return exc_info.value


def test_violates_matches_real_sqlite_unique_violation(
    session_factory: sessionmaker[Session],
) -> None:
    error = _duplicate_email_error(session_factory)

    assert violates(error, USERS_EMAIL_NORMALIZED)
    assert not violates(error, ACTIVE_ACTION_TOKEN)
    assert not violates(error, USER_ROLE_ASSIGNMENT)


def test_violates_uses_constraint_name_when_driver_provides_it() -> None:
    original = SimpleNamespace(diag=SimpleNamespace(constraint_name="uq_users_email_normalized"))
    error = IntegrityError("INSERT ...", {}, original)  # type: ignore[arg-type]

    assert violates(error, USERS_EMAIL_NORMALIZED)
    assert not violates(error, ACTIVE_ACTION_TOKEN)


def test_role_assignment_foreign_key_violation_is_not_reported_as_success(
    session_factory: sessionmaker[Session],
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.ERROR)
    with session_factory() as session:
        with pytest.raises(IntegrityError):
            assign_default_role_if_unassigned(session, user_id=uuid.uuid4())

    assert len(_unexpected_records(caplog)) == 1


def test_concurrent_role_assignment_race_is_still_absorbed(
    session_factory: sessionmaker[Session],
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.ERROR)
    user_id = create_user(session_factory, email="race@example.com")
    with session_factory() as winner:
        assert assign_default_role_if_unassigned(winner, user_id=user_id) is True
        winner.commit()

    with session_factory() as loser:
        # Simulate the loser having read "no roles" before the winner committed.
        loser_check = "app.services.roles.user_has_any_role"
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(loser_check, lambda *_a, **_k: False)
            assert assign_default_role_if_unassigned(loser, user_id=user_id) is False

    assert _unexpected_records(caplog) == []


def test_token_issuance_for_missing_user_fails_closed_and_is_logged(
    session_factory: sessionmaker[Session],
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.ERROR)
    with session_factory() as session:
        raw = issue_action_token(
            session,
            user_id=uuid.uuid4(),
            purpose=UserActionTokenPurpose.PASSWORD_RESET,
        )

    assert raw is None
    records = _unexpected_records(caplog)
    assert len(records) == 1
    assert records[0].operation == "action token issuance"


def test_registration_logs_unexpected_integrity_failure_but_stays_generic(
    session_factory: sessionmaker[Session],
    low_cost_argon2: None,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.ERROR)
    unexpected = IntegrityError(
        "INSERT ...",
        {},
        Exception("FOREIGN KEY constraint failed"),  # type: ignore[arg-type]
    )

    def failing_flush(*_args: object, **_kwargs: object) -> None:
        raise unexpected

    with session_factory() as session:
        monkeypatch.setattr(session, "flush", failing_flush)
        result = identity.register_user(
            session,
            email="new-user@example.com",
            password="a sufficiently long password",
        )

    assert result is None
    records = _unexpected_records(caplog)
    assert len(records) == 1
    # Driver text can contain conflicting values; it must not be logged.
    assert "FOREIGN KEY" not in records[0].getMessage()
    assert "new-user@example.com" not in str(vars(records[0]))


def test_duplicate_registration_is_expected_and_not_logged(
    session_factory: sessionmaker[Session],
    low_cost_argon2: None,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.ERROR)
    create_user(session_factory, email="taken@example.com")

    with session_factory() as session:
        result = identity.register_user(
            session,
            email="taken@example.com",
            password="a sufficiently long password",
        )

    assert result is None
    assert _unexpected_records(caplog) == []
