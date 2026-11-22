"""Migration round-trip checks for the audit-event table."""

import uuid
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine

from app.db.session import create_db_engine

PROJECT_ROOT = Path(__file__).resolve().parents[1]
USER_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")
ASSESSMENT_ID = uuid.UUID("22222222-2222-2222-2222-222222222222")
AUDIT_EVENT_ID = uuid.UUID("33333333-3333-3333-3333-333333333333")
SURVIVING_ASSESSMENT_ID = uuid.UUID("44444444-4444-4444-4444-444444444444")
TIMESTAMP = "2026-01-01 00:00:00.000000"

AUDIT_INDEXES = {
    "ix_audit_events_assessment_id_occurred_at": ["assessment_id", "occurred_at"],
    "ix_audit_events_actor_user_id_occurred_at": ["actor_user_id", "occurred_at"],
    "ix_audit_events_action_occurred_at": ["action", "occurred_at"],
    "ix_audit_events_occurred_at": ["occurred_at"],
}


def make_config(database_url: str) -> Config:
    config = Config(str(PROJECT_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


def insert_identity_and_assessment(engine: Engine) -> None:
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO users ("
                "id, email, email_normalized, password_hash, is_active, "
                "is_email_verified, created_at, updated_at"
                ") VALUES (:id, :email, :email, :password_hash, 1, 1, :created_at, :created_at)"
            ),
            {
                "id": USER_ID.hex,
                "email": "audit-migration@example.com",
                "password_hash": "argon2id-placeholder-hash",
                "created_at": TIMESTAMP,
            },
        )
        connection.execute(
            text(
                "INSERT INTO assessment_jobs ("
                "id, assessment_type, status, created_at, updated_at"
                ") VALUES (:id, 'repository', 'queued', :created_at, :created_at)"
            ),
            {"id": ASSESSMENT_ID.hex, "created_at": TIMESTAMP},
        )


def test_migration_0012_follows_0011() -> None:
    script = ScriptDirectory.from_config(make_config("sqlite://"))

    revision = script.get_revision("0012")

    assert revision is not None
    assert revision.down_revision == "0011"
    assert script.get_heads() == ["0022"]


def test_migration_0012_round_trip_preserves_audit_history(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "audit-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    config = make_config(database_url)

    command.upgrade(config, "0011")

    engine = create_db_engine(database_url)
    try:
        with engine.connect() as connection:
            assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1
        insert_identity_and_assessment(engine)
    finally:
        engine.dispose()

    command.upgrade(config, "head")

    engine = create_db_engine(database_url)
    try:
        columns = {column["name"]: column for column in inspect(engine).get_columns("audit_events")}
        assert columns["actor_user_id"]["nullable"] is True
        assert columns["assessment_id"]["nullable"] is True
        assert columns["resource_id"]["nullable"] is True
        assert columns["occurred_at"]["nullable"] is False
        assert columns["action"]["nullable"] is False
        assert columns["outcome"]["nullable"] is False

        indexes = {index["name"]: index for index in inspect(engine).get_indexes("audit_events")}
        for name, expected_columns in AUDIT_INDEXES.items():
            assert indexes[name]["column_names"] == expected_columns

        foreign_keys = {
            foreign_key["name"]: foreign_key
            for foreign_key in inspect(engine).get_foreign_keys("audit_events")
        }
        assert foreign_keys["fk_audit_events_actor_user_id"]["referred_table"] == "users"
        assert (
            foreign_keys["fk_audit_events_actor_user_id"]["options"].get("ondelete") == "SET NULL"
        )
        assert foreign_keys["fk_audit_events_assessment_id"]["referred_table"] == "assessment_jobs"
        assert (
            foreign_keys["fk_audit_events_assessment_id"]["options"].get("ondelete") == "SET NULL"
        )

        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO audit_events ("
                    "id, occurred_at, actor_user_id, assessment_id, resource_type, "
                    "resource_id, action, outcome, context"
                    ") VALUES (:id, :occurred_at, :actor, :assessment, 'assessment', "
                    ":resource, 'assessment.created', 'success', "
                    '\'{"assessment_type": "repository"}\')'
                ),
                {
                    "id": AUDIT_EVENT_ID.hex,
                    "occurred_at": TIMESTAMP,
                    "actor": USER_ID.hex,
                    "assessment": ASSESSMENT_ID.hex,
                    "resource": ASSESSMENT_ID.hex,
                },
            )

        # Deleting the assessment must preserve the audit row and null only the
        # foreign-key link; the immutable resource identifier remains.
        with engine.begin() as connection:
            connection.execute(
                text("DELETE FROM assessment_jobs WHERE id = :id"),
                {"id": ASSESSMENT_ID.hex},
            )
            remaining = connection.execute(
                text("SELECT assessment_id, resource_id FROM audit_events WHERE id = :id"),
                {"id": AUDIT_EVENT_ID.hex},
            ).one()
            assert remaining.assessment_id is None
            assert remaining.resource_id == ASSESSMENT_ID.hex

            assert connection.exec_driver_sql("PRAGMA foreign_key_check").fetchall() == []

        # A second, untouched assessment proves the round trip does not damage
        # unrelated business rows.
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO assessment_jobs ("
                    "id, assessment_type, status, created_at, updated_at"
                    ") VALUES (:id, 'repository', 'queued', :created_at, :created_at)"
                ),
                {"id": SURVIVING_ASSESSMENT_ID.hex, "created_at": TIMESTAMP},
            )
    finally:
        engine.dispose()

    command.downgrade(config, "0011")

    engine = create_db_engine(database_url)
    try:
        assert "audit_events" not in inspect(engine).get_table_names()
        # The business rows created before the audit table existed are untouched.
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT COUNT(*) FROM assessment_jobs"),
                ).scalar_one()
                == 1
            )
    finally:
        engine.dispose()

    command.upgrade(config, "head")

    engine = create_db_engine(database_url)
    try:
        assert "audit_events" in inspect(engine).get_table_names()
        with engine.connect() as connection:
            assert connection.execute(text("SELECT COUNT(*) FROM audit_events")).scalar_one() == 0
    finally:
        engine.dispose()
