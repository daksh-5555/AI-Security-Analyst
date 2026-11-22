"""Migration round-trip checks for assessment ownership."""

import uuid
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError

from app.db.session import create_db_engine

PROJECT_ROOT = Path(__file__).resolve().parents[1]
OWNER_INDEX = "ix_assessment_jobs_owner_id"
OWNER_FOREIGN_KEY = "fk_assessment_jobs_owner_id"
USER_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")
ASSESSMENT_ID = uuid.UUID("22222222-2222-2222-2222-222222222222")
REPOSITORY_TARGET_ID = uuid.UUID("33333333-3333-3333-3333-333333333333")
ANALYSIS_RUN_ID = uuid.UUID("44444444-4444-4444-4444-444444444444")
FINDING_ID = uuid.UUID("55555555-5555-5555-5555-555555555555")
EVIDENCE_ID = uuid.UUID("66666666-6666-6666-6666-666666666666")
STATUS_HISTORY_ID = uuid.UUID("77777777-7777-7777-7777-777777777777")
TIMESTAMP = "2026-01-01 00:00:00.000000"


def make_config(database_url: str) -> Config:
    config = Config(str(PROJECT_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


def insert_legacy_graph(engine: Engine) -> None:
    """Insert an assessment with every dependent record that 0011 can affect."""
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
                "email": "legacy-owner-migration@example.com",
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
        connection.execute(
            text(
                "INSERT INTO repository_targets ("
                "id, assessment_id, source_kind, location, created_at, updated_at"
                ") VALUES (:id, :assessment_id, 'local_path', :location, :created_at, :created_at)"
            ),
            {
                "id": REPOSITORY_TARGET_ID.hex,
                "assessment_id": ASSESSMENT_ID.hex,
                "location": "/legacy/repository",
                "created_at": TIMESTAMP,
            },
        )
        connection.execute(
            text(
                "INSERT INTO analysis_runs ("
                "id, assessment_id, status, created_at, started_at, completed_at, "
                "error_message, analysis_metadata"
                ") VALUES (:id, :assessment_id, 'completed', :created_at, :created_at, "
                ":created_at, NULL, NULL)"
            ),
            {
                "id": ANALYSIS_RUN_ID.hex,
                "assessment_id": ASSESSMENT_ID.hex,
                "created_at": TIMESTAMP,
            },
        )
        connection.execute(
            text(
                "INSERT INTO assessment_findings ("
                "id, assessment_id, analysis_run_id, position, title, category, "
                "severity, status, confidence, summary, affected_component, "
                "remediation, created_at, updated_at"
                ") VALUES (:id, :assessment_id, :analysis_run_id, 0, :title, :category, "
                "'high', 'confirmed', 0.9, :summary, NULL, NULL, :created_at, :created_at)"
            ),
            {
                "id": FINDING_ID.hex,
                "assessment_id": ASSESSMENT_ID.hex,
                "analysis_run_id": ANALYSIS_RUN_ID.hex,
                "title": "Legacy finding",
                "category": "injection",
                "summary": "Legacy finding summary",
                "created_at": TIMESTAMP,
            },
        )
        connection.execute(
            text(
                "INSERT INTO finding_evidence ("
                "id, finding_id, position, description, source, details, created_at"
                ") VALUES (:id, :finding_id, 0, :description, :source, NULL, :created_at)"
            ),
            {
                "id": EVIDENCE_ID.hex,
                "finding_id": FINDING_ID.hex,
                "description": "Legacy evidence",
                "source": "static-analysis",
                "created_at": TIMESTAMP,
            },
        )
        connection.execute(
            text(
                "INSERT INTO assessment_status_history ("
                "id, assessment_id, previous_status, new_status, changed_at, reason"
                ") VALUES (:id, :assessment_id, 'queued', 'running', :changed_at, :reason)"
            ),
            {
                "id": STATUS_HISTORY_ID.hex,
                "assessment_id": ASSESSMENT_ID.hex,
                "changed_at": TIMESTAMP,
                "reason": "legacy transition",
            },
        )


def column_names(engine: Engine, table_name: str) -> set[str]:
    return {column["name"] for column in inspect(engine).get_columns(table_name)}


def assert_legacy_graph_present(engine: Engine) -> None:
    expected_rows = {
        "assessment_jobs": ASSESSMENT_ID,
        "repository_targets": REPOSITORY_TARGET_ID,
        "analysis_runs": ANALYSIS_RUN_ID,
        "assessment_findings": FINDING_ID,
        "finding_evidence": EVIDENCE_ID,
        "assessment_status_history": STATUS_HISTORY_ID,
    }
    with engine.connect() as connection:
        assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1

        for table_name, row_id in expected_rows.items():
            count = connection.execute(
                text(f"SELECT COUNT(*) FROM {table_name} WHERE id = :id"),
                {"id": row_id.hex},
            ).scalar_one()
            assert count == 1, f"{table_name} row {row_id} was lost"

        assert (
            connection.execute(
                text("SELECT COUNT(*) FROM users WHERE id = :id"),
                {"id": USER_ID.hex},
            ).scalar_one()
            == 1
        )
        assert connection.exec_driver_sql("PRAGMA foreign_key_check").fetchall() == []


def test_migration_0011_follows_0010() -> None:
    script = ScriptDirectory.from_config(make_config("sqlite://"))

    revision = script.get_revision("0011")

    assert revision is not None
    assert revision.down_revision == "0010"
    assert script.get_heads() == ["0022"]


def test_migration_0011_round_trip_preserves_assessment_and_child_rows(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "assessment-owner-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    config = make_config(database_url)

    command.upgrade(config, "0010")

    engine = create_db_engine(database_url)
    try:
        # The application engine keeps normal foreign-key enforcement enabled.
        with engine.connect() as connection:
            assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1

        insert_legacy_graph(engine)
        assert_legacy_graph_present(engine)
    finally:
        engine.dispose()

    command.upgrade(config, "head")

    engine = create_db_engine(database_url)
    try:
        columns = {
            column["name"]: column for column in inspect(engine).get_columns("assessment_jobs")
        }
        assert columns["owner_id"]["nullable"] is True

        foreign_keys = inspect(engine).get_foreign_keys("assessment_jobs")
        owner_foreign_key = next(
            foreign_key for foreign_key in foreign_keys if foreign_key["name"] == OWNER_FOREIGN_KEY
        )
        assert owner_foreign_key["referred_table"] == "users"
        assert owner_foreign_key["constrained_columns"] == ["owner_id"]
        assert owner_foreign_key["referred_columns"] == ["id"]
        assert owner_foreign_key["options"].get("ondelete") == "RESTRICT"

        indexes = {index["name"]: index for index in inspect(engine).get_indexes("assessment_jobs")}
        assert indexes[OWNER_INDEX]["column_names"] == ["owner_id"]
        assert indexes["ix_assessment_jobs_created_at"]["column_names"] == ["created_at"]

        assert_legacy_graph_present(engine)

        with engine.connect() as connection:
            owner_id = connection.execute(
                text("SELECT owner_id FROM assessment_jobs WHERE id = :id"),
                {"id": ASSESSMENT_ID.hex},
            ).scalar_one()
        assert owner_id is None

        with engine.begin() as connection:
            connection.execute(
                text("UPDATE assessment_jobs SET owner_id = :owner_id WHERE id = :id"),
                {"owner_id": USER_ID.hex, "id": ASSESSMENT_ID.hex},
            )

        with pytest.raises(IntegrityError):
            with engine.begin() as connection:
                connection.execute(
                    text("DELETE FROM users WHERE id = :id"),
                    {"id": USER_ID.hex},
                )

        # A failed constraint must not damage the graph.
        assert_legacy_graph_present(engine)
    finally:
        engine.dispose()

    command.downgrade(config, "0010")

    engine = create_db_engine(database_url)
    try:
        assert "owner_id" not in column_names(engine, "assessment_jobs")
        remaining_indexes = {
            index["name"]: index for index in inspect(engine).get_indexes("assessment_jobs")
        }
        assert OWNER_INDEX not in remaining_indexes
        assert remaining_indexes["ix_assessment_jobs_created_at"]["column_names"] == ["created_at"]
        assert not any(
            foreign_key["name"] == OWNER_FOREIGN_KEY
            for foreign_key in inspect(engine).get_foreign_keys("assessment_jobs")
        )

        assert_legacy_graph_present(engine)

        with engine.connect() as connection:
            assert connection.execute(text("SELECT COUNT(*) FROM roles")).scalar_one() == 3
    finally:
        engine.dispose()

    command.upgrade(config, "head")

    engine = create_db_engine(database_url)
    try:
        assert "owner_id" in column_names(engine, "assessment_jobs")
        assert_legacy_graph_present(engine)

        with engine.connect() as connection:
            owner_id = connection.execute(
                text("SELECT owner_id FROM assessment_jobs WHERE id = :id"),
                {"id": ASSESSMENT_ID.hex},
            ).scalar_one()
        assert owner_id is None
    finally:
        engine.dispose()
