"""Migration round-trip checks for the analysis-run lease foundation."""

import importlib.util
import uuid
from pathlib import Path
from types import ModuleType

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError

from app.db.session import create_db_engine

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ACTIVE_RUN_INDEX = "uq_analysis_runs_active_assessment"
CANCEL_ACTOR_FOREIGN_KEY = "fk_analysis_runs_cancel_requested_by_user_id"
USER_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")
CANCEL_ACTOR_ID = uuid.UUID("22222222-2222-2222-2222-222222222222")
ASSESSMENT_ID = uuid.UUID("33333333-3333-3333-3333-333333333333")
RUNNING_RUN_ID = uuid.UUID("44444444-4444-4444-4444-444444444444")
COMPLETED_RUN_ID = uuid.UUID("55555555-5555-5555-5555-555555555555")
FINDING_ID = uuid.UUID("66666666-6666-6666-6666-666666666666")
AUDIT_EVENT_ID = uuid.UUID("77777777-7777-7777-7777-777777777777")
TIMESTAMP = "2026-01-01 00:00:00.000000"
RUNNING_STARTED_AT = "2026-01-02 03:04:05.000000"
SENTINEL_HEARTBEAT = "2026-03-04 05:06:07.000000"


def make_config(database_url: str) -> Config:
    config = Config(str(PROJECT_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


def load_migration_module() -> ModuleType:
    path = PROJECT_ROOT / "migrations" / "versions" / "0014_add_analysis_run_lease.py"
    spec = importlib.util.spec_from_file_location("migration_0014", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def insert_legacy_graph(engine: Engine) -> None:
    """Insert the rows that migration 0014 must preserve and backfill."""
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
                "email": "lease-migration@example.com",
                "password_hash": "argon2id-placeholder-hash",
                "created_at": TIMESTAMP,
            },
        )
        connection.execute(
            text(
                "INSERT INTO users ("
                "id, email, email_normalized, password_hash, is_active, "
                "is_email_verified, created_at, updated_at"
                ") VALUES (:id, :email, :email, :password_hash, 1, 1, :created_at, :created_at)"
            ),
            {
                "id": CANCEL_ACTOR_ID.hex,
                "email": "lease-canceller@example.com",
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
                "INSERT INTO analysis_runs ("
                "id, assessment_id, status, created_at, started_at, completed_at, "
                "error_message, analysis_metadata"
                ") VALUES (:id, :assessment_id, :status, :created_at, :started_at, "
                ":completed_at, NULL, NULL)"
            ),
            {
                "id": RUNNING_RUN_ID.hex,
                "assessment_id": ASSESSMENT_ID.hex,
                "status": "running",
                "created_at": TIMESTAMP,
                "started_at": RUNNING_STARTED_AT,
                "completed_at": None,
            },
        )
        connection.execute(
            text(
                "INSERT INTO analysis_runs ("
                "id, assessment_id, status, created_at, started_at, completed_at, "
                "error_message, analysis_metadata"
                ") VALUES (:id, :assessment_id, :status, :created_at, :started_at, "
                ":completed_at, NULL, NULL)"
            ),
            {
                "id": COMPLETED_RUN_ID.hex,
                "assessment_id": ASSESSMENT_ID.hex,
                "status": "completed",
                "created_at": TIMESTAMP,
                "started_at": TIMESTAMP,
                "completed_at": TIMESTAMP,
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
                "analysis_run_id": RUNNING_RUN_ID.hex,
                "title": "Finding across the lease migration",
                "category": "injection",
                "summary": "Existing findings must survive the rebuild.",
                "created_at": TIMESTAMP,
            },
        )
        connection.execute(
            text(
                "INSERT INTO audit_events ("
                "id, occurred_at, resource_type, action, outcome, context"
                ") VALUES (:id, :occurred_at, 'analysis_run', "
                "'analysis_run.started', 'success', NULL)"
            ),
            {"id": AUDIT_EVENT_ID.hex, "occurred_at": TIMESTAMP},
        )


def assert_graph_present(engine: Engine) -> None:
    expected_rows = {
        "assessment_jobs": ASSESSMENT_ID,
        "analysis_runs": RUNNING_RUN_ID,
        "assessment_findings": FINDING_ID,
        "audit_events": AUDIT_EVENT_ID,
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
                text("SELECT COUNT(*) FROM analysis_runs WHERE id = :id"),
                {"id": COMPLETED_RUN_ID.hex},
            ).scalar_one()
            == 1
        )
        assert (
            connection.execute(
                text("SELECT COUNT(*) FROM users WHERE id IN (:owner, :actor)"),
                {"owner": USER_ID.hex, "actor": CANCEL_ACTOR_ID.hex},
            ).scalar_one()
            == 2
        )
        assert connection.exec_driver_sql("PRAGMA foreign_key_check").fetchall() == []


def table_schema(engine: Engine) -> str:
    with engine.connect() as connection:
        return connection.exec_driver_sql(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'analysis_runs'"
        ).scalar_one()


def active_run_index_schema(engine: Engine) -> str:
    with engine.connect() as connection:
        return connection.exec_driver_sql(
            "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = :name",
            {"name": ACTIVE_RUN_INDEX},
        ).scalar_one()


def test_migration_0014_follows_0013() -> None:
    script = ScriptDirectory.from_config(make_config("sqlite://"))

    revision = script.get_revision("0014")

    assert revision is not None
    assert revision.down_revision == "0013"
    assert script.get_heads() == ["0022"]


def test_migration_0014_round_trip_preserves_data_and_backfills(tmp_path: Path) -> None:
    database_path = tmp_path / "analysis-run-lease.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    config = make_config(database_url)

    command.upgrade(config, "0013")

    engine = create_db_engine(database_url)
    try:
        insert_legacy_graph(engine)
        assert_graph_present(engine)
        assert "heartbeat_at" not in {
            column["name"] for column in inspect(engine).get_columns("analysis_runs")
        }
    finally:
        engine.dispose()

    command.upgrade(config, "0014")

    backfill = load_migration_module().BACKFILL_RUNNING_HEARTBEATS
    engine = create_db_engine(database_url)
    try:
        columns = {
            column["name"]: column for column in inspect(engine).get_columns("analysis_runs")
        }
        for column_name in (
            "heartbeat_at",
            "cancel_requested_at",
            "cancel_requested_by_user_id",
        ):
            assert columns[column_name]["nullable"] is True

        foreign_key = next(
            foreign_key
            for foreign_key in inspect(engine).get_foreign_keys("analysis_runs")
            if foreign_key["name"] == CANCEL_ACTOR_FOREIGN_KEY
        )
        assert foreign_key["referred_table"] == "users"
        assert foreign_key["constrained_columns"] == ["cancel_requested_by_user_id"]
        assert foreign_key["referred_columns"] == ["id"]
        assert foreign_key["options"].get("ondelete") == "SET NULL"

        index_schema = active_run_index_schema(engine)
        assert "UNIQUE INDEX" in index_schema
        assert "WHERE status = 'running'" in index_schema

        schema = table_schema(engine)
        assert "analysis_run_status" in schema
        assert "status IN ('running', 'completed', 'failed')" in schema

        with engine.connect() as connection:
            running_heartbeat = connection.execute(
                text("SELECT heartbeat_at FROM analysis_runs WHERE id = :id"),
                {"id": RUNNING_RUN_ID.hex},
            ).scalar_one()
            completed_heartbeat = connection.execute(
                text("SELECT heartbeat_at FROM analysis_runs WHERE id = :id"),
                {"id": COMPLETED_RUN_ID.hex},
            ).scalar_one()
            cancellation = connection.execute(
                text(
                    "SELECT cancel_requested_at, cancel_requested_by_user_id "
                    "FROM analysis_runs WHERE id = :id"
                ),
                {"id": RUNNING_RUN_ID.hex},
            ).one()

        assert running_heartbeat == RUNNING_STARTED_AT
        assert completed_heartbeat is None
        assert cancellation == (None, None)

        assert_graph_present(engine)

        # A second pass must not overwrite a newer heartbeat.
        with engine.begin() as connection:
            connection.execute(
                text("UPDATE analysis_runs SET heartbeat_at = :heartbeat WHERE id = :id"),
                {"heartbeat": SENTINEL_HEARTBEAT, "id": RUNNING_RUN_ID.hex},
            )
            connection.execute(backfill)
            connection.execute(backfill)
            heartbeat = connection.execute(
                text("SELECT heartbeat_at FROM analysis_runs WHERE id = :id"),
                {"id": RUNNING_RUN_ID.hex},
            ).scalar_one()
            completed_heartbeat = connection.execute(
                text("SELECT heartbeat_at FROM analysis_runs WHERE id = :id"),
                {"id": COMPLETED_RUN_ID.hex},
            ).scalar_one()

        assert heartbeat == SENTINEL_HEARTBEAT
        assert completed_heartbeat is None

        invalid_run_id = uuid.uuid4()
        with pytest.raises(IntegrityError, match="analysis_run_status"):
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "INSERT INTO analysis_runs ("
                        "id, assessment_id, status, created_at, started_at"
                        ") VALUES (:id, :assessment_id, 'unknown', :created_at, :created_at)"
                    ),
                    {
                        "id": invalid_run_id.hex,
                        "assessment_id": ASSESSMENT_ID.hex,
                        "created_at": TIMESTAMP,
                    },
                )
    finally:
        engine.dispose()

    command.downgrade(config, "0013")

    engine = create_db_engine(database_url)
    try:
        columns = {column["name"] for column in inspect(engine).get_columns("analysis_runs")}
        assert "heartbeat_at" not in columns
        assert "cancel_requested_at" not in columns
        assert "cancel_requested_by_user_id" not in columns
        assert not any(
            foreign_key["name"] == CANCEL_ACTOR_FOREIGN_KEY
            for foreign_key in inspect(engine).get_foreign_keys("analysis_runs")
        )

        index_schema = active_run_index_schema(engine)
        assert "UNIQUE INDEX" in index_schema
        assert "WHERE status = 'running'" in index_schema

        schema = table_schema(engine)
        assert "analysis_run_status" in schema
        assert "status IN ('running', 'completed', 'failed')" in schema

        assert_graph_present(engine)

        with pytest.raises(IntegrityError, match="analysis_run_status"):
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "INSERT INTO analysis_runs ("
                        "id, assessment_id, status, created_at, started_at"
                        ") VALUES (:id, :assessment_id, 'unknown', :created_at, :created_at)"
                    ),
                    {
                        "id": uuid.uuid4().hex,
                        "assessment_id": ASSESSMENT_ID.hex,
                        "created_at": TIMESTAMP,
                    },
                )
    finally:
        engine.dispose()

    command.upgrade(config, "head")

    engine = create_db_engine(database_url)
    try:
        assert_graph_present(engine)
        with engine.connect() as connection:
            heartbeat = connection.execute(
                text("SELECT heartbeat_at FROM analysis_runs WHERE id = :id"),
                {"id": RUNNING_RUN_ID.hex},
            ).scalar_one()
        assert heartbeat == RUNNING_STARTED_AT
    finally:
        engine.dispose()


def test_migration_0014_cancellation_actor_deletion_sets_null(tmp_path: Path) -> None:
    database_path = tmp_path / "analysis-run-cancellation-actor.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    config = make_config(database_url)

    command.upgrade(config, "head")

    run_id = uuid.uuid4()
    engine = create_db_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO users ("
                    "id, email, email_normalized, password_hash, is_active, "
                    "is_email_verified, created_at, updated_at"
                    ") VALUES (:id, :email, :email, 'hash', 1, 1, :created_at, :created_at)"
                ),
                {
                    "id": CANCEL_ACTOR_ID.hex,
                    "email": "cancellation-actor@example.com",
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
                    "INSERT INTO analysis_runs ("
                    "id, assessment_id, status, created_at, started_at, heartbeat_at, "
                    "cancel_requested_at, cancel_requested_by_user_id"
                    ") VALUES (:id, :assessment_id, 'running', :created_at, :created_at, "
                    ":created_at, :cancel_requested_at, :actor)"
                ),
                {
                    "id": run_id.hex,
                    "assessment_id": ASSESSMENT_ID.hex,
                    "created_at": TIMESTAMP,
                    "cancel_requested_at": TIMESTAMP,
                    "actor": CANCEL_ACTOR_ID.hex,
                },
            )

        with engine.begin() as connection:
            connection.execute(
                text("DELETE FROM users WHERE id = :id"),
                {"id": CANCEL_ACTOR_ID.hex},
            )

        with engine.connect() as connection:
            run = connection.execute(
                text(
                    "SELECT cancel_requested_at, cancel_requested_by_user_id "
                    "FROM analysis_runs WHERE id = :id"
                ),
                {"id": run_id.hex},
            ).one()
            user_count = connection.execute(
                text("SELECT COUNT(*) FROM users WHERE id = :id"),
                {"id": CANCEL_ACTOR_ID.hex},
            ).scalar_one()
            assert connection.exec_driver_sql("PRAGMA foreign_key_check").fetchall() == []

        assert run.cancel_requested_at == TIMESTAMP
        assert run.cancel_requested_by_user_id is None
        assert user_count == 0
    finally:
        engine.dispose()
