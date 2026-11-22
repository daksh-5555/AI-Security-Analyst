"""Migration round-trip checks for the terminal analysis-run audit values."""

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
TIMESTAMP = "2026-01-01 00:00:00.000000"

AUDIT_INDEXES = {
    "ix_audit_events_assessment_id_occurred_at": ["assessment_id", "occurred_at"],
    "ix_audit_events_actor_user_id_occurred_at": ["actor_user_id", "occurred_at"],
    "ix_audit_events_action_occurred_at": ["action", "occurred_at"],
    "ix_audit_events_occurred_at": ["occurred_at"],
}

INSERT_AUDIT_EVENT = text(
    "INSERT INTO audit_events ("
    "id, occurred_at, resource_type, action, outcome, context"
    ") VALUES (:id, :occurred_at, 'analysis_run', :action, :outcome, NULL)"
)


def make_config(database_url: str) -> Config:
    config = Config(str(PROJECT_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


def insert_event(
    engine: Engine,
    *,
    event_id: str,
    action: str,
    outcome: str,
) -> None:
    with engine.begin() as connection:
        connection.execute(
            INSERT_AUDIT_EVENT,
            {
                "id": event_id,
                "occurred_at": TIMESTAMP,
                "action": action,
                "outcome": outcome,
            },
        )


def test_migration_0013_follows_0012() -> None:
    script = ScriptDirectory.from_config(make_config("sqlite://"))

    revision = script.get_revision("0013")

    assert revision is not None
    assert revision.down_revision == "0012"
    assert script.get_heads() == ["0022"]


def test_migration_0013_downgrade_blocks_while_terminal_audit_rows_exist(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "terminal-audit-downgrade.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    config = make_config(database_url)

    command.upgrade(config, "head")

    engine = create_db_engine(database_url)
    try:
        insert_event(
            engine,
            event_id="e" * 32,
            action="analysis_run.failed",
            outcome="failure",
        )
    finally:
        engine.dispose()

    with pytest.raises(RuntimeError, match="terminal analysis-run audit"):
        command.downgrade(config, "0012")

    engine = create_db_engine(database_url)
    try:
        with engine.connect() as connection:
            version = connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one()
            temporary_tables = connection.execute(
                text(
                    "SELECT name FROM sqlite_master WHERE type = 'table' "
                    "AND name = '_alembic_tmp_audit_events'"
                )
            ).all()
            terminal_rows = connection.execute(
                text(
                    "SELECT COUNT(*) FROM audit_events "
                    "WHERE action = 'analysis_run.failed' AND outcome = 'failure'"
                )
            ).scalar_one()
        indexes = {index["name"] for index in inspect(engine).get_indexes("audit_events")}
        foreign_keys = {
            foreign_key["name"]: foreign_key
            for foreign_key in inspect(engine).get_foreign_keys("audit_events")
        }
    finally:
        engine.dispose()

    # The failed downgrade must leave the schema version, durable audit row,
    # indexes, and foreign keys untouched, and must not leave batch-DDL residue.
    assert version == "0013"
    assert temporary_tables == []
    assert terminal_rows == 1
    assert set(AUDIT_INDEXES) <= indexes
    assert foreign_keys["fk_audit_events_actor_user_id"]["referred_table"] == "users"
    assert foreign_keys["fk_audit_events_assessment_id"]["referred_table"] == "assessment_jobs"
    assert foreign_keys["fk_audit_events_actor_user_id"]["options"]["ondelete"] == "SET NULL"
    assert foreign_keys["fk_audit_events_assessment_id"]["options"]["ondelete"] == "SET NULL"

    engine = create_db_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text("DELETE FROM audit_events WHERE action = 'analysis_run.failed'")
            )
    finally:
        engine.dispose()

    command.downgrade(config, "0012")

    engine = create_db_engine(database_url)
    try:
        with engine.connect() as connection:
            schema = connection.exec_driver_sql(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'audit_events'"
            ).scalar_one()
        indexes = {index["name"] for index in inspect(engine).get_indexes("audit_events")}
        foreign_keys = {
            foreign_key["name"] for foreign_key in inspect(engine).get_foreign_keys("audit_events")
        }

        # Every pre-0013 action and outcome remains representable.
        for event_id, action, outcome in (
            ("1" * 32, "assessment.created", "success"),
            ("2" * 32, "assessment.access_denied", "denied"),
            ("3" * 32, "assessment.lifecycle_changed", "success"),
            ("4" * 32, "assessment.lifecycle_denied", "denied"),
            ("5" * 32, "repository_target.created", "success"),
            ("6" * 32, "analysis_run.started", "success"),
        ):
            insert_event(
                engine,
                event_id=event_id,
                action=action,
                outcome=outcome,
            )
        with engine.connect() as connection:
            assert connection.execute(text("SELECT COUNT(*) FROM audit_events")).scalar_one() == 6
    finally:
        engine.dispose()

    assert "analysis_run.completed" not in schema
    assert "analysis_run.failed" not in schema
    assert "'failure'" not in schema
    assert set(AUDIT_INDEXES) <= indexes
    assert {"fk_audit_events_actor_user_id", "fk_audit_events_assessment_id"} <= foreign_keys

    command.upgrade(config, "head")

    engine = create_db_engine(database_url)
    try:
        insert_event(
            engine,
            event_id="7" * 32,
            action="analysis_run.completed",
            outcome="success",
        )
        insert_event(
            engine,
            event_id="8" * 32,
            action="analysis_run.failed",
            outcome="failure",
        )

        with engine.connect() as connection:
            schema = connection.exec_driver_sql(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'audit_events'"
            ).scalar_one()
            assert connection.execute(text("SELECT COUNT(*) FROM audit_events")).scalar_one() == 8
        indexes = {index["name"] for index in inspect(engine).get_indexes("audit_events")}
        foreign_keys = {
            foreign_key["name"] for foreign_key in inspect(engine).get_foreign_keys("audit_events")
        }

        with pytest.raises(IntegrityError, match="audit_action"):
            insert_event(
                engine,
                event_id="9" * 32,
                action="analysis_run.unknown",
                outcome="success",
            )
    finally:
        engine.dispose()

    assert "analysis_run.completed" in schema
    assert "analysis_run.failed" in schema
    assert "'failure'" in schema
    assert set(AUDIT_INDEXES) <= indexes
    assert {"fk_audit_events_actor_user_id", "fk_audit_events_assessment_id"} <= foreign_keys


def test_migration_0013_extends_constraints_and_preserves_history(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "terminal-audit-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    config = make_config(database_url)

    command.upgrade(config, "0012")

    engine = create_db_engine(database_url)
    try:
        insert_event(
            engine,
            event_id="a" * 32,
            action="analysis_run.started",
            outcome="success",
        )
    finally:
        engine.dispose()

    command.upgrade(config, "head")

    engine = create_db_engine(database_url)
    try:
        # Existing audit history from the previous constraint set survives.
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT COUNT(*) FROM audit_events WHERE action = 'analysis_run.started'")
                ).scalar_one()
                == 1
            )

        insert_event(
            engine,
            event_id="b" * 32,
            action="analysis_run.completed",
            outcome="success",
        )
        insert_event(
            engine,
            event_id="c" * 32,
            action="analysis_run.failed",
            outcome="failure",
        )

        indexes = {index["name"]: index for index in inspect(engine).get_indexes("audit_events")}
        for name, expected_columns in AUDIT_INDEXES.items():
            assert indexes[name]["column_names"] == expected_columns

        with pytest.raises(IntegrityError, match="audit_action"):
            insert_event(
                engine,
                event_id="d" * 32,
                action="analysis_run.unknown",
                outcome="success",
            )
    finally:
        engine.dispose()

    # Downgrading must restore the narrower constraints; the terminal rows are
    # removed first because they are not representable under the old schema.
    engine = create_db_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text("DELETE FROM audit_events WHERE action IN (:completed, :failed)"),
                {
                    "completed": "analysis_run.completed",
                    "failed": "analysis_run.failed",
                },
            )
    finally:
        engine.dispose()

    command.downgrade(config, "0012")

    engine = create_db_engine(database_url)
    try:
        with engine.connect() as connection:
            schema = connection.exec_driver_sql(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'audit_events'"
            ).scalar_one()
        assert "analysis_run.completed" not in schema
        assert "analysis_run.failed" not in schema
        assert "'failure'" not in schema
        indexes = {index["name"] for index in inspect(engine).get_indexes("audit_events")}
        assert set(AUDIT_INDEXES) <= indexes
    finally:
        engine.dispose()

    command.upgrade(config, "head")

    engine = create_db_engine(database_url)
    try:
        with engine.connect() as connection:
            assert connection.execute(text("SELECT COUNT(*) FROM audit_events")).scalar_one() == 1
    finally:
        engine.dispose()
