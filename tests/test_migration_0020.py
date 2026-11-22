"""Migration 0020: bounded assessment workflows (M10)."""

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError

from app.db.session import create_db_engine

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TS = "2026-01-01 00:00:00.000000"
A = "a" * 32


def make_config(url: str) -> Config:
    config = Config(str(PROJECT_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", url)
    return config


def insert_workflow(conn, workflow_id: str, status: str) -> None:
    conn.execute(
        text(
            "INSERT INTO assessment_workflows (id, assessment_id, status, graph_version, "
            "current_node, options, state, created_at, updated_at) VALUES "
            "(:w, :a, :s, 'assessment-workflow/1', 'load_assessment', '{}', '{}', :ts, :ts)"
        ),
        {"w": workflow_id, "a": A, "s": status, "ts": TS},
    )


@pytest.fixture
def migrated(tmp_path: Path):
    url = f"sqlite:///{(tmp_path / 'workflows.db').as_posix()}"
    config = make_config(url)
    command.upgrade(config, "0020")
    engine = create_db_engine(url)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO assessment_jobs (id, assessment_type, status, created_at, updated_at) "
                "VALUES (:a, 'repository', 'queued', :ts, :ts)"
            ),
            {"a": A, "ts": TS},
        )
    try:
        yield config, engine
    finally:
        engine.dispose()


def test_0020_revision_chain() -> None:
    script = ScriptDirectory.from_config(make_config("sqlite://"))
    assert script.get_revision("0020").down_revision == "0019"
    assert script.get_heads() == ["0022"]


def test_one_active_workflow_per_assessment(migrated) -> None:
    _config, engine = migrated
    with engine.begin() as conn:
        insert_workflow(conn, "b" * 32, "awaiting_approval")
    with pytest.raises(IntegrityError), engine.begin() as conn:
        insert_workflow(conn, "c" * 32, "running")
    with engine.begin() as conn:
        conn.execute(text("UPDATE assessment_workflows SET status = 'completed'"))
        insert_workflow(conn, "c" * 32, "running")
    with pytest.raises(IntegrityError), engine.begin() as conn:
        insert_workflow(conn, "d" * 32, "paused")  # status CHECK


def test_events_are_ordered_and_unique(migrated) -> None:
    _config, engine = migrated
    with engine.begin() as conn:
        insert_workflow(conn, "b" * 32, "running")
        statement = text(
            "INSERT INTO workflow_events (id, workflow_id, sequence, node, outcome, attempt, "
            "occurred_at) VALUES (:i, :w, 1, 'load_assessment', 'completed', 1, :ts)"
        )
        conn.execute(statement, {"i": "e" * 32, "w": "b" * 32, "ts": TS})
    with pytest.raises(IntegrityError), engine.begin() as conn:
        conn.execute(statement, {"i": "f" * 32, "w": "b" * 32, "ts": TS})


def test_downgrade_guard_and_round_trip(migrated) -> None:
    config, engine = migrated
    with engine.begin() as conn:
        insert_workflow(conn, "b" * 32, "completed")
    with pytest.raises(RuntimeError, match="0020"):
        command.downgrade(config, "0019")
    assert "assessment_workflows" in inspect(engine).get_table_names()
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM assessment_workflows"))
    command.downgrade(config, "0019")
    tables = set(inspect(engine).get_table_names())
    assert not {"assessment_workflows", "workflow_events"} & tables
    command.upgrade(config, "0020")
    assert "workflow_events" in inspect(engine).get_table_names()
