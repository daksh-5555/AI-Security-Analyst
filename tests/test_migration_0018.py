"""Migration 0018: queued/cancelled run states, lease and progress columns (M8)."""

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
A, R1, R2 = "a" * 32, "b" * 32, "c" * 32
NEW_COLUMNS = {
    "requested_by_user_id",
    "lease_owner",
    "lease_expires_at",
    "stage",
    "attempts",
    "error_code",
    "summary_snapshot",
}


def make_config(url: str) -> Config:
    config = Config(str(PROJECT_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", url)
    return config


def index_sql(engine) -> str:
    with engine.connect() as conn:
        return conn.exec_driver_sql(
            "SELECT sql FROM sqlite_master WHERE name = 'uq_analysis_runs_active_assessment'"
        ).scalar_one()


def insert_run(conn, run_id: str, status: str) -> None:
    conn.execute(
        text(
            "INSERT INTO analysis_runs (id, assessment_id, status, created_at, started_at) "
            "VALUES (:r, :a, :s, :ts, :ts)"
        ),
        {"r": run_id, "a": A, "s": status, "ts": TS},
    )


@pytest.fixture
def migrated(tmp_path: Path):
    url = f"sqlite:///{(tmp_path / 'durable.db').as_posix()}"
    config = make_config(url)
    command.upgrade(config, "0017")
    engine = create_db_engine(url)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO assessment_jobs (id, assessment_type, status, created_at, updated_at) "
                "VALUES (:a, 'repository', 'queued', :ts, :ts)"
            ),
            {"a": A, "ts": TS},
        )
        insert_run(conn, R1, "completed")
    command.upgrade(config, "0018")
    try:
        yield config, engine
    finally:
        engine.dispose()


def test_0018_revision_chain() -> None:
    script = ScriptDirectory.from_config(make_config("sqlite://"))
    assert script.get_revision("0018").down_revision == "0017"
    assert script.get_heads() == ["0022"]


def test_upgrade_adds_columns_and_keeps_existing_runs(migrated) -> None:
    _config, engine = migrated
    columns = {c["name"]: c for c in inspect(engine).get_columns("analysis_runs")}
    assert NEW_COLUMNS <= set(columns)
    assert all(columns[name]["nullable"] for name in NEW_COLUMNS - {"attempts"})
    with engine.connect() as conn:
        row = conn.execute(text("SELECT status, attempts FROM analysis_runs")).one()
    assert tuple(row) == ("completed", 0)  # attempts server default
    assert "WHERE status IN ('queued', 'running')" in index_sql(engine)


def test_new_states_are_accepted_and_one_active_run_is_enforced(migrated) -> None:
    _config, engine = migrated
    with engine.begin() as conn:
        insert_run(conn, R2, "queued")
    with pytest.raises(IntegrityError), engine.begin() as conn:
        insert_run(conn, "d" * 32, "running")  # queued already counts as active
    with engine.begin() as conn:
        conn.execute(text("UPDATE analysis_runs SET status = 'cancelled' WHERE id = :r"), {"r": R2})
        insert_run(conn, "d" * 32, "running")
    with pytest.raises(IntegrityError), engine.begin() as conn:
        insert_run(conn, "e" * 32, "paused")  # status CHECK still enforced


def test_downgrade_refuses_to_drop_queue_history(migrated) -> None:
    config, engine = migrated
    with engine.begin() as conn:
        insert_run(conn, R2, "queued")
    with pytest.raises(RuntimeError, match="0018"):
        command.downgrade(config, "0017")
    # Nothing was changed by the refused downgrade.
    assert "WHERE status IN ('queued', 'running')" in index_sql(engine)

    with engine.begin() as conn:
        conn.execute(text("DELETE FROM analysis_runs WHERE id = :r"), {"r": R2})
        conn.execute(
            text(
                "INSERT INTO audit_events (id, occurred_at, resource_type, action, outcome) "
                "VALUES (:i, :ts, 'analysis_run', 'analysis_run.cancelled', 'success')"
            ),
            {"i": "f" * 32, "ts": TS},
        )
    with pytest.raises(RuntimeError, match="audit"):
        command.downgrade(config, "0017")


def test_clean_round_trip(migrated) -> None:
    config, engine = migrated
    command.downgrade(config, "0017")
    columns = {c["name"] for c in inspect(engine).get_columns("analysis_runs")}
    assert not NEW_COLUMNS & columns
    assert "WHERE status = 'running'" in index_sql(engine)
    with engine.connect() as conn:
        assert conn.execute(text("SELECT COUNT(*) FROM analysis_runs")).scalar_one() == 1
    command.upgrade(config, "0018")
    assert "WHERE status IN ('queued', 'running')" in index_sql(engine)
