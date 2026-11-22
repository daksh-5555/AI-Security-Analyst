"""Migration 0022: web_target_lab_sessions and lab-session audit actions (M15)."""

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


def insert_session(conn, session_id: str) -> None:
    conn.execute(
        text(
            "INSERT INTO web_target_lab_sessions (id, assessment_id, username, login_path, "
            "cookie_header, established_at) "
            "VALUES (:i, :a, 'admin', '/login.php', 'PHPSESSID=x', :ts)"
        ),
        {"i": session_id, "a": A, "ts": TS},
    )


@pytest.fixture
def migrated(tmp_path: Path):
    url = f"sqlite:///{(tmp_path / 'lab.db').as_posix()}"
    config = make_config(url)
    command.upgrade(config, "0022")
    engine = create_db_engine(url)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO assessment_jobs (id, assessment_type, status, created_at, updated_at) "
                "VALUES (:a, 'web_security', 'queued', :ts, :ts)"
            ),
            {"a": A, "ts": TS},
        )
    try:
        yield config, engine
    finally:
        engine.dispose()


def test_0022_is_head() -> None:
    script = ScriptDirectory.from_config(make_config("sqlite://"))
    assert script.get_revision("0022").down_revision == "0021"
    assert script.get_heads() == ["0022"]


def test_one_session_per_assessment_and_audit_actions(migrated) -> None:
    _config, engine = migrated
    assert "web_target_lab_sessions" in inspect(engine).get_table_names()
    with engine.begin() as conn:
        insert_session(conn, "b" * 32)
    with pytest.raises(IntegrityError), engine.begin() as conn:
        insert_session(conn, "c" * 32)  # unique assessment_id
    with engine.begin() as conn:
        for action in ("web_target.lab_session_established", "web_target.lab_session_cleared"):
            conn.execute(
                text(
                    "INSERT INTO audit_events (id, occurred_at, resource_type, action, outcome) "
                    "VALUES (:i, :ts, 'assessment_target', :ac, 'success')"
                ),
                {"i": action[-20:].ljust(32, "0")[:32], "ts": TS, "ac": action},
            )


def test_downgrade_guard_and_round_trip(migrated) -> None:
    config, engine = migrated
    with engine.begin() as conn:
        insert_session(conn, "b" * 32)
    with pytest.raises(RuntimeError, match="0022"):
        command.downgrade(config, "0021")
    assert "web_target_lab_sessions" in inspect(engine).get_table_names()
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM web_target_lab_sessions"))
    command.downgrade(config, "0021")
    assert "web_target_lab_sessions" not in inspect(engine).get_table_names()
    command.upgrade(config, "0022")
    assert "web_target_lab_sessions" in inspect(engine).get_table_names()
