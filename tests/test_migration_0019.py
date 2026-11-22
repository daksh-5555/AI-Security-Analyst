"""Migration 0019: advisory finding explanations (M9)."""

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
A, R, F, X = "a" * 32, "b" * 32, "c" * 32, "d" * 32


def make_config(url: str) -> Config:
    config = Config(str(PROJECT_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", url)
    return config


def insert_explanation(conn, status: str = "available") -> None:
    conn.execute(
        text(
            "INSERT INTO finding_explanations (id, assessment_id, finding_id, status, provider, "
            "model, prompt_template_version, supplied_evidence_ids, created_at) "
            "VALUES (:x, :a, :f, :s, 'fake', 'm', 'finding-explanation/1', '[]', :ts)"
        ),
        {"x": X, "a": A, "f": F, "s": status, "ts": TS},
    )


@pytest.fixture
def migrated(tmp_path: Path):
    url = f"sqlite:///{(tmp_path / 'explanations.db').as_posix()}"
    config = make_config(url)
    command.upgrade(config, "0019")
    engine = create_db_engine(url)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO assessment_jobs (id, assessment_type, status, created_at, updated_at) "
                "VALUES (:a, 'repository', 'queued', :ts, :ts)"
            ),
            {"a": A, "ts": TS},
        )
        conn.execute(
            text(
                "INSERT INTO analysis_runs (id, assessment_id, status, created_at, started_at) "
                "VALUES (:r, :a, 'completed', :ts, :ts)"
            ),
            {"r": R, "a": A, "ts": TS},
        )
        conn.execute(
            text(
                "INSERT INTO assessment_findings (id, assessment_id, analysis_run_id, position, "
                "title, category, severity, status, confidence, summary, created_at, updated_at) "
                "VALUES (:f, :a, :r, 0, 't', 'c', 'low', 'not_tested', 0.5, 's', :ts, :ts)"
            ),
            {"f": F, "a": A, "r": R, "ts": TS},
        )
    try:
        yield config, engine
    finally:
        engine.dispose()


def test_0019_revision_chain() -> None:
    script = ScriptDirectory.from_config(make_config("sqlite://"))
    assert script.get_revision("0019").down_revision == "0018"
    assert script.get_heads() == ["0022"]


def test_table_constraints_and_cascade(migrated) -> None:
    _config, engine = migrated
    assert "finding_explanations" in inspect(engine).get_table_names()
    with engine.begin() as conn:
        insert_explanation(conn)
        tokens = conn.execute(
            text("SELECT input_tokens + output_tokens FROM finding_explanations")
        ).scalar_one()
        assert tokens == 0
    with pytest.raises(IntegrityError), engine.begin() as conn:
        conn.execute(text("DELETE FROM finding_explanations"))
        insert_explanation(conn, status="confirmed")  # only available/unavailable
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM assessment_findings WHERE id = :f"), {"f": F})
        remaining = conn.execute(text("SELECT COUNT(*) FROM finding_explanations")).scalar_one()
    assert remaining == 0  # explanations go with their finding


def test_downgrade_guard_and_round_trip(migrated) -> None:
    config, engine = migrated
    with engine.begin() as conn:
        insert_explanation(conn)
    with pytest.raises(RuntimeError, match="0019"):
        command.downgrade(config, "0018")
    assert "finding_explanations" in inspect(engine).get_table_names()

    with engine.begin() as conn:
        conn.execute(text("DELETE FROM finding_explanations"))
    command.downgrade(config, "0018")
    assert "finding_explanations" not in inspect(engine).get_table_names()
    with engine.connect() as conn:
        assert conn.execute(text("SELECT COUNT(*) FROM assessment_findings")).scalar_one() == 1
    command.upgrade(config, "0019")
    assert "finding_explanations" in inspect(engine).get_table_names()
