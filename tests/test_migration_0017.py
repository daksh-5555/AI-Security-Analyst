"""Migration 0017: normalized evidence and finding identity fields (M7)."""

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import text

from app.db.session import create_db_engine

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TS = "2026-01-01 00:00:00.000000"
A, R, F, E = "a" * 32, "b" * 32, "c" * 32, "d" * 32


def make_config(url: str) -> Config:
    config = Config(str(PROJECT_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", url)
    return config


@pytest.fixture
def migrated(tmp_path: Path):
    url = f"sqlite:///{(tmp_path / 'evidence.db').as_posix()}"
    config = make_config(url)
    command.upgrade(config, "0016")
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
        conn.execute(
            text(
                "INSERT INTO finding_evidence (id, finding_id, position, description, source, "
                "created_at) VALUES (:e, :f, 0, 'd', 'src', :ts)"
            ),
            {"e": E, "f": F, "ts": TS},
        )
    command.upgrade(config, "0017")
    try:
        yield config, engine
    finally:
        engine.dispose()


def test_migration_0017_is_head() -> None:
    script = ScriptDirectory.from_config(make_config("sqlite://"))
    assert script.get_revision("0017").down_revision == "0016"
    assert script.get_heads() == ["0022"]


def test_upgrade_preserves_findings_and_backfills_seen_times(migrated) -> None:
    _config, engine = migrated
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT first_seen_at, last_seen_at, created_at, rule_id FROM assessment_findings")
        ).one()
        assert row[0] == row[1] == row[2] and row[3] is None
        assert conn.execute(text("SELECT COUNT(*) FROM finding_evidence")).scalar() == 1
        assert conn.execute(text("PRAGMA foreign_key_check")).fetchall() == []


def test_downgrade_refuses_while_normalized_evidence_exists(migrated) -> None:
    config, engine = migrated
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO evidence_items (id, assessment_id, analysis_run_id, evidence_key, "
                "source_type, tool_name, tool_version, rule_id, method, summary, observed_at, "
                "created_at) VALUES (:id, :a, :r, 'k', 'repository', 't', '1', 'r', 'm', 's', "
                ":ts, :ts)"
            ),
            {"id": "e" * 32, "a": A, "r": R, "ts": TS},
        )
    with pytest.raises(RuntimeError, match="0017"):
        command.downgrade(config, "0016")
    with engine.connect() as conn:
        assert conn.execute(text("SELECT COUNT(*) FROM evidence_items")).scalar() == 1


def test_round_trip_without_normalized_evidence(migrated) -> None:
    config, engine = migrated
    command.downgrade(config, "0016")
    with engine.connect() as conn:
        columns = {row[1] for row in conn.execute(text("PRAGMA table_info(assessment_findings)"))}
        assert "identity_key" not in columns
        assert conn.execute(text("SELECT COUNT(*) FROM assessment_findings")).scalar() == 1
        assert conn.execute(text("SELECT COUNT(*) FROM finding_evidence")).scalar() == 1
    command.upgrade(config, "0017")
