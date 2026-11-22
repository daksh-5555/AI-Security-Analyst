"""Migration checks for the ``potential`` finding status (M2)."""

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError

from app.db.session import create_db_engine

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TIMESTAMP = "2026-01-01 00:00:00.000000"
ASSESSMENT_ID = "a" * 32
FINDING_ID = "b" * 32
EVIDENCE_ID = "c" * 32


def make_config(database_url: str) -> Config:
    config = Config(str(PROJECT_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


def _seed_finding(engine: Engine, *, finding_id: str, status: str, position: int) -> None:
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO assessment_findings (id, assessment_id, position, title, "
                "category, severity, status, confidence, summary, created_at, updated_at) "
                "VALUES (:id, :assessment, :position, 't', 'c', 'high', :status, 0.5, "
                "'s', :ts, :ts)"
            ),
            {
                "id": finding_id,
                "assessment": ASSESSMENT_ID,
                "position": position,
                "status": status,
                "ts": TIMESTAMP,
            },
        )


def _setup(tmp_path: Path) -> tuple[Config, Engine]:
    database_url = f"sqlite:///{(tmp_path / 'potential.db').as_posix()}"
    config = make_config(database_url)
    command.upgrade(config, "0014")
    engine = create_db_engine(database_url)
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO assessment_jobs (id, assessment_type, status, created_at, "
                "updated_at) VALUES (:id, 'repository', 'queued', :ts, :ts)"
            ),
            {"id": ASSESSMENT_ID, "ts": TIMESTAMP},
        )
    _seed_finding(engine, finding_id=FINDING_ID, status="not_tested", position=0)
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO finding_evidence (id, finding_id, position, description, "
                "source, details, created_at) VALUES (:id, :finding, 0, 'd', 'src', "
                "'{\"k\": 1}', :ts)"
            ),
            {"id": EVIDENCE_ID, "finding": FINDING_ID, "ts": TIMESTAMP},
        )
    return config, engine


def _counts(engine: Engine) -> tuple[int, int]:
    with engine.connect() as connection:
        findings = connection.execute(text("SELECT COUNT(*) FROM assessment_findings")).scalar()
        evidence = connection.execute(text("SELECT COUNT(*) FROM finding_evidence")).scalar()
    return findings, evidence


def test_migration_0015_follows_0014() -> None:
    script = ScriptDirectory.from_config(make_config("sqlite://"))
    revision = script.get_revision("0015")
    assert revision is not None
    assert revision.down_revision == "0014"
    assert script.get_heads() == ["0022"]


def test_upgrade_allows_potential_and_preserves_existing_rows(tmp_path: Path) -> None:
    config, engine = _setup(tmp_path)
    try:
        with pytest.raises(IntegrityError):
            _seed_finding(engine, finding_id="d" * 32, status="potential", position=1)

        command.upgrade(config, "0015")

        assert _counts(engine) == (1, 1)
        _seed_finding(engine, finding_id="d" * 32, status="potential", position=1)
        with pytest.raises(IntegrityError):
            _seed_finding(engine, finding_id="e" * 32, status="maybe", position=2)
        with engine.connect() as connection:
            assert connection.execute(text("PRAGMA foreign_key_check")).fetchall() == []
    finally:
        engine.dispose()


def test_downgrade_refuses_while_potential_findings_exist(tmp_path: Path) -> None:
    config, engine = _setup(tmp_path)
    try:
        command.upgrade(config, "0015")
        _seed_finding(engine, finding_id="d" * 32, status="potential", position=1)

        with pytest.raises(RuntimeError, match="potential"):
            command.downgrade(config, "0014")
        assert _counts(engine) == (2, 1)

        with engine.begin() as connection:
            connection.execute(text("DELETE FROM assessment_findings WHERE status = 'potential'"))
        command.downgrade(config, "0014")
        assert _counts(engine) == (1, 1)
        command.upgrade(config, "0015")
        assert _counts(engine) == (1, 1)
    finally:
        engine.dispose()
