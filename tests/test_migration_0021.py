"""Migration 0021: explanation retrieval provenance (M11)."""

from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import inspect

from app.db.session import create_db_engine

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def make_config(url: str) -> Config:
    config = Config(str(PROJECT_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", url)
    return config


def test_0021_revision_chain() -> None:
    script = ScriptDirectory.from_config(make_config("sqlite://"))
    assert script.get_revision("0021").down_revision == "0020"
    assert script.get_heads() == ["0022"]


def test_round_trip(tmp_path: Path) -> None:
    url = f"sqlite:///{(tmp_path / 'retrieval.db').as_posix()}"
    config = make_config(url)
    command.upgrade(config, "0021")
    engine = create_db_engine(url)
    try:
        columns = {c["name"]: c for c in inspect(engine).get_columns("finding_explanations")}
        assert columns["retrieval"]["nullable"] is True
        command.downgrade(config, "0020")
        assert "retrieval" not in {
            c["name"] for c in inspect(engine).get_columns("finding_explanations")
        }
        command.upgrade(config, "0021")
    finally:
        engine.dispose()
