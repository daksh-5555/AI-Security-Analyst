"""Migration 0016: assessment targets, backfill, and audit constraint extension (M4)."""

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
TS = "2026-01-01 00:00:00.000000"
OWNER = "1" * 32
OWNED_ASSESSMENT, ORPHAN_ASSESSMENT = "a" * 32, "b" * 32
OWNED_TARGET, ORPHAN_TARGET = "c" * 32, "d" * 32


def make_config(url: str) -> Config:
    config = Config(str(PROJECT_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", url)
    return config


def _seed(engine: Engine) -> None:
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO users (id, email, email_normalized, password_hash, is_active, "
                "is_email_verified, created_at, updated_at) VALUES (:id, 'o@example.com', "
                "'o@example.com', 'x', 1, 1, :ts, :ts)"
            ),
            {"id": OWNER, "ts": TS},
        )
        for assessment_id, owner in ((OWNED_ASSESSMENT, OWNER), (ORPHAN_ASSESSMENT, None)):
            conn.execute(
                text(
                    "INSERT INTO assessment_jobs (id, owner_id, assessment_type, status, "
                    "created_at, updated_at) VALUES (:id, :owner, 'repository', 'queued', :ts, :ts)"
                ),
                {"id": assessment_id, "owner": owner, "ts": TS},
            )
        for target_id, assessment_id in (
            (OWNED_TARGET, OWNED_ASSESSMENT),
            (ORPHAN_TARGET, ORPHAN_ASSESSMENT),
        ):
            conn.execute(
                text(
                    "INSERT INTO repository_targets (id, assessment_id, source_kind, location, "
                    "created_at, updated_at) VALUES (:id, :a, 'local_path', :loc, :ts, :ts)"
                ),
                {
                    "id": target_id,
                    "a": assessment_id,
                    "loc": f"/srv/repositories/{target_id[:4]}",
                    "ts": TS,
                },
            )


@pytest.fixture
def migrated(tmp_path: Path):
    url = f"sqlite:///{(tmp_path / 'targets.db').as_posix()}"
    config = make_config(url)
    command.upgrade(config, "0015")
    engine = create_db_engine(url)
    _seed(engine)
    command.upgrade(config, "0016")
    try:
        yield config, engine
    finally:
        engine.dispose()


def _targets(engine: Engine) -> dict[str, tuple]:
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT repository_target_id, status, authorization_basis, created_by_user_id, "
                "target_type, canonical_target FROM assessment_targets"
            )
        ).fetchall()
    return {str(row[0]).replace("-", ""): tuple(row[1:]) for row in rows}


def test_migration_0016_follows_0015() -> None:
    script = ScriptDirectory.from_config(make_config("sqlite://"))
    assert script.get_revision("0016").down_revision == "0015"
    assert script.get_heads() == ["0022"]


def test_backfill_authorizes_owned_targets_and_blocks_orphans(migrated) -> None:
    _config, engine = migrated
    targets = _targets(engine)

    owned = targets[OWNED_TARGET]
    assert owned[0] == "authorized" and owned[1] == "legacy_backfill"
    assert str(owned[2]).replace("-", "") == OWNER
    assert owned[3] == "repository" and owned[4].startswith("/srv/repositories/")
    orphan = targets[ORPHAN_TARGET]
    assert orphan[0] == "pending_authorization" and orphan[1] is None and orphan[2] is None

    with engine.connect() as conn:
        assert conn.execute(text("SELECT COUNT(*) FROM repository_targets")).scalar() == 2
        assert conn.execute(text("PRAGMA foreign_key_check")).fetchall() == []


def test_constraints_after_upgrade(migrated) -> None:
    _config, engine = migrated
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO audit_events (id, occurred_at, resource_type, action, outcome) "
                "VALUES (:id, :ts, 'assessment_target', 'assessment_target.revoked', 'success')"
            ),
            {"id": "e" * 32, "ts": TS},
        )
    with pytest.raises(IntegrityError), engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO assessment_targets (id, assessment_id, target_type, "
                "canonical_target, status, created_at, updated_at) "
                "VALUES (:id, :a, 'repository', 'x', 'maybe', :ts, :ts)"
            ),
            {"id": "f" * 32, "a": OWNED_ASSESSMENT, "ts": TS},
        )
    with (
        pytest.raises(IntegrityError),
        engine.begin() as conn,
    ):  # one repository target per assessment
        conn.execute(
            text(
                "INSERT INTO assessment_targets (id, assessment_id, target_type, "
                "canonical_target, status, created_at, updated_at) "
                "VALUES (:id, :a, 'repository', 'x', 'authorized', :ts, :ts)"
            ),
            {"id": "9" * 32, "a": OWNED_ASSESSMENT, "ts": TS},
        )


def test_downgrade_refuses_while_target_audit_history_exists(migrated) -> None:
    config, engine = migrated
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO audit_events (id, occurred_at, resource_type, action, outcome) "
                "VALUES (:id, :ts, 'assessment_target', 'assessment_target.authorized', 'success')"
            ),
            {"id": "e" * 32, "ts": TS},
        )
    with pytest.raises(RuntimeError, match="0016"):
        command.downgrade(config, "0015")
    with engine.begin() as conn:
        assert conn.execute(text("SELECT COUNT(*) FROM assessment_targets")).scalar() == 2


def test_round_trip_without_target_audit_history(migrated) -> None:
    config, engine = migrated
    command.downgrade(config, "0015")
    with engine.connect() as conn:
        tables = {
            row[0]
            for row in conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))
        }
        assert "assessment_targets" not in tables
        assert conn.execute(text("SELECT COUNT(*) FROM repository_targets")).scalar() == 2
    command.upgrade(config, "0016")
    assert len(_targets(engine)) == 2
