"""PostgreSQL migration chain and constraints (M13). Runs only with TEST_POSTGRES_URL."""

from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text

from app.db.session import create_db_engine

PROJECT_ROOT = Path(__file__).resolve().parents[1]
URL = os.environ.get("TEST_POSTGRES_URL")

pytestmark = pytest.mark.skipif(not URL, reason="set TEST_POSTGRES_URL to run PostgreSQL tests")


@pytest.fixture
def schema_config():
    assert URL is not None
    schema = f"m_{uuid.uuid4().hex[:16]}"
    admin = create_db_engine(URL)
    with admin.begin() as conn:
        conn.execute(text(f'CREATE SCHEMA "{schema}"'))
    url = f"{URL}{'&' if '?' in URL else '?'}options=-csearch_path%3D{schema}"
    config = Config(str(PROJECT_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    engine = create_db_engine(url)
    try:
        yield config, engine, schema
    finally:
        engine.dispose()
        with admin.begin() as conn:
            conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()


def test_full_chain_round_trip_without_drift(schema_config) -> None:
    config, engine, _schema = schema_config
    command.upgrade(config, "head")
    command.check(config)  # models and migrations agree on PostgreSQL
    command.downgrade(config, "base")
    with engine.connect() as conn:
        remaining = conn.execute(
            text("SELECT count(*) FROM pg_tables WHERE schemaname = current_schema()")
        ).scalar_one()
    assert remaining == 1  # only alembic_version
    command.upgrade(config, "head")


def test_partial_unique_indexes_keep_their_predicates(schema_config) -> None:
    config, engine, _schema = schema_config
    command.upgrade(config, "head")
    with engine.connect() as conn:
        indexes = dict(
            conn.execute(
                text(
                    "SELECT indexname, indexdef FROM pg_indexes WHERE schemaname = current_schema()"
                )
            ).all()
        )
    runs = indexes["uq_analysis_runs_active_assessment"]
    assert "UNIQUE" in runs and "queued" in runs and "running" in runs
    workflows = indexes["uq_assessment_workflows_active_assessment"]
    assert "UNIQUE" in workflows and "awaiting_approval" in workflows


def test_check_constraints_are_enforced(schema_config) -> None:
    config, engine, _schema = schema_config
    command.upgrade(config, "head")
    with engine.connect() as conn:
        constraints = {
            row[0]
            for row in conn.execute(
                text(
                    "SELECT conname FROM pg_constraint c JOIN pg_namespace n "
                    "ON n.oid = c.connamespace WHERE n.nspname = current_schema() "
                    "AND c.contype = 'c'"
                )
            )
        }
    for name in ("analysis_run_status", "audit_action", "audit_resource_type", "workflow_status"):
        assert name in constraints, name
