from logging.config import fileConfig
from typing import Any

from alembic import context
from sqlalchemy import engine_from_config, event, pool
from sqlalchemy.engine import Engine

import app.models  # noqa: F401
from app.core.config import settings
from app.db.base import Base

config = context.config

if config.config_file_name is not None:
    # Do not disable application loggers when migrations run after app import.
    fileConfig(config.config_file_name, disable_existing_loggers=False)

if not config.get_main_option("sqlalchemy.url"):
    config.set_main_option("sqlalchemy.url", settings.database_url)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def _configure_sqlite_foreign_keys(
    dbapi_connection: Any,
    _connection_record: Any,
    *,
    enforce: bool,
) -> None:
    """Set SQLite foreign-key enforcement before Alembic opens a transaction.

    SQLite ignores ``PRAGMA foreign_keys`` changes made inside an active
    transaction, so the setting must happen on the raw DBAPI connection when it
    is created. The application engine enables enforcement independently; this
    listener only controls the short-lived migration connections.
    """
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute(f"PRAGMA foreign_keys={'ON' if enforce else 'OFF'}")
    finally:
        cursor.close()


def _verify_sqlite_foreign_keys(connectable: Engine) -> None:
    """Re-enable enforcement and assert the migrated database is consistent."""
    with connectable.connect() as verification_connection:
        enabled = verification_connection.exec_driver_sql("PRAGMA foreign_keys").scalar()
        if enabled != 1:
            raise RuntimeError("SQLite foreign-key enforcement was not restored after migration")

        violations = verification_connection.exec_driver_sql("PRAGMA foreign_key_check").fetchall()
        if violations:
            raise RuntimeError(
                f"SQLite foreign_key_check reported violations after migration: {violations!r}"
            )


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    is_sqlite = connectable.dialect.name == "sqlite"
    if is_sqlite:
        # Alembic's batch mode rebuilds tables by dropping the original table.
        # With enforcement on, SQLite would cascade-delete every dependent row
        # of the rebuilt parent (for example, the assessment children when
        # 0011 rebuilds assessment_jobs). Disable enforcement on each raw
        # migration connection before any transaction starts, then verify with
        # a fresh connection where enforcement is enabled again.
        enforcement = {"enabled": False}

        def configure_foreign_keys(
            dbapi_connection: Any,
            connection_record: Any,
        ) -> None:
            _configure_sqlite_foreign_keys(
                dbapi_connection,
                connection_record,
                enforce=enforcement["enabled"],
            )

        event.listen(connectable, "connect", configure_foreign_keys)

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=connection.dialect.name == "sqlite",
        )

        with context.begin_transaction():
            context.run_migrations()

        if is_sqlite:
            # NullPool creates a fresh DBAPI connection for the verification,
            # so the listener can now switch to enabling enforcement.
            enforcement["enabled"] = True
            _verify_sqlite_foreign_keys(connectable)


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
