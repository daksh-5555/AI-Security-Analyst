"""Dialect-aware failure-injection triggers for rollback tests (M13).

The rollback tests force a database write to fail. SQLite and PostgreSQL need
different DDL for that; these helpers emit the right form for the connection.
"""

from __future__ import annotations

from sqlalchemy.engine import Connection


def create_failure_trigger(
    connection: Connection,
    name: str,
    *,
    table: str,
    event: str,
    message: str,
    when: str | None = None,
) -> None:
    """Make every matching INSERT/UPDATE on ``table`` fail with ``message``.

    ``when`` is a condition over ``NEW`` (for example ``NEW.status = 'failed'``).
    """
    if connection.dialect.name == "postgresql":
        condition = when or "TRUE"
        connection.exec_driver_sql(
            f"CREATE FUNCTION {name}_fn() RETURNS trigger LANGUAGE plpgsql AS $$ "
            # SQLSTATE 23000 (integrity violation) matches SQLite's RAISE(ABORT),
            # which surfaces as IntegrityError, so both dialects inject the same
            # kind of failure.
            f"BEGIN IF {condition} THEN RAISE EXCEPTION '{message}' "
            "USING ERRCODE = 'integrity_constraint_violation'; END IF; RETURN NEW; END $$"
        )
        connection.exec_driver_sql(
            f"CREATE TRIGGER {name} BEFORE {event} ON {table} "
            f"FOR EACH ROW EXECUTE FUNCTION {name}_fn()"
        )
        return
    clause = f"WHEN {when} " if when else ""
    connection.exec_driver_sql(
        f"CREATE TRIGGER {name} BEFORE {event} ON {table} {clause}"
        f"BEGIN SELECT RAISE(ABORT, '{message}'); END"
    )


def drop_failure_trigger(connection: Connection, name: str, *, table: str) -> None:
    if connection.dialect.name == "postgresql":
        connection.exec_driver_sql(f"DROP TRIGGER IF EXISTS {name} ON {table}")
        connection.exec_driver_sql(f"DROP FUNCTION IF EXISTS {name}_fn()")
        return
    connection.exec_driver_sql(f"DROP TRIGGER IF EXISTS {name}")
