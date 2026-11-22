# ADR-0016: PostgreSQL support

Status: accepted (M13). Date: 2026-11-17.

## Context

SQLite was the only database ever exercised. Several features rely on database
semantics that differ between SQLite and PostgreSQL:
- partial unique indexes for "one active run" and "one active workflow";
- conditional UPDATEs for claims and terminal transitions;
- the worker's running cap, documented in ADR-0011 as possibly exceeded by one
  on PostgreSQL;
- CHECK constraints from enum columns.

The owner installed PostgreSQL 16 locally and approved the `psycopg` driver.

## Decision

1. **Driver.** `psycopg` 3, through SQLAlchemy's `postgresql+psycopg` dialect.
   It is an optional extra (`pip install ".[postgres]"`); SQLite remains the
   default and needs nothing extra.
2. **Migrations.** All 21 migrations run unchanged on PostgreSQL: upgrade to
   head, `alembic check` with no drift, full downgrade to base, and re-upgrade.
   The SQLite-specific steps (batch mode, foreign-key pragmas) already applied
   only to SQLite.
3. **Exact claim cap on PostgreSQL.** `claim_next_run`:
   - takes a transaction-scoped advisory lock (`pg_advisory_xact_lock`), so the
     cap check and the claim are serialized across workers;
   - selects the candidate with `FOR UPDATE SKIP LOCKED`;
   - keeps the conditional UPDATE.

   The cap is now exact on both databases. The ADR-0011 caveat no longer
   applies.
4. **Tests on both databases.** Setting `TEST_POSTGRES_URL` runs the whole
   suite against PostgreSQL, giving each test its own throwaway schema;
   without it, SQLite is used as before.
   - Rollback tests use dialect-aware failure-injection triggers
     (`tests/db_triggers.py`). The PostgreSQL trigger raises SQLSTATE 23000, so
     both databases inject the same kind of failure.
   - Assertions on database error text accept either dialect's wording.
   - `tests/test_postgres_migrations.py` checks the chain, the partial-index
     predicates, and the named CHECK constraints on PostgreSQL. It skips
     without the server.

## Consequences

- PostgreSQL is verified locally (16.16, psycopg 3.3.9). It is not yet verified
  in CI or on other major versions.
- Process-local admission control (rate limits, synchronous-run slots) is
  still per process. The database-backed limits (worker cap, async per-user
  quota, unique indexes) are deployment-wide on both databases.
- Tests that exercise SQLite-only behaviour (file-based migration tests,
  `sqlite_master` inspection) still use their own SQLite databases in both
  modes, as intended.
