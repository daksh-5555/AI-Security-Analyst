# M13 — PostgreSQL Support

Status: **complete. This is the last blueprint milestone; awaiting owner review.**

## Environment

- PostgreSQL **16.16** (Homebrew, local), database `aisa_test`, installed by the owner.
- Driver **psycopg 3.3.9** (approved by the owner), installed only in the scratch
  test environment and declared as the optional extra `[postgres]`.
- SQLAlchemy 2.1.8, dialect `postgresql+psycopg`.

## What changed

| Area | Change |
| --- | --- |
| Worker claim | `claim_next_run` on PostgreSQL takes a transaction-scoped advisory lock, so the cap check and the claim are serialized, and selects the candidate with `FOR UPDATE SKIP LOCKED`. The running cap is now exact (it could previously be exceeded by one; ADR-0011 caveat resolved). SQLite path unchanged |
| Test harness | `TEST_POSTGRES_URL` switches `db_engine` to a fresh schema per test, dropped afterwards; SQLite remains the default |
| Rollback tests | `tests/db_triggers.py`: dialect-aware failure-injection triggers, replacing 10 SQLite-only `CREATE TRIGGER … RAISE(ABORT)` statements. PostgreSQL raises SQLSTATE 23000, the same kind of failure as SQLite |
| Assertions | Two `UNIQUE constraint failed` message matches also accept PostgreSQL's constraint-name wording; the behaviour tested is identical |
| New tests | `tests/test_postgres_migrations.py` (3; chain round trip with no drift, partial-index predicates, named CHECK constraints; skipped without PostgreSQL); `test_claim_cap_is_exact_under_concurrent_workers` (8 workers, 6 queued runs, cap 2) |
| Packaging | `pyproject.toml`: optional extra `postgres = ["psycopg[binary]>=3.2,<4"]` |
| Docs | ADR-0016; README (PostgreSQL test instructions, removed "PostgreSQL not supported"); technical reference; stale cap caveats updated in README, ADR-0011, technical reference, and the setting description |

No application code needed dialect changes beyond the claim path. All 21
migrations ran unchanged.

## Blueprint acceptance criteria

| Criterion | Evidence |
| --- | --- |
| Migrations work on PostgreSQL | Upgrade to head, `alembic check` (no drift), downgrade to base, re-upgrade, both manually and in `test_full_chain_round_trip_without_drift` |
| Constraints behave the same | Partial unique indexes keep their `queued/running` and `running/awaiting_approval` predicates; named CHECK constraints exist and reject invalid values (whole suite) |
| Concurrency verified | Exact cap under 8 concurrent workers, 5/5 repeated runs green on PostgreSQL with no lock errors; existing concurrency tests (single active run, terminal-transition races, lease recovery, workflow step claim) pass on PostgreSQL |
| Same behaviour on both databases | Full suite results below |

## Verification

| Check | SQLite | PostgreSQL 16 |
| --- | --- | --- |
| `pytest` (full) | **1667 passed, 0 failed**, 10 skipped (7 Windows-only, 3 PostgreSQL-only), no warnings | **1670 passed, 0 failed**, 7 skipped (Windows-only), no warnings; all per-test schemas dropped |
| Coverage | 89% | not measured separately |
| Migrations | head `0021`, no drift, round trip | head `0021`, no drift, round trip |
| `ruff check` / `ruff format --check` | clean | |
| OpenAPI | unchanged | |
| Dependencies | core unchanged; `[postgres]` extra added | |

Before the fixes, the first PostgreSQL run had 17 failures out of about 1,660.
All of them came from the SQLite-only trigger syntax and error-message
assertions in test code; no application test failed for a dialect reason.

## Known gaps and risks

- Verified on one local PostgreSQL 16 server only; not yet in CI or on other
  major versions.
- The concurrency test cannot prove the lock is necessary: an unlucky
  interleaving was needed to trigger the old over-claim. The change is
  justified by reasoning (READ COMMITTED snapshot per statement) and is covered
  for correctness.
- Rate limits and synchronous-run slots remain per process (documented since B9
  and M8).
- Windows test suite still not run. DVWA lab (D14) still open.
