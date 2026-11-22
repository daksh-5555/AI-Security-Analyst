# M8 — Durable Background Execution and Recovery

Status: **complete, awaiting owner review before M9.**

## What was added

| Area | Files |
| --- | --- |
| Migration | `migrations/versions/0018_durable_analysis_runs.py`: `queued`/`cancelled` run states; active-run index widened to queued-or-running; `requested_by_user_id`, `lease_owner`, `lease_expires_at`, `stage`, `attempts`, `error_code`, `summary_snapshot`; queue index; `analysis_run.queued`/`.cancelled` audit actions; downgrade guard |
| Execution | `app/services/analysis_execution.py`: one shared pipeline (`_execute_run`) for synchronous and worker runs; `enqueue_assessment_analysis`; `execute_claimed_run` (validates the target again); lease-conditional terminal transitions; `finish_run_unsuccessfully` (FAILED or CANCELLED with audit); transient requeue; stored summary snapshot |
| Heartbeat | `app/services/analysis_heartbeat.py`: extends `lease_expires_at`, records `stage`, renews only for the lease owner |
| Worker | `app/services/analysis_worker.py` (`claim_next_run`, `recover_stale_runs`, `AnalysisWorker`); `app/worker.py` (`python -m app.worker [--once \| --recover-only]`) |
| Services | `app/services/analysis_runs.py`: `request_cancellation`, durable per-user active-run count, `latest_summary_snapshot` |
| API | `POST …/analysis-runs?mode=async` (202); `POST …/analysis-runs/{run_id}/cancel`; `GET …/attack-surface/summary?source=persisted`; run responses gain `stage`, `attempts`, `error_code`, `cancel_requested_at` |
| Settings | `ANALYSIS_ASYNC_ENABLED` (default **false**), `ANALYSIS_WORKER_MAX_ATTEMPTS` (3), `ANALYSIS_WORKER_MAX_RUNNING` (2), `ANALYSIS_WORKER_POLL_INTERVAL_SECONDS` (2); `ANALYSIS_STALE_AFTER_SECONDS` is now the lease length and is actually used |
| Tests | `tests/test_analysis_worker.py` (20), `tests/test_migration_0018.py` (5) |
| Docs | ADR-0011, README, technical reference, `.env.example` |

## Blueprint acceptance criteria

| Criterion | Evidence |
| --- | --- |
| Long analyses do not block the request | `?mode=async` returns 202 at once; a worker executes the run (`test_async_run_is_queued_then_completed_by_the_worker`) |
| Persisted status and progress | `status`, `stage`, `attempts`, `error_code`, `cancel_requested_at` on every run, updated by claim, heartbeat, and terminal transitions |
| Atomic claim; no double execution | One conditional UPDATE (`test_two_workers_never_claim_the_same_run`, four threads); global running cap (`test_claim_respects_the_global_running_cap`) |
| Crash recovery | Expired lease → requeued and completed by another worker, findings not duplicated (`test_crashed_worker_run_is_requeued_and_completed_without_duplicates`); attempts exhausted → `failed`/`lease_expired` (`test_exhausted_attempts_fail_with_lease_expired`); stale synchronous and pre-0018 runs → `failed`, never retried |
| A superseded worker cannot corrupt results | `test_worker_that_lost_its_lease_cannot_complete_or_fail_the_run`: no findings, no terminal audit event, run stays with the new owner |
| Persisted cancellation | Queued → `cancelled` immediately; running → stops at the next heartbeat (`test_cancel_a_running_run_stops_it_at_the_next_heartbeat`); synchronous request returns 409; stale run with a cancel request → `cancelled`; finished run → 409 |
| Idempotent retries | Findings are written only in the completion transaction; transient errors are requeued, then fail with `transient_retries_exhausted`; permanent errors are never retried |
| Revalidation before execution | A target removed while its run was queued fails with `target_validation_failed`, and analysis never starts |
| Summary reads persisted results | `?source=persisted` equals the live summary (`test_persisted_summary_matches_the_live_summary`) |
| Every state change is audited | queued, started (each attempt), completed, failed, cancelled |

## API changes — please review

All changes are additive. No existing path, field, or default changed behaviour,
except for the one 409 mapping below.

- **New:** query parameter `mode` on `POST …/analysis-runs` (default `sync`); 202
  and 400 responses; path `…/analysis-runs/{run_id}/cancel`; query parameter
  `source` on the summary (default `live`); four optional run fields; run
  statuses `queued` and `cancelled`; audit actions `analysis_run.queued` and
  `analysis_run.cancelled`. Clients that validate enums strictly must accept the
  new values.
- **Changed:** a synchronous run aborted by cancellation now returns **409**
  instead of 500. Before M8, nothing could trigger that abort, so no existing
  client could have seen it. One test parameter was updated.
- **Not changed (owner decision):** the summary endpoint still recalculates by
  default. M0 planned to make the stored summary the default. That would change
  behaviour for every existing caller, so it is opt-in (`?source=persisted`)
  until you decide.
- `started_at` stays non-nullable. For a queued run it holds the creation time
  until the worker claims the run.
- OpenAPI diff: 1 new path; `POST …/analysis-runs` and `GET …/summary` gained
  one optional parameter and response docs; 3 run schemas gained 4 optional
  fields; 2 enums gained values; no schema removed or made stricter.

## Existing tests changed (intended)

- Head pins `0017` → `0018` in the migration tests for 0010–0017.
- `test_analysis_runs.py`: the head column set includes the seven 0018 columns.
- `test_analysis_run_concurrency.py`: at head the active-run index predicate is
  `status IN ('queued', 'running')`.
- `test_migration_0014.py`: the round trip upgrades to `0014` instead of `head`.
  It checks 0014's own schema, which 0018 now supersedes.
- `test_analysis_runs_api.py`: `AnalysisExecutionAbortedError` → 409 (see above).
- `test_attack_surface_api.py`: the summary 200/404 descriptions mention `source=persisted`.

No assertion was weakened.

## Verification

| Check | Result |
| --- | --- |
| `pytest` (full) | **1545 passed, 0 failed, 7 skipped** (Windows-only), no warnings |
| Repeat runs of the threaded claim and cancel tests | 6/6 green |
| Coverage | 88% overall; worker 86%, execution 94%, run API 98% |
| `ruff check` / `ruff format --check` | clean |
| Alembic | head `0018`; `alembic check` reports no drift; full downgrade and re-upgrade OK; round trip, guard, and constraint tests |
| OpenAPI | additive only (see above) |
| Dependencies | unchanged (`pyproject.toml` identical) |
| Egress | no new network imports; the worker uses `platform.node()` for its id |

Defect fixed during M8: the execution module had an unreachable duplicate
`return` block, which was removed in the refactor.

## Known gaps and risks

- Recovery only happens while a worker (or a scheduled `--recover-only`) runs.
  Async mode is off by default for that reason.
- Cancellation is cooperative: a single long stage finishes before the run stops.
- On PostgreSQL, simultaneous claims can exceed `ANALYSIS_WORKER_MAX_RUNNING` by
  one, but never double-claim a run. `FOR UPDATE SKIP LOCKED` is planned for M13.
- The worker runs one analysis at a time per process; to scale, run more
  processes.
- Process-local admission still governs synchronous runs.
- The Windows test suite has still not been run. D14 (Docker, PostgreSQL, DVWA)
  remains open.

## Next milestone

M9: optional LLM explanations of findings. These are advisory only and never
change status or severity. The provider is off by default, inputs are redacted,
and tests use a stubbed provider with no real LLM calls.
