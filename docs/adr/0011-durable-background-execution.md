# ADR-0011: Durable background execution, cancellation, and recovery

Status: accepted (M8). Date: 2026-11-16.

## Context

Analysis ran only inside the HTTP request. A long analysis blocked a worker
thread, and if the process died the run stayed `running` forever. The lease
columns from migration 0014 (`heartbeat_at`, `cancel_requested_at`) existed,
but nothing requested cancellation and nothing reclaimed stale runs. M0
decision D11 chose to add an asynchronous mode and keep the synchronous
behaviour available.

## Decision

1. **Run states.** `analysis_runs.status` gains `queued` and `cancelled`.
   Migration 0018 widens the active-run partial unique index to
   `status IN ('queued', 'running')`, so an assessment has at most one queued
   or running run. New columns: `requested_by_user_id`, `lease_owner`,
   `lease_expires_at`, `stage`, `attempts`, `error_code`, and
   `summary_snapshot`. New audit actions: `analysis_run.queued` and
   `analysis_run.cancelled`.
2. **Database as queue.** There is no broker. `POST …/analysis-runs?mode=async`
   validates the target and commits a `queued` run together with its audit
   event, then returns 202 with `Location`. It is off by default
   (`ANALYSIS_ASYNC_ENABLED=false`), because queued runs only progress while a
   worker runs. Without `mode`, the request runs synchronously and returns 201,
   exactly as before.
3. **Worker** (`python -m app.worker`, `app/services/analysis_worker.py`).
   Each iteration does three things:
   - runs the stale-lease recovery sweep;
   - claims the oldest queued run with one conditional UPDATE. The row must
     still be `queued`, and the number of worker-claimed running runs must be
     below `ANALYSIS_WORKER_MAX_RUNNING`. The `analysis_run.started` audit event
     commits in the same transaction;
   - executes the run through the same pipeline as synchronous runs.

   Before executing, the worker validates the target again. A target that was
   revoked, removed, or moved while the run was queued fails the run with
   `target_validation_failed`, and the run is never retried.
4. **Lease and progress.** The heartbeat thread extends `lease_expires_at` (by
   `ANALYSIS_STALE_AFTER_SECONDS`) and records `stage`. For a worker run it
   renews only while `lease_owner` still matches. Every terminal transition is
   conditional on `status = 'running'` and, for worker runs, on `lease_owner`.
   A worker whose lease was recovered therefore cannot complete or fail the
   run.
5. **Idempotent results.** Findings and evidence are written only inside the
   single completion transaction. A crashed or superseded attempt leaves no
   findings, so a retry cannot duplicate them. Retest comparison is unaffected.
6. **Recovery** (`recover_stale_runs`). For each running run whose lease
   expired, or legacy or synchronous runs whose heartbeat is older than the
   stale threshold:
   - cancellation was requested: the run becomes `cancelled`;
   - a worker run with attempts left is requeued (`error_code=lease_expired_retry`);
   - otherwise the run becomes `failed` with `error_code=lease_expired`.

   Each update repeats the staleness predicate, so a run that renewed in the
   meantime is left alone.
7. **Retries.** Only transient failures are retried: lease loss, and a database
   `OperationalError` (requeued with `transient_retry`). They are limited by
   `ANALYSIS_WORKER_MAX_ATTEMPTS`. Analyzer errors, deadlines, and target
   problems are permanent.
8. **Cancellation.** `POST …/analysis-runs/{run_id}/cancel` behaves by run state:
   - queued: the run becomes `cancelled` at once, with its audit event;
   - running: `cancel_requested_at` is set. The heartbeat stops renewing and
     aborts the pipeline at the next stage boundary. The executing process (or
     recovery, if that process is gone) records `cancelled`;
   - terminal: 409.

   A synchronous request whose run is cancelled returns 409.
9. **Persisted summary.** A completed repository run stores the API
   attack-surface summary in `summary_snapshot` (relative repository path only).
   `GET …/attack-surface/summary?source=persisted` returns the newest one
   without re-running the pipeline. The default stays `source=live`, which
   recalculates. Changing the default would be a breaking behaviour change, so
   it is left to the owner.
10. **Quota.** In async mode, the per-user concurrency quota counts queued and
    running runs in the database. It therefore applies across all processes.
    Runs of the same assessment are excluded, so a duplicate request gets 409.

## Consequences

- Restarting a process no longer leaves runs `running` forever, once a worker
  (or `python -m app.worker --recover-only` on a schedule) runs.
- Synchronous runs are recovered as `failed`, never retried, because their
  HTTP caller is gone.
- `started_at` stays non-nullable to keep the API contract. A queued run
  carries its creation time there until it is claimed.
- ~~On PostgreSQL under READ COMMITTED, two workers claiming at the same
  instant could exceed `ANALYSIS_WORKER_MAX_RUNNING` by one.~~ Resolved in M13
  (ADR-0016): claims take an advisory lock and use `FOR UPDATE SKIP LOCKED`.
- Run statuses `queued` and `cancelled` and the new fields are additive API
  changes. Clients that validate enums strictly must accept the new values.
- Cancellation is cooperative: a single long stage runs until its next check.
