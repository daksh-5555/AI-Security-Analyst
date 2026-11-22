# M4 — Target Authorization and Repository Isolation

Status: **complete, awaiting owner review before M5.**
Completes ADR-0004 (now *Accepted*). The guarded egress client was delivered in M3
(ADR-0006).

## What was added

| Area | Files |
| --- | --- |
| Model and migration | `app/models/assessment_target.py`, `migrations/versions/0016_create_assessment_targets.py` (table, backfill, audit constraint extension, guarded downgrade) |
| Enums | `TargetType`, `TargetStatus`, `AuthorizationBasis`; audit actions `assessment_target.authorized` / `assessment_target.revoked`; resource type `assessment_target` |
| Service | `app/services/target_authorization.py`: URL canonicalization, registration, authorize/revoke, `require_authorized_repository_target`, `DatabaseTargetAuthorizationPolicy`, `build_target_client`, `policy_snapshot` |
| API | `app/api/targets.py` (`POST …/web-target`, `GET …/targets`, `POST …/targets/{id}/authorize`, `POST …/targets/{id}/revoke`), `app/schemas/target.py`, constants |
| Enforcement | `analysis_execution.py` (checked before any run record exists), `repository_discovery.discover_registered_repository` (covers runs and the summary), `409` mapping in `analysis_runs.py` and `attack_surface.py` |
| Isolation (S-7) | `repository_targets.py`: `repository_roots_for_owner`, `validate_repository_location(..., allowed_roots=...)`, authorization row created with every repository registration |
| Settings | `REPOSITORY_ISOLATION` (`shared`/`per_user`; must be explicit in staging/production), `WEB_TARGET_ALLOWED_HOSTS`, `WEB_TARGET_ALLOWED_LOCAL_NETWORKS` (refused in staging/production) |
| Tests | `test_migration_0016.py` (5), `test_target_authorization.py` (23), `test_targets_api.py` (14), config tests; head pins `0015` → `0016` in six migration tests |
| Docs | ADR-0004 finalized, README, technical reference, `.env.example` |

## Design decision taken in this milestone (please review)

**S-7 is fixed by configuration, not by default.** `REPOSITORY_ISOLATION=per_user`
confines each owner to `<allowed root>/<owner user id>/`. It is checked at
registration and again at analysis time, and rejections are indistinguishable from
any other invalid path. The default stays `shared` for development so existing
single-user setups keep working. Staging and production refuse to start unless the
value is set explicitly. If you prefer `per_user` as the default everywhere, it is a
one-line change; most existing tests would then need repositories created under a
per-user sub-root.

## Blueprint criteria covered

| Requirement | Evidence |
| --- | --- |
| Explicit authorized target registration/confirmation | `confirm_authorized: true` plus a 20–1000 character statement plus an allowlisted host; audited; `test_web_target_registration_*` |
| Canonicalize hosts, schemes, ports, paths; HTTP/HTTPS only; no URL credentials | `canonicalize_web_target` with 8 positive and 9 rejection cases |
| Target ownership and authorization explicit; shared roots alone insufficient | Owned `assessment_targets` row for every target; per-user isolation; `test_per_user_isolation_*`, `test_isolation_is_rechecked_at_analysis_time` |
| Revocation effective; no run without authorization | `test_revocation_blocks_analysis_until_reauthorized` (409 for run and summary, zero run records), `test_legacy_pending_target_is_blocked` |
| Only owner/Admin can manage | `test_only_owner_or_admin_can_manage_targets` (other analyst 404, viewer 403, admin 200) |
| All network access through one guarded client | `build_target_client` returns a client bound to the target host; pending, revoked, or non-allowlisted targets are refused |
| Data preservation in migration | Backfill test, FK check, downgrade guard, round trip |

## Verification

| Check | Result |
| --- | --- |
| `pytest` (full) | **1464 passed, 0 failed, 7 skipped** (Windows-only) |
| Coverage | 88% overall; target service 91%, targets API 93%, model 100% |
| `ruff check` / `ruff format --check` | clean (226 files) |
| Alembic | head `0016`; `alembic check` reports no drift; upgrade → downgrade base → upgrade OK |
| OpenAPI | 4 new paths; **no existing path changed**; new schemas `AssessmentTargetRead`, `WebTargetCreate`, `TargetAuthorizationRequest`, `TargetType`, `TargetStatus`, `AuthorizationBasis`; `AuditAction`/`AuditResourceType` gained the new values (additive) |
| Dependencies | unchanged |

## Behaviour changes to note

- Analysis runs and summaries now return **409** when the repository target's
  authorization record is missing, pending, or revoked. Existing owned targets were
  backfilled as authorized; ownerless legacy targets need an Admin to authorize them.
- Every repository registration now also creates an authorization record. The
  registration response is unchanged.

## Known gaps and risks

- No web analysis uses web targets yet. The crawler (M5) and probes (M6) will be
  the first users of `build_target_client`.
- DNS is not checked at registration. A target host that resolves to a blocked
  address is accepted and then refused at connection time by the guarded client.
- `repository_discovery.py` (76%) and `repository_targets.py` (78%) coverage is
  dominated by pre-existing OS-error branches.
- The Windows test suite has still not been run.
- Infrastructure decision D14 (Docker/PostgreSQL/DVWA) is still open. M5 can use
  local Python fixture sites, but the DVWA integration in M6 needs Docker or a
  manual DVWA install.

## Next milestone

M5: safe runtime web crawler over authorized web targets. Same-origin, depth and
page budgets, link/form/parameter inventory, no destructive form submission,
robots handling, and cancellation. All requests go through `build_target_client`.
