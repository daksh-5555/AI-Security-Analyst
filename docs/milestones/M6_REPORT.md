# M6 — Runtime XSS and SQL Injection Checks

Status: **complete, awaiting owner review before M7.**

## What was added

| Area | Files |
| --- | --- |
| Probe tool (`runtime_probes`) | `app/services/runtime_probes/tool.py`, `__init__.py` |
| Web registry and findings | `app/services/analysis_tools.py`: probe tool registered after the crawler, `web_tool_pipeline_config` (probes only when enabled), `runtime_findings_from_result` |
| Settings | `RUNTIME_PROBES_ENABLED` (default **false**), `RUNTIME_PROBE_MAX_PARAMETERS` (10), `RUNTIME_PROBE_MAX_REQUESTS` (200), `WEB_TARGET_MAX_REQUESTS_PER_SECOND` (2; used by `web_network_policy`) |
| Tests | `tests/probe_fixtures.py` (deliberately vulnerable and safe loopback app backed by real in-memory SQLite), `tests/test_runtime_probes.py` (15 tests) |
| Updated test | `tests/test_web_analysis_runs.py`: web runs now list `runtime_probes` as skipped (disabled) and therefore incomplete, an intended consequence of the off-by-default setting |
| Docs | ADR-0009, README, technical reference, `.env.example` |

## Results against the fixtures

| Endpoint | Behaviour | Result |
| --- | --- | --- |
| `/items?id=` | SQL built by string concatenation | `sqli` **confirmed** (two consistent boolean pairs) |
| `/items-safe?id=` | parameterized SQL | no finding |
| `/items-errors?id=` | SQL-like error on a quote, not injectable | `sqli` **potential** (error signal only) |
| `/noisy?id=` | random content | SQLi not tested (`unstable_baseline`); tool `partial` |
| `/search?q=` | raw HTML reflection | `xss` **potential** (html_text) |
| `/attr?q=` | raw attribute reflection | `xss` **potential** (attribute) |
| `/script?q=` | raw JavaScript-string reflection | `xss` **potential** (script) |
| `/flaky?q=` | unencoded once, then encoded | `xss` **inconclusive** |
| `/search-safe`, `/attr-safe`, `/find` | encoded reflection | no finding (counted as encoded) |
| `/profile?token=` | sensitive parameter name | crawled, never probed |
| `/delete?id=`, POST `/comment` | state-changing | never requested |

## Blueprint acceptance criteria

| Criterion | Evidence |
| --- | --- |
| Never confirmed from a generic error, reflection, status, or length change alone | Only `runtime.sqli_boolean` with a repeated, consistent pair can be `confirmed`; `test_reflection_or_errors_alone_are_never_confirmed` |
| Each finding links to request/response evidence with secrets redacted | Evidence holds request summary (method, parameter, probe kind) and response summary (status, length); no bodies (`test_evidence_contains_no_response_bodies`) |
| Probes rate-limited and bounded | Target-bound client rate and parameter/request budgets (`test_request_and_parameter_budgets`) |
| No destructive requests | Fixture log: GET only; every probe value matches the inert allowlist; no `OR`/`UNION`/`SLEEP`/`;`/`--` (`test_only_inert_get_probes_are_sent`) |
| Tests: vulnerable and safe fixtures, reflection without execution, encoded reflection, SQL error without injection, differential noise, parameter and form handling, request budget | All present in `test_runtime_probes.py` |
| DVWA tests opt-in, never against public targets | Probes are disabled by default and only reach authorized, allowlisted targets. No DVWA test exists yet because there is no lab (D14) |

## Verification

| Check | Result |
| --- | --- |
| `pytest` (full) | **1508 passed, 0 failed, 7 skipped** (Windows-only) |
| Coverage | 88% overall; probe tool 92% |
| `ruff check` / `ruff format --check` | clean |
| Alembic | head `0016`, no drift (no migration in M6) |
| OpenAPI | byte-identical |
| Dependencies | unchanged (`difflib`, `html`, `secrets` from the standard library) |

## Known gaps and risks

- XSS is never `confirmed`, because there is no browser harness. Stored and DOM XSS
  are not tested.
- POST forms are not probed. Time-based blind SQLi and authenticated areas are not
  tested.
- String-context SQLi uses baseline `1`. If that value matches nothing, there is no
  differential, and the result is reported as *no signal*, not *safe*.
- A real DVWA has not been tested; it still needs decision D14 (Docker Desktop, a
  local install, or CI).
- The Windows test suite has still not been run.

## Next milestone

M7: evidence normalization and correlation. That means a normalized evidence store
(the `evidence_items` table plus finding links), deduplication and first-seen /
last-seen / retest tracking across runs, correlating static input→sink flows with
runtime parameters, routing the static pipeline through the registry, and making
the summary endpoint read persisted results. This includes a migration.
