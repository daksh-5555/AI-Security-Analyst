# M5 — Safe Web Crawler

Status: **complete, awaiting owner review before M6.**
This milestone was finished across two sessions; the code was checkpointed
(existing suite green) before its tests and documentation were written.

## What was added

| Area | Files |
| --- | --- |
| HTML extraction (standard library, capped, no input values) | `app/services/crawler/html.py` |
| Canonical URLs, scope, safety denylist, form classification | `app/services/crawler/scope.py` |
| Crawler tool (`web_crawl`) | `app/services/crawler/tool.py`, `app/services/crawler/__init__.py` |
| Web analysis runs | `app/services/analysis_execution.py` (web branch, `_build_web_analysis_metadata`, shared `_incomplete_tools`), `app/services/analysis_tools.py` (`build_web_tool_registry`, `run_web_tools`, `crawl_inventory`) |
| Target checks | `app/services/target_authorization.py`: `require_authorized_web_target` (status *and* current allowlist, before any run record), `WebTargetNotFoundError`, public `within_base_path` |
| Tool context | `app/services/tooling/protocol.py`: `web_target_url`, `http_client` |
| API | `app/api/analysis_runs.py`: 404 "Web target not found" |
| Settings | `CRAWLER_MAX_DEPTH`, `CRAWLER_MAX_PAGES`, `CRAWLER_MAX_REQUESTS`, `CRAWLER_MAX_VARIANTS_PER_PATH`, `CRAWLER_RESPECT_ROBOTS`, `CRAWLER_EXCLUDED_PATHS` |
| Tests | `tests/crawl_fixtures.py` (loopback fixture site that logs every request), `tests/test_crawler.py` (24), `tests/test_web_analysis_runs.py` (5) |
| Docs | ADR-0008, README, technical reference, `.env.example` |

## Blueprint acceptance criteria

| Criterion | Evidence |
| --- | --- |
| Structured endpoint/form inventory | `crawler.page`, `crawler.form`, `crawler.auth_boundary` evidence; `crawl_inventory` in run metadata (`test_crawl_inventories_*`, `test_web_run_crawls_the_authorized_target`) |
| Every request through the safe client | The tool only uses `ToolContext.http_client` from `build_target_client`; no network imports outside `app/services/net/`; an external redirect is refused by the client (`request_failed.host_not_allowed`) |
| Crawl limits enforced | Depth, pages, requests, per-path variants (`test_depth_page_request_and_variant_budgets`); base path and excluded paths (`test_base_path_scope_is_enforced`, …) |
| No arbitrary form submission | The fixture server log contains GET only; `/comment`, `/search`, `/login` POSTs never sent (`test_crawler_only_sends_get_and_never_submits_forms`) |
| No destructive actions | `/logout`, `/delete?id=7` never requested; `setup.php`/`security.php` on the denylist |
| Same-origin boundary, redirects, content types | Other host, `mailto:`, `javascript:`, and fragments ignored; internal redirect followed; non-HTML recorded, not parsed |
| Cancellation and time budget | `test_cancellation_stops_the_crawl`; run deadline via the shared execution context |
| Repeatable against a fixed fixture | `test_results_are_repeatable` (identical evidence keys and counts) |
| No secrets in output | Hidden CSRF value, session cookie, and query values are absent from results and run responses |

## Verification

| Check | Result |
| --- | --- |
| `pytest` (full) | **1493 passed, 0 failed, 7 skipped** (Windows-only) |
| Coverage | 88% overall; crawler tool 95%, scope 92%, HTML 90% |
| `ruff check` / `ruff format --check` | clean |
| Alembic | head `0016`, no drift (no migration in M5) |
| OpenAPI | byte-identical (new behaviour uses existing endpoints) |
| Dependencies | unchanged (standard-library HTML parser) |

Issue found and fixed during M5: a target whose host was removed from
`WEB_TARGET_ALLOWED_HOSTS` after authorization was admitted, and then failed when
the client was built, leaving a failed run record. The allowlist is now re-checked
before any run record is created (exact 409, zero runs, nothing sent).

## Behaviour notes

- Web runs complete even if the crawl fails; the tool status (`failed`/`partial`)
  and `completeness` record it. They report no findings: vulnerability checks are
  M6.
- The real per-target rate (2 requests/second) applies, so a full crawl of the
  fixture site takes about 8 seconds.

## Known gaps and risks

- No JavaScript execution, sitemap, or API-description discovery; no
  authenticated crawling.
- The destructive-link denylist is pattern-based. A destructive GET endpoint with
  an innocuous name could still be requested, so crawl only lab or disposable
  targets.
- Still untested against a real DVWA instance; that needs infrastructure decision
  D14 (Docker Desktop, a local install, or CI).
- The Windows test suite has still not been run.

## Next milestone

M6: conservative runtime XSS and SQL injection checks on crawled parameters,
following the proof rules in ADR-0003. Reflection alone, a SQL error message, or a
status or length change is never `confirmed`. Probes are harmless, bounded, and
opt-in; DVWA integration tests run only when the lab is available.
