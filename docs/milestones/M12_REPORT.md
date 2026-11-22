# M12 — JSON and HTML Assessment Reports

Status: **complete, awaiting owner review before M13.**

## Key decision: no Jinja2 (please review)

M0 decision D13 proposed Jinja2 with autoescaping. Jinja2 is not installed, and
adding it needs your approval for a download, so the HTML renderer uses the
standard library with **escaping on by default**. Every value is escaped,
quotes included, unless it is a fragment the renderer built itself. A raw
finding title, path, or excerpt cannot reach the output unescaped. The tests
include an actual `<script>` payload from the fake OSV advisory feed, plus
injected titles, paths, and excerpts. If you approve Jinja2 later, the renderer
can switch to templates without changing the report schema.

## What was added

| Area | Files |
| --- | --- |
| Builder | `app/services/reports/builder.py`: report from persisted data only; deterministic ordering; content hash; secret scrubbing; relative/redacted target display; incomplete-check detection; advisory references; labelled AI explanations with sources; workflow plan and approvals |
| HTML | `app/services/reports/html.py`: escaping-by-default renderer, self-contained page (no scripts, images, or remote assets), stylesheet pinned by hash in the CSP |
| API | `app/api/reports.py`: `GET …/reports/json` and `GET …/reports/html` (`analysis_run_id` optional) |
| Workflow | `generate_report` node now builds the report and records its hash, finding count, and incomplete checks (it was a skip in M10) |
| Settings | `REPORT_MAX_FINDINGS` (500), `REPORT_MAX_EVIDENCE_PER_FINDING` (10), `REPORT_MAX_BYTES` (5 MB, then 413) |
| Tests | `tests/test_reports.py` (12) |
| Docs | ADR-0015, README (also corrected stale "no HTML reports" statements), technical reference, `.env.example` |

## Blueprint acceptance criteria and tests

| Requirement | Evidence |
| --- | --- |
| JSON and HTML agree with persisted findings | Same finding IDs, statuses, severities, and evidence IDs as `GET …/findings`; every finding ID appears in the HTML (`test_reports_agree_with_persisted_findings`) |
| Reports explicitly show incomplete checks | `checks_not_run` lists the partial dependency audit; the executive summary says that absence of findings is not proof; the HTML shows an incomplete banner; failed runs are "not a clean result" (`test_failed_run_is_reported_as_not_clean`) |
| HTML safely escaped | Malicious title, component, location, excerpt, and advisory text: no raw `<script>`, `<img>`, `<svg>`, or `<iframe>`; no `src` or `on*` attributes in real markup; only https links; CSP header and meta tag present (`test_html_escapes_malicious_titles_paths_and_evidence`) |
| No server paths, secrets, raw tokens, or sensitive headers | A token in a summary, a bearer header, and a session cookie in an excerpt are all masked; the host path never appears (`test_no_server_paths_or_secrets_in_reports`) |
| Access follows assessment authorization | Another analyst gets 404; unauthenticated gets 401 (`test_report_access_follows_assessment_authorization`) |
| Size limits and safe content disposition | `attachment` with a UUID file name, `no-store`, `nosniff` (`test_download_headers`); finding truncation is shown, and oversize returns 413 (`test_size_and_finding_limits`) |
| Empty, partial, and failed runs | `test_empty_assessment_report`, `test_failed_run_is_reported_as_not_clean`, partial dependency audit in the main test |
| Deterministic JSON and versioning | Repeated downloads are identical apart from `generated_at`; keys are sorted; schema and generator versions are present; the hash changes with new data (`test_deterministic_and_versioned`) |
| AI explanations labelled as AI-generated and grounded | A fixed label, model, and attributed sources; the finding status is unchanged; findings without an explanation show none (`test_ai_explanations_are_labelled_and_attributed`) |
| Workflow integration | The recorded hash equals a later download's hash; the report shows the workflow plan (`test_workflow_report_step_matches_the_downloaded_report`) |

## Existing tests changed (intended)

- `tests/test_workflows.py`: `generate_report` now completes instead of skipping.

No assertion was weakened, and no migration was needed.

## Verification

| Check | Result |
| --- | --- |
| `pytest` (full) | **1666 passed, 0 failed, 7 skipped** (Windows-only), no warnings |
| Coverage | 89% overall; reports API 100%, builder 98%, HTML 97% |
| `ruff check` / `ruff format --check` | clean |
| Alembic | head still `0021`; no model changes |
| OpenAPI | 2 new paths; no schema changes |
| Dependencies | unchanged (`pyproject.toml` identical) |

## Known gaps and risks

- Reports are generated on demand and not stored. Their identity is the content
  hash (and the workflow event when a workflow ran).
- Report downloads are not audited. That would need one more audit-action
  migration; it is a small follow-up if you want it.
- No PDF export.
- The Windows test suite has still not been run. D14 (Docker, PostgreSQL, DVWA)
  remains open.

## Next milestone

M13: PostgreSQL support. Running the migrations and concurrency tests against
PostgreSQL needs:
- a PostgreSQL driver, a new dependency (for example `psycopg`), needing your
  approval;
- a PostgreSQL server, which ties into the still-open D14 (Docker, a local
  install, or CI).

M13 can't be verified without both, so it needs those decisions first.
