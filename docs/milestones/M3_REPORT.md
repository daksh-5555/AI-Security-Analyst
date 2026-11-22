# M3 — Dependency Inventory and Advisory Analysis (with the guarded egress client)

Status: **complete, awaiting owner review before M4.**
Per M0 decision D8, the guarded HTTP client from M4 was built first, so the
advisory lookup never touches the network outside the policy-enforcing client.

## What was added

| Area | Files |
| --- | --- |
| Guarded egress client (ADR-0006) | `app/services/net/guarded_client.py`, `app/services/net/__init__.py` |
| Shared safe file reader | `app/services/tooling/files.py` (moved out of the secret scanner; that scanner now uses it) |
| Version logic and OSV range evaluation | `app/services/dependencies/versions.py` |
| Dependency inventory | `app/services/dependencies/inventory.py` |
| OSV provider and cache | `app/services/dependencies/osv.py` |
| Audit tool | `app/services/dependencies/auditor.py`, `app/services/dependencies/__init__.py` |
| Run integration and findings | `app/services/analysis_tools.py` (registers `dependency_audit`, `dependency_findings_from_result`) |
| Settings | `app/core/config.py`: `DEPENDENCY_AUDIT_MODE`, `ADVISORY_OSV_BASE_URL` (validated https), `ADVISORY_CACHE_DIR`, `ADVISORY_CACHE_TTL_SECONDS`, `ADVISORY_MAX_PACKAGES`, `ADVISORY_REQUEST_TIMEOUT_SECONDS`, `DEPENDENCY_MANIFEST_MAX_SIZE_BYTES` |
| Run completeness | `app/services/analysis_execution.py`: `skipped/not_applicable` tools no longer make a run incomplete |
| Dependency | `pyproject.toml`: `packaging>=24.0` (PEP 440/508; already installed transitively) |
| Test isolation | `tests/conftest.py`: autouse guard that blocks every non-loopback socket connection; dependency audit forced to offline mode |
| Tests | `test_guarded_http_client.py` (31), `test_dependency_versions.py`, `test_dependency_inventory.py`, `test_osv_provider.py` (11), `test_dependency_audit.py`, `test_offline_guard.py`, `osv_fixtures.py` (loopback fake OSV), plus config tests |
| Docs | ADR-0006, ADR-0007, README, technical reference, `.env.example` |

## Blueprint acceptance criteria

**M3 (dependency/CVE)**

| Criterion | Evidence |
| --- | --- |
| Every advisory match has a reproducible version-range explanation | `match_explanation` such as "version 2.0.1 is within the affected range (introduced 0, fixed 2.0.3)" (`test_matches_are_verified_locally_and_explained`, `test_explanation_is_reproducible`) |
| Missing advisory data is "unavailable", not "no vulnerabilities" | `test_offline_without_cache_*`, `test_provider_failures_are_unavailable[slow/invalid/rate_limited]`; tool result `partial` with `advisory_data_unavailable` |
| No repository code executed | Parsing uses `tomllib`/`json`/`packaging` only; `test_no_repository_code_or_package_manager_is_executed` patches `subprocess.Popen` to fail |
| Results show source and freshness | Evidence `source`, `source_url`, `fetched_at`, `freshness`; stale labelling (`test_fresh_cache_avoids_network_and_expiry_labels_stale`, `test_provider_outage_falls_back_to_stale_cache`) |
| Tests: vulnerable/fixed/unaffected, boundaries, prerelease, unknown versions, malformed manifests, timeout, invalid response, rate limit, cache expiry, offline | All covered in the version, inventory, provider, and audit suites |

**M4 client portion (SSRF and redirect protections)**

| Criterion | Evidence |
| --- | --- |
| Unsafe destinations blocked before sending | Scheme, credentials, host allowlist, and blocked-address tests assert that no connection was attempted |
| Redirects and resolved addresses revalidated | Six redirect revalidation cases, loop, and limit; rebinding test proves the connection uses the vetted IP and the next lookup is re-checked |
| Limits with safe defaults | Oversize, decompression bomb, content type, slow response, cancellation tests |

## Verification

| Check | Result |
| --- | --- |
| `pytest` (full) | **1413 passed, 0 failed, 7 skipped** (Windows-only) |
| Coverage | 88% overall; versions 97%, inventory 97%, auditor 95%, OSV provider 88%, guarded client 87% |
| `ruff check` / `ruff format --check` | clean (217 files) |
| Alembic | head `0015`, no drift, round trip OK (no migration in M3) |
| OpenAPI | byte-identical before and after |
| Egress | No `httpx`/`requests`/`urllib.request`/`http.client`/`socket.create_connection` use outside `app/services/net/` |

Bugs found and fixed during the milestone:

1. A malformed redirect `Location` made `urljoin` raise an uncaught `ValueError`;
   it now fails safely as `bad_redirect`.
2. PyPI package names were sent to the provider unnormalised (`Demo_HTTP`), which
   could miss advisories; queries and cache keys now use PEP 503 canonical names.

## Behaviour changes to note

- `DEPENDENCY_AUDIT_MODE` defaults to **`online`**: outside the test suite, analysis
  runs on repositories with pinned or locked dependencies now make HTTPS requests to
  `api.osv.dev` (package names and versions only). Set `offline` or `disabled` if
  that is not wanted.
- Repositories with unpinned dependencies and no lock file now produce a `partial`
  dependency audit, and therefore `completeness.is_complete = false`. This is
  intentional honesty, not an error.
- `dependency` findings appear in `findings_count`.

## Known gaps and risks

- **Not verified against the live OSV API.** All provider tests use a loopback fake
  that follows the documented OSV request/response shapes. A single live smoke query
  is recommended before relying on online mode.
- PyPI and npm only. No `pnpm`/`yarn` locks, CVSS scoring, or reachability analysis.
- The guarded client has no per-assessment target authorization yet. That remains
  M4 (ADR-0004 stays *proposed*).
- `tooling/files.py` coverage is 71%: some OS-error branches are exercised only by
  the secret-scanner tests indirectly.
- The Windows test suite has still not been run.

## Next milestone

M4: the remainder of target authorization. That means the `assessment_targets`
record with owner, explicit confirmation and policy snapshot (this also fixes S-7
for repository targets) and the `TargetAuthorizationPolicy` implementation, wired
to the guarded client for web targets. It includes a migration. Infrastructure
decision D14 (PostgreSQL/DVWA) is still open.
