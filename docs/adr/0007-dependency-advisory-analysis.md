# ADR-0007: Dependency inventory and advisory matching

- Status: Accepted (M3)
- Date: 2026-11-16

## Decision

1. **Inventory without execution.** `app/services/dependencies/inventory.py` parses
   `requirements*.txt`, `pyproject.toml` (PEP 621, PEP 735 groups, Poetry),
   `poetry.lock`, `Pipfile.lock`, `package.json`, and `package-lock.json` /
   `npm-shrinkwrap.json` (v1–v3) with `tomllib`, `json`, and `packaging` only.
   - No package manager, build backend, `setup.py`, or install script ever runs.
   - Files are read with the shared `read_bounded` (no symlinks, inside the root,
     size limited).
   - `pnpm-lock.yaml` and `yarn.lock` are reported as unsupported.
   - Lock-file versions replace manifest ranges in the same directory.
   - Only exact versions (lock entries, `==` pins, exact npm versions) are checked.
     Ranges without a lock file are reported as *unresolved* and are never matched
     by guessing a version.
   - Direct versus transitive is recorded where the format allows it, otherwise
     `unknown`.
2. **Provider.** OSV (`https://api.osv.dev`), queried through the ADR-0006 client
   restricted to that host:
   - `POST /v1/querybatch` (in chunks of 500, following `next_page_token` for up
     to 10 pages) returns advisory IDs;
   - `GET /v1/vulns/{id}` returns details, with IDs validated against
     `^[A-Za-z0-9][A-Za-z0-9._:-]{1,99}$` before use;
   - responses are untrusted: size-limited, JSON-parsed, and type-checked, with
     text stripped of control characters and truncated to 300 characters.
3. **Local verification.** Every provider match is re-evaluated locally against the
   advisory's `affected` ranges (OSV event semantics, PEP 440 for PyPI, SemVer 2.0
   for npm). The result and a reproducible explanation are stored, for example
   `version 2.0.1 is within the affected range (introduced 0, fixed 2.0.3)`.
4. **Cache and freshness.** Query results and advisories are cached in memory and,
   if `ADVISORY_CACHE_DIR` is set, as JSON files written atomically, keyed by
   SHA-256 and verified on read; symlinked or oversize cache files are ignored.
   Every package result is `fresh`, `stale` (an expired entry used because the
   provider was offline or failed), or `unavailable`.
   `DEPENDENCY_AUDIT_MODE=offline` never contacts the provider.
5. **Statuses and findings.** One finding per (package, version, advisory), with
   one evidence item per manifest; category `dependency`:
   - local range check `affected` on an exact version → `confirmed`
     (verification method: advisory version-range match). This confirms that a
     published advisory applies to that version, not that the vulnerable code path
     is reachable in the application, and the summary says so;
   - version or bound not parseable → `potential`;
   - provider match that the local check rejects → `inconclusive`.

   Severity comes from the advisory's `database_specific.severity` (GitHub labels:
   CRITICAL, HIGH, MODERATE→medium, LOW), otherwise `unknown`. CVSS vectors are
   not scored. Stale data lowers confidence and adds a limitation.
6. **Honest coverage.** Unresolved versions, unavailable or stale advisory data,
   budget overflow (`ADVISORY_MAX_PACKAGES`), unusable files, and range-check
   problems all make the tool result `partial` with explicit limitations. A
   repository without dependency files yields `skipped/not_applicable`, which
   does not make the run incomplete.

## Consequences

- New runtime dependency `packaging` (PyPA; already present transitively) for
  PEP 440 and PEP 508 parsing.
- `DEPENDENCY_AUDIT_MODE` defaults to `online`. Production deployments need
  outbound HTTPS to the OSV host, or offline mode with a pre-filled cache.
- No automatic upgrades; remediation text names the fixed versions from the
  advisory.
