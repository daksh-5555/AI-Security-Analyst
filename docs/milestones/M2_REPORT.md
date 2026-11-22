# M2 — Repository Secret Scanning

Status: **complete, awaiting owner review before M3.**
Decisions applied from M0: D4 (`potential` status), D5 (scanner may read `.env` and
key files), D6 (in-house rule engine), D7 (keyed HMAC fingerprints).

## What was added

| File | Purpose |
| --- | --- |
| `app/services/secret_scanning/rules.py` | Versioned rule catalog (`secret-rules-2026.11.1`), placeholder detection, entropy helper, excerpt-only masking patterns, custom-rule builder |
| `app/services/secret_scanning/scanner.py` | `SecretScannerTool`: bounded, symlink-safe reads of inventoried files; overlap resolution; redaction; fingerprints; budgets; skip/partial accounting; allowlist |
| `app/services/analysis_tools.py` | Tool registry for analysis runs, fingerprint-grouped conversion to `potential` findings, per-tool run metadata |
| `migrations/versions/0015_add_potential_finding_status.py` | Adds `potential` to the `finding_status` CHECK constraint; downgrade refuses while `potential` rows exist |
| `docs/adr/0005-secret-scanning.md` | Engine, inputs, redaction, false-positive handling, statuses |
| `tests/test_secret_scanner.py`, `tests/test_secret_findings.py`, `tests/test_migration_0015.py` | 68 new collected tests (including parametrized cases) |

Existing files changed:

- `app/schemas/enums.py`: `FindingStatus.POTENTIAL`.
- `app/core/config.py`: `EVIDENCE_FINGERPRINT_KEY` (at least 32 bytes; required
  in staging/production), `SECRET_SCAN_ENABLED`, four budget settings,
  `SECRET_SCAN_ALLOWLIST` (validated narrow and justified),
  `SECRET_SCAN_CUSTOM_RULES` (validated).
- `app/services/analysis_execution.py`: runs the registry after the static pipeline.
  Secret findings are persisted with the flow findings. The metadata gains `tools[]`
  plus `completeness.static_analysis_is_complete`, `tools_are_complete`, and
  `incomplete_tools`, and `completeness.is_complete` now also requires every tool to
  have completed.
- Tests updated for intended changes only:
  - Head-revision assertions `0014` → `0015` (5 migration tests).
  - The status vocabulary now includes `potential`.
  - Production-config fixtures supply the fingerprint key.
  - Five analysis tests that stub the whole pipeline now give their stand-in
    `discovery=None` and accept the new metadata keyword arguments. Their assertions
    are unchanged.
- `README.md`, `docs/TECHNICAL_REFERENCE.md`, `.env.example`: documentation of rules,
  settings, metadata, and limitations.

## Deviation from the M1 plan

M1 proposed routing the *existing* static pipeline through the registry in M2. I did
not do that: the pipeline's intermediate results (summary metrics, flow
relationships) feed the run metadata and the finding policy, and `ToolResult`
cannot carry them without the evidence normalization planned for M7. M2 routes only
the new tool through the registry. The static adapter from M1 remains available.

## Blueprint acceptance criteria

| Criterion | Evidence |
| --- | --- |
| Deterministic results that name the matching rule | `test_results_are_deterministic_with_a_configured_key`; every evidence record carries `rule_id` and rule-set version |
| Secret material never in persisted output or logs | `test_scan_makes_no_network_calls_and_logs_no_secrets`, `test_analysis_run_persists_redacted_potential_secret_findings` (searches API responses and every row of `assessment_findings`, `finding_evidence`, `analysis_runs`, `audit_events`), `test_excerpts_hide_every_value_on_the_line` |
| Relative paths and line numbers | Every positive-rule test checks `location.path` and `line` |
| Explicit false-positive handling | Placeholders counted (`test_placeholders_are_counted_not_reported`); allowlist narrow, counted, explained (`test_allowlist_is_narrow_counted_and_explained`, config validation tests); test/example paths reported with lower confidence |
| No network requests | `socket.connect` / `create_connection` patched to fail during a scan; no network imports in `app/` |
| Tests: synthetic secrets per rule, near misses, redaction, ignore rules, symlinks, oversize, binary, dedup, Windows/POSIX paths | 12 positive rule cases plus the private-key case, 9 near misses, 6 placeholders, policy exclusions, oversize → partial, budgets, symlink/out-of-root/absolute reads, fingerprint dedup across files, Windows-style traversal and allowlist globs |

## Verification

| Check | Result |
| --- | --- |
| `pytest` (full) | **1322 passed, 0 failed, 7 skipped** (Windows-only) |
| Coverage | 87% overall; scanner 92%, rules 95%, `analysis_tools` 98% |
| `ruff check` / `ruff format --check` | clean (199 files) |
| Alembic | single head `0015`; `alembic check` reports no drift; upgrade → downgrade base → upgrade OK; 0015 data-preservation and downgrade-guard tests pass |
| OpenAPI | The only difference is the added `"potential"` value in the finding-status enum (additive) |
| Dependencies | `pyproject.toml` unchanged |
| A smoke test during development found that a short password (`hunter2`) next to a detected token was not masked in the excerpt | Fixed with excerpt-only masking of all secret-like assignments and URL passwords; covered by `test_excerpts_hide_every_value_on_the_line` |

## Known gaps and risks

- Regex and line-oriented: multi-line, encoded, or obfuscated secrets and
  unsupported formats can be missed. Git history is not scanned.
- Lock files, vendored code, minified assets, and binaries are not scanned (counted
  as policy exclusions).
- Placeholder detection can hide a real value that looks like a placeholder (for
  example one containing "example"). It is counted, not dropped silently.
- Without `EVIDENCE_FINGERPRINT_KEY` (development only), fingerprints are
  per-process.
- Existing API clients now see `potential` as a finding status and see secret
  findings in `findings_count`.
- The Windows test suite has still not been run.

## Next milestone

M3 (dependency inventory and CVE analysis) needs outbound access to OSV. Per
decision D8, the proposal is to build the guarded HTTP client portion of M4 first
(or an advisory-only client absorbed by M4). Infrastructure decision D14
(PostgreSQL/DVWA) is still open.
