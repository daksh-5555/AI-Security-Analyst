# M9 — Optional, Advisory LLM Explanations

Status: **complete, awaiting owner review before M10.**

## What was added

| Area | Files |
| --- | --- |
| Migration | `migrations/versions/0019_create_finding_explanations.py`: `finding_explanations` (status, error code, provider, model, prompt template version, output, supplied IDs, token usage, requester); `finding_explanation.created` audit action and `finding_explanation` resource type; downgrade guard |
| Model | `app/models/finding_explanation.py` |
| Contract | `app/services/explanations/contract.py`: `FindingExplanationOutput` (closed schema, no status or severity field) and `provider_json_schema()` (inlined, constraint-free copy for the provider) |
| Redaction | `app/services/explanations/redaction.py`: second-pass `scrub_text` over everything sent and received |
| Prompt | `app/services/explanations/prompt.py`: fixed, versioned policy (`finding-explanation/1`); minimum-necessary, escaped data block; item and size budgets |
| Provider seam | `app/services/explanations/provider.py` (interface, stable error codes, `build_provider`); `anthropic_provider.py` (official SDK, imported lazily) |
| Service | `app/services/explanations/service.py`: budget check, provider call, JSON, schema, and grounding validation, storage, audit |
| API | `app/api/explanations.py`: `POST` / `GET …/findings/{finding_id}/explanations`; `FindingExplanationRead` |
| Settings | `LLM_EXPLANATIONS_ENABLED` (default **false**), `LLM_PROVIDER`, `LLM_MODEL` (`claude-opus-5-5`), `LLM_API_KEY` (secret), `LLM_EFFORT`, `LLM_REFUSAL_FALLBACK`, `LLM_TIMEOUT_SECONDS`, `LLM_MAX_RETRIES`, `LLM_MAX_OUTPUT_TOKENS`, `LLM_MAX_PROMPT_CHARS`, `LLM_MAX_EVIDENCE_ITEMS`, `LLM_MAX_RESPONSE_CHARS`, `LLM_ASSESSMENT_TOKEN_BUDGET`. Staging and production require a key when enabled |
| Dependency | `pyproject.toml`: optional extra `ai = ["anthropic>=1.0,<2.0"]`. The core dependencies are unchanged |
| Tests | `tests/test_explanations.py` (47), `tests/test_migration_0019.py` (3) |
| Docs | ADR-0012, README (also corrected stale scope statements from M5/M6), technical reference, `.env.example` |

## Blueprint acceptance criteria

| Criterion | Evidence |
| --- | --- |
| Optional; cannot create a confirmed finding | Off by default (400). The contract has no status or severity, and extra fields are rejected. A provider that "obeys" an injection and returns `status: confirmed` gets `schema_validation_failed`, and the findings stay identical (`test_rejected_output_is_unavailable_and_the_finding_survives[injection-obeyed]`) |
| All claims grounded in stored evidence | Every claim and reference must be a supplied finding or evidence ID; invented IDs or CVEs give `ungrounded_output`. The supplied set is stored with each attempt |
| LLM failure never loses scanner results | Timeout, quota, outage, refusal, truncation, auth failure, and an SDK crash are each stored as `unavailable` with a code, and findings are unchanged (`test_provider_failures_are_recorded_not_raised`, 7 cases) |
| Sensitive material redacted before invocation | No raw token reaches the provider for any finding, including the secret finding. No host path, fingerprint, or hash is sent (`test_no_secret_reaches_the_provider`). Scrubber unit tests cover AWS keys, GitHub tokens, JWTs, `password=`, URL credentials, e-mail addresses, bearer tokens, cookies, and private-key blocks. Output is scrubbed too (`test_output_is_scrubbed_before_storage`) |
| Prompt injection in repository files and HTTP responses | An injection comment in the fixture repository, plus injected finding summary and URL path, stay inside the single escaped data block (`test_injection_in_repository_text_stays_inside_the_data_block`, `test_prompt_escapes_injection_and_drops_unneeded_fields`) |
| Invalid JSON, schema failure, malformed or oversized output | `invalid_json`, `schema_validation_failed`, `empty_output`, `output_too_large` |
| Timeouts, bounded retries, size limits, token budgets | SDK `timeout` and `max_retries` from settings; `max_tokens` capped by the remaining budget; budget exhaustion gives 429 without calling the provider (`test_token_budget_per_assessment`) |
| Provenance for reproducibility | Provider, model as reported, prompt template version, supplied IDs, tokens, requester, and time per attempt, plus an audit event without content |
| Mock provider only, no network | A scripted `FakeProvider`, and a fake SDK module for the adapter. The offline socket guard is active. The real SDK is not installed in the test environment |

## Decisions for you

- **Provider and model.** Per D12: Anthropic, `claude-opus-5-5`, effort `medium`.
  **Server-side refusal fallback is on by default** (`LLM_REFUSAL_FALLBACK=true`):
  when the model declines, the provider retries on its default fallback model, and
  the stored `model` shows which model answered. Set it to `false` if you only
  want the configured model.
- **Egress.** The SDK connects to the provider's fixed API host itself, not
  through `GuardedHttpClient`. The host is not configurable and is never derived
  from analysed content. If you need egress control, restrict it at the network
  layer.
- **Pin.** `anthropic>=1.0,<2.0` is declared but has not been installed or run
  here. Before the first real use, install the extra and do one manual smoke test
  with a test key.

## Existing code and tests changed

- **Bug fixed (introduced in M8):** the failure path had its own UPDATE statement
  instead of going through `_transition_run_if_running`. That made
  `test_concurrent_failure_handlers_record_exactly_one_terminal_event` race
  instead of following its intended sequence: it passed in M8 by chance and
  failed once in M9. All terminal transitions now go through one function again.
  The test passed 5/5 after the fix.
- Head pins `0018` → `0019` in migration tests 0010–0018; the 0018 "is head"
  test was renamed `test_0018_revision_chain`.
- `analysis_admission`: new rate-limit scope `analysis.explanation`.

No assertion was weakened.

## Verification

| Check | Result |
| --- | --- |
| `pytest` (full) | **1595 passed, 0 failed, 7 skipped** (Windows-only), no warnings. A full run takes 3m20s without coverage. The 11-minute run was the coverage run under machine load; no single test is slow (the slowest takes 8s) |
| Coverage | 88% overall; explanations package 93–100% (adapter 100%, service 99%) |
| `ruff check` / `ruff format --check` | clean |
| Alembic | head `0019`; `alembic check` reports no drift; full downgrade and re-upgrade OK |
| OpenAPI | 1 new path; 4 new schemas; `AuditAction` and `AuditResourceType` gained one value each; no existing path changed |
| Dependencies | core unchanged; optional `[ai]` extra added |

## Known gaps and risks

- Never exercised against the live provider: the adapter's request shape follows
  the SDK documentation but is only tested against a fake.
- Grounding checks that cited IDs exist, not that each sentence is true. The API
  returns an advisory notice with every explanation.
- The budget check is not transactional, so concurrent requests can overshoot it
  by about one request each.
- The Windows test suite has still not been run. D14 (Docker, PostgreSQL, DVWA)
  remains open.

## Next milestone

M10: LangGraph orchestration. A bounded, auditable workflow over the existing
deterministic tools, with human approval for high-impact steps. The LLM cannot
add targets or invoke arbitrary tools.
