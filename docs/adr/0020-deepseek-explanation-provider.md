# ADR-0020: DeepSeek explanation provider (Anthropic-compatible endpoint)

Status: accepted. Date: 2026-11-22.

## Context

Advisory finding explanations (M9, ADR-0012) were available only through
Anthropic. We want DeepSeek (`deepseek-flash`) as a selectable provider without
disrupting the deterministic engine, the explanation service's grounding
guarantees, the LangGraph workflow, or the existing API contract.

DeepSeek exposes an **Anthropic-compatible** Messages endpoint at
`https://api.deepseek.com/anthropic`, so the official `anthropic` SDK (the
existing optional `[ai]` extra) can target it with a `base_url` — no second SDK.

Audit finding: the explanation **service** (`explain_finding`) already validates
the provider's raw **text** itself — parse JSON → validate `FindingExplanationOutput`
(Pydantic) → grounding checks (every cited ID must be supplied) → scrub → store as
`available`/`unavailable`. It only ever reads the finding, so no provider can
change status, severity, or confidence. Provider selection is centralized in
`build_provider()`, which feeds both the direct API and the LangGraph
`explain_findings` node. This made the change small and provider-agnostic.

The Anthropic adapter uses Anthropic-only request features — native structured
output (`output_config`), reasoning `effort`, the server-side `fallbacks` beta,
and the `refusal` stop reason — which DeepSeek's compat endpoint does not accept.
So the existing adapter could not simply be pointed at DeepSeek's `base_url`.

## Decision

1. **Reuse the `anthropic` SDK, add a thin DeepSeek adapter.** New
   `DeepSeekExplanationProvider` constructs `anthropic.Anthropic(base_url=…)` and
   sends a plain `messages.create` (no `output_config`/`effort`/betas). It places
   the required JSON schema in the system prompt instead of native structured
   output. Shared SDK error-mapping and response-extraction live in
   `_sdk_support.py`, used by both adapters, so the plumbing is not duplicated.
   The business logic stays entirely in the unchanged service.

2. **Centralized, selectable provider.** `LLM_PROVIDER` is now
   `anthropic | deepseek`; `build_provider()` selects the adapter. `anthropic`
   stays the default and is unchanged in behaviour.

3. **New settings.** `LLM_BASE_URL` (required for DeepSeek), `LLM_MODEL=deepseek-flash`.
   `validate_security_configuration` requires `LLM_BASE_URL` when
   `LLM_PROVIDER=deepseek` and explanations are enabled in staging/production. The
   adapter raises a clear `provider_not_configured` error (no secret exposed) when
   the key or base URL is missing at request time.

## Why `deepseek-flash`

That is DeepSeek's API model identifier for DeepSeek-V4.1-Flash-1017, set via
`LLM_MODEL`. The adapter passes it straight through as the `model`.

## Consequences

- **Grounding and safety are unchanged and provider-independent.** The model is an
  advisory layer only: it cannot confirm a vulnerability, change a finding's
  status/severity/confidence, invent evidence or HTTP responses, run scans, make
  arbitrary requests, bypass target authorization, or override approval gates. It
  is given no tools. Output that cites anything not supplied, or fails schema
  validation, is rejected and stored as `unavailable`.
- **Prompt injection** inside analysed content (code, URLs, advisory text,
  retrieved docs) is treated as untrusted data: it is JSON-escaped inside a
  `<finding_data>` block and the system policy forbids following it. The
  schema-in-prompt addition does not change this.
- **LangGraph** is untouched: the `explain_findings` node resolves the provider
  through the same `build_provider()`, so DeepSeek works under both the built-in
  and LangGraph engines with no graph changes.
- **Reliability/cost** controls are inherited: per-attempt timeout, bounded output
  tokens, prompt-size limits, SDK retries for transient failures, a per-assessment
  token budget, and graceful provider-unavailable handling. The deterministic
  scanner keeps working if DeepSeek is down; with explanations disabled, no
  external request is ever made.
- **Secrets**: the key and base URL come only from backend settings, never from
  analysed content; they are never logged or returned to the frontend.

## Configuration (local `.env`, never committed)

```env
LLM_EXPLANATIONS_ENABLED=true
LLM_PROVIDER=deepseek
LLM_MODEL=deepseek-flash
LLM_BASE_URL=https://api.deepseek.com/anthropic
LLM_API_KEY=<your DeepSeek key>
```

Default stays `LLM_EXPLANATIONS_ENABLED=false` (no key, no external calls). Enable
and disable by toggling that flag. Install the SDK with `pip install -e ".[ai]"`.

## Testing

- Mocked unit tests (`tests/test_deepseek_provider.py`) inject a scripted fake SDK
  — no network, SDK not required: provider selection, base URL + model, no
  Anthropic-only fields sent, schema injected into the system prompt, error and
  stop-reason mapping, missing key/base URL, SDK not installed, key never logged.
  The provider-agnostic service tests (`tests/test_explanations.py`) already cover
  grounding and no-finding-mutation for any provider.
- An **opt-in live smoke test** (`tests/test_deepseek_live_smoke.py`) runs only
  with `DEEPSEEK_LIVE_TEST=1` and a real `LLM_API_KEY`; it is skipped in ordinary
  runs and must never be part of CI.

```bash
# mocked (default):
pytest tests/test_deepseek_provider.py -q
# live (explicit; real key, makes a real call):
DEEPSEEK_LIVE_TEST=1 LLM_API_KEY=sk-... LLM_PROVIDER=deepseek \
LLM_MODEL=deepseek-flash LLM_BASE_URL=https://api.deepseek.com/anthropic \
pytest tests/test_deepseek_live_smoke.py -q
```
