# ADR-0012: Optional, advisory LLM explanations of findings

Status: accepted (M9). Date: 2026-11-16.

## Context

Deterministic tools produce findings with evidence, a status, and a severity.
Engineers also need plain-language explanations and remediation guidance. The
blueprint (Phase 9) allows an LLM to explain findings, but not to detect
vulnerabilities, change classifications, or receive sensitive material. M0
decision D12 chose a provider-neutral interface with an Anthropic Claude adapter
(official SDK), plus a fake provider for every test.

## Decision

1. **Opt-in and optional.** `LLM_EXPLANATIONS_ENABLED=false` by default. The
   SDK is an optional extra (`pip install ".[ai]"`) and is imported only when a
   request is made. A missing SDK is reported as `provider_not_installed`.
   Staging and production refuse to start with explanations enabled but no
   `LLM_API_KEY`.
2. **On request, per finding.** An analyst calls
   `POST …/findings/{finding_id}/explanations`, and
   `GET …/findings/{finding_id}/explanations` lists attempts. Analysis runs
   never call the provider.
3. **Read-only with respect to results.** The service only reads the finding
   and its evidence. Every attempt is stored in `finding_explanations`
   (migration 0019) with its outcome: `available` with output, or `unavailable`
   with an error code. A provider failure therefore never loses or alters
   scanner results. The output contract has no status, severity, or confidence
   field, and extra fields are rejected.
4. **Minimum necessary, redacted input.** The provider receives:
   - the finding's classification fields;
   - at most `LLM_MAX_EVIDENCE_ITEMS` evidence items, each with location,
     method, a bounded redacted excerpt, and a whitelist of request/response
     summary keys.

   It never receives repository files, response bodies, fingerprints, hashes,
   or host paths. Every string passes a second, independent redaction
   (`scrub_text`) for secret-scanner rule matches, sensitive `name=value`
   pairs, URL credentials, bearer tokens, JWTs, cookies, authorization headers,
   private-key blocks, and e-mail addresses. The prompt is bounded by
   `LLM_MAX_PROMPT_CHARS`; evidence items are dropped (and counted) to fit.
5. **Prompt-injection defence.**
   - The system policy is fixed and versioned (`finding-explanation/1`).
   - All analysed content is JSON inside one `<finding_data>` block, with `<`,
     `>`, and `&` escaped, so it cannot close the block.
   - The policy says the block is untrusted data.
   - No tools are offered, so output cannot invoke anything.
   - Output is accepted only if it validates against the closed schema.
6. **Structured, grounded output.** The provider is asked for JSON via
   `output_config.format`, using a constraint-free copy of the Pydantic schema.
   Pydantic validation on our side is authoritative. Every `claims[].evidence_ids`
   entry and every `evidence_references` entry must be one of the supplied IDs;
   otherwise the result is `ungrounded_output`. Output strings are scrubbed
   again before storage.
7. **Bounded cost and time.**
   - Per-attempt timeout `LLM_TIMEOUT_SECONDS`, with `LLM_MAX_RETRIES` SDK
     retries.
   - `max_tokens` is `min(LLM_MAX_OUTPUT_TOKENS, remaining assessment budget)`.
   - Responses over `LLM_MAX_RESPONSE_CHARS` are rejected.
   - Each assessment has a token budget (`LLM_ASSESSMENT_TOKEN_BUDGET`), and
     failed attempts count toward it.
   - Requests share the per-user analysis rate limiter (scope
     `analysis.explanation`).
8. **Reproducibility.** Each row stores provider, model as reported, prompt
   template version, the supplied ID set, token usage, requester, and time. An
   `finding_explanation.created` audit event records the outcome without
   content.
9. **Anthropic adapter.**
   - Model `claude-opus-5-5`; `output_config.effort` configurable (default
     `medium`).
   - Server-side refusal fallback (`fallbacks: "default"`, beta
     `server-side-fallback-2026-07-01`) is on by default and can be turned off
     with `LLM_REFUSAL_FALLBACK=false`.
   - `stop_reason` `refusal` maps to `provider_refused` and `max_tokens` maps
     to `provider_output_truncated`.
   - SDK errors are mapped most-specific-first to stable codes; provider
     message text is never stored or logged.

## Consequences

- The SDK's HTTP connection to the provider's fixed API host does not go
  through `GuardedHttpClient`. The host is not configurable and never derived
  from analysed content. Operators who need egress control should restrict it
  at the network layer.
- The adapter is tested against a fake SDK, never the real one, because tests
  are offline and the SDK is not a test dependency. The first real use should be
  a manual smoke test with a test key.
- The budget check is not transactional: concurrent requests for one
  assessment can overshoot it by one request each.
- Explanations are advisory text. Grounding checks that cited IDs exist; it
  cannot prove that a sentence is true. The API returns an advisory notice with
  every explanation.
