# ADR-0002: Evidence redaction and provenance

- Status: Accepted (M1)
- Date: 2026-11-16

## Context

Secret scanning and HTTP probing observe credentials, cookies, tokens, and
response bodies. Once such a value reaches the database, a log line, an API
response, a test failure message, or an LLM prompt, it cannot be recalled.

## Decision

1. `EvidenceRecord` has no field that can hold a raw sensitive value. It stores a
   location, a bounded `redacted_excerpt` (at most 240 characters), a
   `content_hash`, an optional keyed `fingerprint`, request/response *summaries*,
   provenance, limitations, and metadata.
2. Redaction is done by the pure functions in
   `app/services/tooling/redaction.py` **before** a record is constructed:
   - `redact_excerpt` masks every sensitive span with a fixed-width mask, so the
     length of the value is not revealed. It masks before truncating, so a cut can
     never expose part of a value, and it strips control characters. At most a
     short, non-secret type marker such as `AKIA` may stay visible, and only when
     it reveals at most a quarter of the value.
   - `redact_headers` replaces authorization, cookie, set-cookie, API-key, CSRF,
     and session-token header values.
   - `redact_url` drops user-info and fragments and masks query values whose names
     look sensitive (`token`, `key`, `secret`, `password`, `session`,
     `signature`, `code`, …). Over-redaction is accepted; under-redaction is not.
3. Sensitive values are deduplicated with `keyed_fingerprint` (HMAC-SHA-256 with a
   deployment key of at least 32 bytes). Plain hashes are used only for
   non-sensitive content, because a plain hash of a low-entropy secret can be
   confirmed offline by guessing. The key setting is introduced with its first
   user in M2.
4. Locations are repository-relative paths (POSIX separators, no `..`) or
   origin-relative URL paths. Absolute POSIX, Windows-drive, UNC, and `~` paths are
   rejected by validation.
5. Provenance records the tool identity and version, the rule ID, the observation
   time, and the deterministic method. `evidence_key` is derived from the tool,
   rule, location, and a hash or fingerprint, so a re-run produces the same key.
6. Raw evidence (never stored), sanitized evidence (`EvidenceRecord`), and future
   AI explanations (M9) are separate artifacts. AI output never overwrites
   evidence.

## Consequences

- Every new tool needs redaction tests that search persisted output, logs, and
  exceptions for its synthetic secrets.
- Masked excerpts are less convenient for reviewers; the location and line number
  let them inspect the source directly.
