# ADR-0005: Repository secret scanning

- Status: Accepted (M2)
- Date: 2026-11-16

## Context

Committed credentials are among the most common and most damaging repository
weaknesses. The blueprint requires deterministic, redacted, offline detection with
explicit false-positive handling. M0 recorded three decisions: the scanner may read
`.env` and key files (D5), it uses an in-house rule engine (D6), and it fingerprints
values with a keyed HMAC (D7).

## Decision

1. **Engine.** `app/services/secret_scanning/rules.py` holds a versioned catalog
   (`secret-rules-2026.11.1`) of documented regular expressions:
   - private key blocks;
   - AWS access key IDs and secret keys;
   - GitHub classic and fine-grained tokens;
   - GitLab, Slack, and Stripe live keys;
   - Google API keys;
   - connection strings with embedded passwords;
   - JWTs;
   - secret-like assignments in `.env`-style files;
   - a generic secret-name assignment that additionally requires at least 16
     characters and 3.5 bits/character of entropy.

   Entropy is never the only signal. Operators can add project rules through
   `SECRET_SCAN_CUSTOM_RULES` (validated: `custom.` prefix, compiles, at most one
   group, never matches empty).
2. **Overlaps.** Rules run in priority order. Once a span on a line is claimed by a
   more specific rule, generic rules do not report the same text.
3. **Inputs.** Only files in the validated discovery inventory are read: no
   symlinks, only regular files inside the root, opened with `O_NOFOLLOW` where
   available. Size, total-byte, file-count, and match budgets apply.
   - Binary files, lock files, vendored directories, and minified or generated
     assets are policy exclusions. They are counted but do not make the result
     partial.
   - Oversize, unreadable, or out-of-root files, truncated long lines, budget
     stops, and an incomplete inventory make the result `partial`.
   - `.env` and key files **are** scanned (D5).
4. **Redaction.** No value, excerpt, or path is logged. An excerpt is a bounded
   window (60 characters either side) in which every candidate value on the line is
   masked. That includes values rejected as placeholders or for low entropy, and
   any value assigned to a secret-like name or embedded as a URL password, so a
   weak password never appears even if no rule reported it. Private-key headers are
   shown; key bodies never are. Evidence stores an HMAC-SHA-256 `fingerprint`
   (`EVIDENCE_FINGERPRINT_KEY`, required in staging/production) and never a plain
   hash of the value.
5. **False positives.**
   - Documented provider example values and obvious placeholders (`${VAR}`,
     `<your-key>`, `changeme`, repeated characters, values labelled
     example/placeholder/dummy) are counted as `placeholders_ignored` and listed as
     a limitation.
   - Test and example paths are still reported, with halved confidence and an
     explanatory limitation.
   - Suppression requires a `SECRET_SCAN_ALLOWLIST` entry naming one rule, one
     non-global repository-relative glob, and a reason of at least 10 characters.
     Every suppression is counted and its reason is listed in the result.
6. **Findings.** Evidence is grouped by fingerprint into one finding per value, with
   one evidence item per location. Findings have category `secret` and status
   **`potential`**: detection proves only that a credential-shaped value is
   committed. The scanner never calls providers or tries to log in, so validity is
   untested. Severity comes from the rule; confidence comes from the rule and the
   file context.
7. **Execution.** The scanner is the first tool run through the registry inside
   analysis runs (`app/services/analysis_tools.py`). The static pipeline still runs
   directly (its intermediate results feed the run metadata) until evidence
   normalization in M7. A failed, skipped (`SECRET_SCAN_ENABLED=false`), or partial
   scanner is listed in `analysis_metadata.tools` and makes
   `completeness.is_complete` false. It never yields a silent clean result.
   Cancellation and run deadlines are checked per file.

## Consequences

- `finding_status` gains `potential` (migration `0015`). The downgrade refuses
  while `potential` rows exist.
- Secret findings are added to analysis runs, so `findings_count` grows for
  repositories that contain secrets.
- Detection is regex-based and line-oriented: secrets split across lines,
  encoded, or encrypted are not found, and formats not in the catalog are found
  only by the generic rule. The catalog version is recorded with every result so
  that results can be reproduced.
