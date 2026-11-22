# ADR-0009: Bounded runtime XSS and SQL injection probes

- Status: Accepted (M6)
- Date: 2026-11-16

## Context

The crawler (ADR-0008) inventories GET parameters and forms on authorized web
targets. The blueprint asks for conservative, non-destructive XSS and SQL
injection checks whose statuses follow documented proof rules (ADR-0003), with no
claim of confirmation from reflection, error messages, or status/length changes
alone.

## Decision

1. **Opt-in.** `RUNTIME_PROBES_ENABLED=false` by default. When off, the
   `runtime_probes` stage is reported as skipped (`disabled`) and the run is not
   complete. Probes run only after the crawl, on the same authorized target,
   through the same target-bound guarded client. The per-target request rate is
   `WEB_TARGET_MAX_REQUESTS_PER_SECOND` (default 2).
2. **What is probed.** Only GET parameters: query parameters of crawled pages and
   non-hidden fields of same-origin GET forms. POST forms are never submitted
   (limitation `post_forms_not_probed`). Parameters with sensitive names (tokens,
   passwords, sessions, keys) and endpoints matching the crawler's state-changing
   denylist are skipped. Other parameters on the same endpoint are sent with the
   value `1`. Budgets are `RUNTIME_PROBE_MAX_PARAMETERS` (10) and
   `RUNTIME_PROBE_MAX_REQUESTS` (200); exceeding either makes the tool `partial`.
3. **Payloads (inert, read-only).**
   - XSS: a random marker `aisa<10 hex>` (reflection check), then
     `marker"'<aisa<6 hex>>`, an unknown tag with no attributes, scripts, or event
     handlers.
   - SQLi: baseline `1` twice, then `AND` true/false pairs in numeric
     (`1 AND 7=7` / `1 AND 7=8`) and string (`1' AND '7'='7` / `1' AND '7'='8`)
     form, a second pair with new literals, and a single `1'` error probe.
   - Never `OR`, `UNION`, stacked statements, comments, time delays, or data
     extraction.
4. **Comparison.** Response bodies are normalised by removing the sent value (raw,
   HTML-escaped, URL-encoded) and whitespace, then compared line by line
   (`difflib`); different status codes count as different. Thresholds: *same*
   ≥ 0.98, *different* ≤ 0.90. Bodies are never stored, only status, length,
   similarities, and the reflection context.
5. **Proof rules.**
   - XSS reflection with `"`, `'`, `<`, `>` unencoded for its context (HTML text or
     comment: the inert tag appears verbatim; attribute or script: a quote follows
     the marker) is **potential**. It is **inconclusive** if a repeat does not
     reproduce it. It is never **confirmed**: executing script would require a
     browser harness, which is not implemented. Encoded reflection is only counted.
   - Boolean SQLi is **confirmed** only when the baseline is stable (two baselines
     same), the first pair has true = same and false = different, *and* a second
     pair with new literals repeats this with the two false responses matching each
     other. If the first pair differs but the second does not repeat it, the result
     is **inconclusive**.
   - A database error message that appears only after a quote (not in the
     baseline) is **potential** (error signal), never confirmed.
   - An unstable baseline means SQLi is not tested for that parameter (limitation
     `unstable_baseline`).
6. **Findings.** Category `xss` (medium; CWE-79) or `sqli` (boolean: high;
   error signal: medium; CWE-89), one per parameter and rule. Each finding records
   its verification method, request summary (method, parameter, probe kind) and
   response summary.

## Consequences

- The string-context test uses baseline `1`. String parameters whose value `1`
  matches nothing produce identical responses for every probe and are reported as
  *no signal*, not as safe.
- Stored, DOM-based, and POST-only vulnerabilities, and blind SQLi that needs
  timing, are out of scope.
- DVWA integration is not part of the automated suite. Deliberately vulnerable
  local fixtures (real SQLite) stand in until a DVWA lab is provided (decision
  D14).
