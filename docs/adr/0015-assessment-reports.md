# ADR-0015: JSON and HTML assessment reports

Status: accepted (M12). Date: 2026-11-17.

## Context

Phase 12 asks for trustworthy, portable reports. They must agree with the
persisted findings and show incomplete checks honestly. HTML must be escaped,
with no secrets, absolute paths, or remote resources, and access must follow
assessment authorization. M0 decision D13 proposed Jinja2 with autoescaping and
a strict Content-Security-Policy. Jinja2 is not installed, and adding it needs
owner approval for a new dependency.

## Decision

1. **Reports come only from persisted data.** `build_report` assembles one
   report from the stored assessment, target, analysis run, findings, linked
   evidence, the latest *available* explanation per finding, and the linked
   workflow plan. Nothing is re-scanned, so JSON and HTML always agree with the
   database. The run is the latest completed run by default (else the latest
   failed or cancelled one), or the one given by `analysis_run_id`.
2. **Schema and versioning.**
   - Each report carries `schema_version` (`assessment-report/1`), the
     generator name and version, and `generated_at`.
   - `content_hash` is a SHA-256 over the canonical report without
     `generated_at`: identical data gives an identical hash, and any change
     gives a new one.
   - JSON is serialized with sorted keys, and findings are ordered by severity
     then position.
3. **Content.** The report contains:
   - assessment identity, target summary, and authorization state;
   - run timestamps and status, and tool versions and statuses;
   - completeness, the workflow plan with its configuration snapshot and
     approvals, when the run came from a workflow;
   - an executive summary generated from counts (never by an AI), and counts by
     severity and status;
   - every finding with its locations, evidence, verification method, status
     rationale, and remediation;
   - checks not run (failed, partial, skipped-by-policy, or truncated static
     analysis), limitations, retest summary, and dependency advisory
     references (OSV links derived from advisory IDs);
   - the AI explanation, if one exists, under a fixed "AI-generated, advisory,
     evidence-grounded" label with its model, template, and attributed sources.
4. **Safety.**
   - Every string passes the secret and personal-data scrubber again.
   - Repository targets are shown relative to their allowed root; web targets
     go through URL redaction.
   - Only allowlisted request and response summary keys are included; no
     bodies, fingerprints, or hashes.
   - **HTML autoescaping without a template engine.** The renderer escapes
     every value, quotes included, unless it is a `Safe` fragment built by the
     renderer itself, so a raw string can never reach the output unescaped.
   - The document has no scripts, no images, and no remote assets. Its single
     stylesheet is pinned by SHA-256 in a CSP that is embedded as a meta tag
     (so a saved file is protected) and sent as a header with
     `frame-ancestors 'none'`. Links are rendered only for `https://` URLs.
5. **Delivery.** `GET …/reports/json` and `GET …/reports/html` use the existing
   assessment read authorization. Responses are `attachment` with a UUID-based
   file name, `Cache-Control: no-store`, and `X-Content-Type-Options: nosniff`.
   Limits: `REPORT_MAX_FINDINGS` (the rest are counted as omitted and shown),
   `REPORT_MAX_EVIDENCE_PER_FINDING`, and `REPORT_MAX_BYTES` (413 when larger).
6. **Workflow.** The `generate_report` node, a skip in M10, now builds the
   report and records its schema version, content hash, finding count, and
   incomplete checks in the workflow event. A later download of unchanged data
   hashes identically.

## Consequences

- No new dependency. If Jinja2 is approved later, the renderer can move to
  templates without changing the report schema.
- Reports are generated on demand and not stored. The content hash, plus the
  workflow event, is the durable record of what a report contained.
- Report downloads are not audited yet. That would need another audit-action
  migration, and is a small follow-up if wanted.
