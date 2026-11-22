# AI Security Analyst --- Advanced Security Engine Implementation Blueprint

**Purpose:** Extend the existing AI Security Analyst backend into the
substantial, evidence-driven web security assessment platform originally
envisioned for the project.

**Implementation agent:** Claude Code\
**Engineering owner:** Project owner\
**Working rule:** Claude Code implements bounded milestones; the project
owner reviews each milestone before the next begins.

------------------------------------------------------------------------

## 1. Why this document exists

The current backend is a meaningful foundation, not the finished product
vision. The existing implementation includes FastAPI APIs,
authentication and sessions, role-based authorization, assessment
management, repository discovery, technology detection, static
attack-surface analysis, evidence correlation, audit events, and
analysis admission controls.

The next work is the major security-analysis capability:

1.  Secret scanning.
2.  Dependency vulnerability analysis using CVE/advisory data.
3.  Runtime web crawling.
4.  Controlled runtime XSS and SQL injection testing.
5.  HTTP-based evidence collection and finding verification.
6.  LLM-assisted finding explanations and remediation.
7.  LangChain/LangGraph orchestration.
8.  Curated security knowledge RAG.
9.  HTML reporting.
10. Durable background execution, cancellation, and stale-run recovery.
11. PostgreSQL support and production database verification.

These features must be built as a coherent security analysis system, not
as disconnected demos. Deterministic tools discover and verify evidence.
AI explains, prioritizes, and helps plan bounded actions; it must not
invent vulnerabilities or independently authorize targets.

------------------------------------------------------------------------

## 2. Non-negotiable engineering rules

### 2.1 Preserve the working backend

Before implementation:

-   Inspect the actual repository and its current state.
-   Read `README.md`, `FINAL_PROJECT_RELEASE_REPORT.md`,
    `docs/TECHNICAL_REFERENCE.md`, project context, original plan,
    migrations, models, services, APIs, and tests when available.
-   Treat the current code as authoritative for what exists.
-   Do not assume file names, API paths, model fields, or migration
    numbers from this plan.
-   Preserve existing authentication, authorization, assessment
    ownership, audit logging, and security controls.
-   Do not rewrite working subsystems merely to match a proposed
    architecture.
-   Never discard user changes, reset the repository, or rewrite Git
    history.
-   Make a verified backup before broad changes. Use Git
    branches/commits only with the owner's approval.

### 2.2 Build deterministic security analysis before AI

The core pipeline must work without an LLM:

-   Repository analysis and static checks produce structured evidence.
-   Runtime tools collect HTTP observations.
-   Deterministic verification rules classify evidence.
-   Finding policy derives status, severity, confidence, and
    limitations.
-   AI may explain or prioritize existing findings, but cannot promote
    an unverified suspicion to a confirmed vulnerability.

### 2.3 Safe testing only

Only assess targets for which the user has explicit authorization.
Default development targets should be localhost and a controlled DVWA
instance.

-   Enforce an explicit target allowlist.
-   Reject loopback/private/link-local/metadata destinations unless they
    are explicitly configured as authorized local targets for the
    assessment environment.
-   Revalidate DNS resolution and every redirect; prevent DNS rebinding
    and redirect-based SSRF.
-   Do not allow arbitrary URL, file, or network access from
    user-controlled repository content.
-   Apply request, page, depth, time, response-size, concurrency, and
    total-run limits.
-   Do not perform destructive tests, data extraction, persistence,
    credential attacks, or denial-of-service testing.
-   SQLi/XSS checks must use harmless, bounded probes against controlled
    targets.
-   Do not scan public third-party systems without explicit
    authorization.

### 2.4 Evidence integrity

Every finding must distinguish:

-   `confirmed`: deterministic verification meets a documented proof
    rule.
-   `potential`: a signal exists but is not enough to confirm.
-   `not_reproduced`: a prior signal could not be reproduced.
-   `inconclusive`: evidence is ambiguous or incomplete.
-   `not_tested`: the relevant check did not run.

Do not call reflected input executable XSS without proving execution in
a safe test context. Do not call a generic SQL error or status-code
change confirmed SQL injection. Keep raw evidence, sanitized evidence,
and AI-generated explanation separate.

------------------------------------------------------------------------

## 3. Target architecture

Extend the current architecture incrementally. Adapt names to the
existing repository.

``` mermaid
flowchart TD
    UI[Client / API Consumer] --> API[FastAPI API]
    API --> AUTH[Authentication, Authorization, Target Policy]
    AUTH --> DB[(SQLite now / PostgreSQL target)]
    API --> JOB[Durable Assessment Job]
    JOB --> WORKER[Worker / Execution Runtime]

    WORKER --> ORCH[Deterministic Assessment Pipeline]
    ORCH --> REPO[Repository Intake & Static Analysis]
    ORCH --> CRAWL[Safe HTTP Crawler]
    REPO --> SECRET[Secret Scanner]
    REPO --> DEP[Dependency & CVE Analyzer]
    REPO --> AST[Existing AST / Attack-Surface Analyzers]
    CRAWL --> XSS[Bounded XSS Checks]
    CRAWL --> SQLI[Bounded SQLi Checks]

    SECRET --> EVID[Evidence Normalization & Correlation]
    DEP --> EVID
    AST --> EVID
    XSS --> EVID
    SQLI --> EVID

    EVID --> POLICY[Deterministic Finding Policy]
    POLICY --> STORE[(Findings, Evidence, Run Events)]
    STORE --> AI[Optional LLM Explanation / LangGraph]
    KB[(Curated OWASP / CWE / Project Guidance)] --> RAG[RAG Retrieval]
    RAG --> AI
    AI --> STORE
    STORE --> REPORT[JSON / HTML Reports]
    REPORT --> API
```

### Architectural boundaries

-   **API layer:** validation, authentication, authorization, job
    submission, status and report retrieval.
-   **Application services:** assessment lifecycle, target policy,
    orchestration, cancellation.
-   **Analysis tools:** isolated deterministic scanners and analyzers.
-   **Evidence layer:** normalized observations, provenance, redaction,
    correlation.
-   **Finding policy:** deterministic status/severity/confidence rules.
-   **AI layer:** optional explanation and planning grounded in stored
    evidence.
-   **Persistence:** assessments, runs, jobs, findings, evidence, audit
    events and report metadata.
-   **Worker runtime:** durable execution, leases, heartbeats,
    cancellation and recovery.

Do not couple scanners directly to FastAPI request handlers or make
scanner modules write arbitrary database records.

------------------------------------------------------------------------

## 4. Required shared data contracts

First inspect existing Pydantic schemas and SQLAlchemy models. Reuse and
evolve them; do not create duplicate concepts.

The implementation should support these logical records.

### 4.1 Assessment target

-   `id`
-   `assessment_id`
-   `target_type` (`repository` or `web_application`)
-   `canonical_target`
-   `authorization_record` or explicit authorization metadata
-   `created_by`
-   `created_at`
-   `policy_snapshot`
-   `status`

Target ownership and authorization must be explicit. Shared allowed
filesystem roots alone are not sufficient for multi-user isolation.

### 4.2 Analysis run

-   `id`
-   `assessment_id`
-   `status`
-   `started_at`, `finished_at`
-   `heartbeat_at`
-   `lease_owner`, `lease_expires_at`
-   `cancel_requested_at`
-   `stage`
-   `progress`
-   `error_code` (safe, non-sensitive)
-   `configuration_snapshot`
-   `tool_versions`

Use atomic database transitions and conditional updates to prevent two
workers from claiming the same run.

### 4.3 Evidence

-   `id`
-   `assessment_id`, `analysis_run_id`
-   `source_type` (repository, dependency, HTTP, crawler, runtime probe,
    AI reference)
-   `tool_name`, `tool_version`
-   `rule_id`
-   `location` (relative file path, URL path, parameter name; never leak
    server absolute paths)
-   `observed_at`
-   `request_summary` and `response_summary` where applicable
-   `redacted_excerpt`
-   `content_hash`
-   `provenance`
-   `limitations`
-   `metadata`

Avoid storing secrets, session cookies, authorization headers, full
sensitive response bodies, or unnecessary personal data. Apply redaction
before persistence and before any external LLM call.

### 4.4 Finding

-   `id`
-   `assessment_id`, `analysis_run_id`
-   `rule_id`, `title`, `description`
-   `category` (secret, dependency, xss, sqli, configuration, etc.)
-   `severity`
-   `status`
-   `confidence`
-   `affected_component`
-   `evidence_ids`
-   `cwe_ids`, `cve_ids` when applicable
-   `recommendation`
-   `first_seen_at`, `last_seen_at`
-   `verification_method`
-   `false_positive_reason` where applicable

Severity, confidence, and verification status are different dimensions.
Do not conflate them.

### 4.5 Tool result

Each tool returns a typed result with:

-   tool identity and version
-   start/end timestamps
-   status (`completed`, `partial`, `failed`, `skipped`, `cancelled`)
-   counts
-   evidence references
-   warnings and limitations
-   resource usage
-   safe error code

------------------------------------------------------------------------

## 5. Implementation roadmap

Implement these phases in order. Claude Code must stop after each phase,
report results, and wait for explicit approval before continuing.

# Phase 1 --- Foundation and execution contracts

### Goals

Prepare a stable extension seam for the new scanners.

### Work

1.  Inventory existing models, services, APIs, run lifecycle, analysis
    pipeline, and migration head.
2.  Map current findings/evidence fields to the shared contracts above.
3.  Identify duplicate concepts and reuse existing ones.
4.  Define scanner/tool protocols and typed results.
5.  Define a stage registry and pipeline configuration.
6.  Define target authorization and network safety policy interfaces.
7.  Define evidence redaction and provenance rules.
8.  Add architecture decision records for significant choices.

### Acceptance criteria

-   Existing API behavior remains compatible.
-   Existing tests pass.
-   New contracts have unit tests.
-   No scanner has been implemented yet.
-   No unneeded schema redesign.
-   The pipeline can register a tool and consume a typed result without
    knowing its implementation.

# Phase 2 --- Secret scanning

### Goal

Detect accidentally committed credentials and sensitive tokens in
authorized repositories.

### Scope

Support common patterns such as:

-   Cloud provider access-key formats.
-   GitHub/GitLab-style tokens.
-   Private key blocks.
-   Database connection strings.
-   JWT-like tokens.
-   Generic high-entropy candidate strings, with conservative
    confidence.
-   Project-specific patterns configured by rules.

Use a maintained scanner/library if it fits the project, or implement a
small rule engine with documented patterns. Do not invent a weak
home-grown entropy detector as the only mechanism.

### Safety and quality

-   Never print secret values in logs, API responses, test failures, or
    LLM prompts.
-   Persist only a redacted excerpt, fingerprint/hash, location and rule
    ID.
-   Exclude `.git`, virtual environments, build outputs, dependency
    caches, binaries and configured ignore paths.
-   Support file-size and total-byte limits.
-   Avoid scanning generated or vendored content by default.
-   Detect test fixtures and examples carefully; do not silently
    suppress all test files.
-   Make allowlisting explicit, auditable and narrow.
-   Do not validate discovered credentials by attempting to log in or
    call provider APIs.

### Tests

-   Known synthetic secrets for each rule.
-   Near-miss values and ordinary strings.
-   Redaction and no-secret-in-logs assertions.
-   Ignore rules, symlinks, oversized files and binary files.
-   Duplicate finding deduplication.
-   Windows and POSIX path handling.

### Acceptance criteria

-   Results are deterministic and explain which rule matched.
-   Secret material never appears in persisted output or logs.
-   Findings include relative paths and line numbers where safe.
-   False-positive handling is explicit.
-   No network requests are made by the secret scanner.

# Phase 3 --- Dependency inventory and CVE analysis

### Goal

Identify dependencies and match versions against trustworthy
vulnerability advisory sources.

### Input formats

Start with the formats actually used in the project and prioritize:

-   Python `requirements.txt` and pinned variants.
-   `pyproject.toml` / lock files.
-   `Pipfile.lock` if present.
-   `poetry.lock` if present.
-   `package-lock.json`, `pnpm-lock.yaml`, or `yarn.lock` only if
    JavaScript repositories are in scope.

Do not claim complete ecosystem support unless tested.

### Design

1.  Parse manifests and lock files without executing project code.
2.  Normalize package name, ecosystem, version and dependency source.
3.  Prefer lock-file-resolved versions over broad manifest ranges.
4.  Match against a documented advisory source such as OSV or another
    approved provider.
5.  Cache responses with freshness metadata.
6.  Handle provider outages, timeouts, quotas and partial results.
7.  Record advisory ID, affected version range, fixed version, source
    URL, published/modified timestamps and match rationale.
8.  Distinguish direct and transitive dependencies when the input format
    supports it.
9.  Do not automatically upgrade packages.

### Security

-   No shelling out to package managers to install or execute target
    dependencies.
-   No execution of repository build scripts.
-   Network access only to configured advisory endpoints.
-   Strict timeouts, response-size limits and cache controls.
-   Treat advisory content as untrusted data.

### Tests

-   Vulnerable, fixed and unaffected synthetic package/version fixtures.
-   Version-range boundaries and prerelease handling.
-   Unknown versions and malformed manifests.
-   Provider timeout, invalid response and rate limit.
-   Cache expiry and stale-data labeling.
-   Offline mode.

### Acceptance criteria

-   Every CVE/advisory match has a reproducible version-range
    explanation.
-   Missing advisory data is reported as unavailable, not "no
    vulnerabilities."
-   No repository code is executed.
-   Results show source and data freshness.

# Phase 4 --- Safe runtime target authorization and HTTP client

### Goal

Build the safety foundation before adding a crawler or probes.

### Required controls

-   Explicit authorized target registration/confirmation.
-   Canonicalize hostnames, schemes, ports and paths.
-   Allow only approved schemes (normally HTTP/HTTPS).
-   Resolve DNS and reject prohibited addresses unless explicitly
    allowed by local test policy.
-   Re-check the destination after redirects and DNS changes.
-   Reject credentials in URLs.
-   Block cloud metadata endpoints and sensitive internal ranges by
    default.
-   Prevent redirects to unapproved hosts.
-   Enforce maximum redirect count.
-   Apply connect/read/total timeouts.
-   Limit response bytes, decompression ratio and content types.
-   Set a clear User-Agent identifying the scanner.
-   Add per-target concurrency and request-rate budgets.
-   Redact cookies, authorization headers, query secrets and sensitive
    response data.
-   Make all network access go through this single policy-enforcing
    client.

Never let individual scanner modules call `requests`, `httpx`, or raw
sockets directly without the policy wrapper.

### Tests

Use a local mock HTTP server and unit tests. Include:

-   Public-looking hostname resolving to a private address.
-   Redirect to loopback or metadata endpoint.
-   Redirect to another host.
-   DNS rebinding simulation.
-   IPv4 and IPv6 edge cases.
-   Slow response, oversized response and decompression bomb protection.
-   Invalid scheme and embedded URL credentials.
-   Redirect loops and malformed Location headers.

### Acceptance criteria

-   All runtime network tools use the same guarded client.
-   Unsafe destinations are blocked before sending a request.
-   Redirects and resolved addresses are revalidated.
-   Limits are configurable but have safe defaults.

# Phase 5 --- Runtime web crawler

### Goal

Discover pages, links, forms and input points on explicitly authorized
web applications.

### Initial scope

-   Start from explicitly supplied base URLs.
-   Same-origin crawling by default.
-   Parse HTML links and forms.
-   Record method, action, input name/type, query parameters and content
    type.
-   Respect configured path exclusions and crawl budget.
-   Support a configurable maximum depth and page count.
-   Deduplicate canonical URLs and equivalent forms.
-   Record status code, content type, redirect chain and page metadata.
-   Identify authentication boundaries without attempting credential
    guessing.
-   Do not submit destructive forms.
-   Do not follow logout, delete, purchase, payment, upload, or
    state-changing actions unless a specific safe test policy explicitly
    allows a harmless controlled action.

Robots.txt handling should be configurable and documented. It is not an
authorization mechanism.

### Tests

-   Local fixture site with links, forms, query parameters and duplicate
    URLs.
-   Same-origin boundary.
-   Redirect handling.
-   Crawl depth and page budget.
-   Excluded paths and content types.
-   Form method/action parsing.
-   No destructive form submission.
-   Cancellation and time-budget enforcement.

### Acceptance criteria

-   Crawler returns a structured endpoint/form inventory.
-   Every request passes through the safe HTTP client.
-   Crawl limits are enforced.
-   The crawler does not submit arbitrary forms.
-   Results are repeatable against a fixed local fixture.

# Phase 6 --- Runtime XSS and SQL injection checks

### Goal

Add conservative, non-destructive runtime checks against controlled
applications such as DVWA.

### XSS checks

-   Identify candidate parameters and form inputs from crawler
    inventory.
-   Use unique, harmless marker payloads.
-   Determine whether the marker is reflected.
-   Classify reflection context (HTML text, attribute, script, URL,
    etc.) where feasible.
-   Check encoding/escaping behavior.
-   Do not classify reflection alone as confirmed XSS.
-   Confirm executable behavior only in an isolated browser/test harness
    with a harmless proof, if such a harness is explicitly approved and
    implemented.
-   Never use payloads that steal cookies, exfiltrate data, persist, or
    affect other users.

### SQL injection checks

-   Use bounded, non-destructive differential probes on approved test
    targets.
-   Compare stable baseline responses with probe responses.
-   Account for dynamic content and noisy status/length differences.
-   Treat generic SQL error messages as signals, not proof.
-   Do not dump data, enumerate schemas, bypass authentication, or
    alter/delete data.
-   Use only harmless boolean/time-independent comparisons initially;
    avoid time-delay payloads in the first release.

### Verification model

Possible results:

-   `potential`: signal observed but not verified.
-   `confirmed`: strong, repeatable, deterministic proof under the
    documented safe verification policy.
-   `inconclusive`: unstable or conflicting response.
-   `not_reproduced`: signal no longer reproduced.
-   `not_tested`: tool unavailable or policy prevented execution.

### Tests

-   Controlled local vulnerable fixtures.
-   Safe non-vulnerable fixtures.
-   Reflection without execution.
-   Encoded reflection.
-   SQL error without injection.
-   Differential response noise.
-   Parameter and form handling.
-   Request budget enforcement.
-   No destructive requests.

### Acceptance criteria

-   No finding is marked confirmed based only on a generic error,
    reflection, status code or response-length change.
-   Each finding links to request/response evidence with secrets
    redacted.
-   Probes are rate-limited and bounded.
-   DVWA integration tests are opt-in and never run against public
    targets.

# Phase 7 --- Evidence normalization, correlation and finding policy

### Goal

Unify static and runtime evidence into trustworthy findings.

### Work

-   Normalize evidence from secret, dependency, static AST, crawler, XSS
    and SQLi tools.
-   Deduplicate by stable rule/target/location identity.
-   Correlate static input-to-sensitive-operation paths with runtime
    endpoints when evidence supports the relationship.
-   Preserve provenance and tool versions.
-   Store sanitized request/response excerpts and content hashes.
-   Separate evidence from AI explanations.
-   Add confidence and status policy with documented rules.
-   Track first seen, last seen and retest history.
-   Support findings that have multiple evidence items.
-   Ensure a failed or skipped tool cannot silently produce an empty
    "clean" result.

### Acceptance criteria

-   Every finding has one or more traceable evidence references.
-   Findings explain why the status and severity were assigned.
-   Missing/failed checks are visible in the run summary.
-   Static suspicion and runtime verification remain distinguishable.
-   Existing finding API contracts remain compatible or are versioned.

# Phase 8 --- Durable background execution and recovery

### Goal

Move long-running assessment work out of API request lifetimes.

### Design decision first

Inspect current run lease/heartbeat/cancellation columns and current
admission control. Choose the simplest durable worker model appropriate
for the existing deployment.

Potential approaches: - Database-backed worker queue with atomic
claim/lease operations for a single-node initial deployment. - A
dedicated queue system only if deployment scale and operational needs
justify it.

Do not introduce Celery, Redis, or another service by default without an
architecture decision and clear operational benefit.

### Required behavior

-   API creates a run/job and returns a stable run ID.
-   Worker atomically claims a queued job.
-   Lease ownership and expiration are enforced.
-   Heartbeats update progress.
-   Cancellation is persisted and checked between bounded operations.
-   Worker shutdown leaves jobs recoverable.
-   Expired leases can be reclaimed safely.
-   Retry policy distinguishes transient from permanent failures.
-   Retries are idempotent and do not duplicate findings/events.
-   Per-assessment and global concurrency budgets are enforced across
    workers where supported.
-   Run history captures stage transitions and safe errors.
-   GET summary/report endpoints read persisted results; they must not
    silently rerun the analysis pipeline.

### Tests

-   Two workers attempting to claim one job.
-   Worker crash after claim.
-   Lease expiration and recovery.
-   Cancellation before start and during execution.
-   Retry after transient failure.
-   Permanent failure.
-   Duplicate delivery/idempotency.
-   Shutdown and restart.
-   Concurrent status transitions.

### Acceptance criteria

-   A long assessment does not depend on the lifetime of an HTTP
    request.
-   Jobs survive process restart.
-   Stale jobs are recoverable.
-   Cancellation is effective at documented checkpoints.
-   No duplicate findings from retries.
-   Job state and assessment state cannot contradict each other.

# Phase 9 --- LLM-assisted explanations

### Goal

Use an LLM to make deterministic findings understandable and actionable
without making it the vulnerability detector.

### Work

-   Define a provider abstraction and configuration.
-   Keep provider credentials in secret settings only.
-   Add strict timeouts, bounded retries and response-size limits.
-   Add cost/token budgets per assessment and per finding.
-   Send only redacted, minimum-necessary evidence.
-   Do not send repository files wholesale.
-   Do not send secrets, cookies, tokens, private keys or sensitive
    personal data.
-   Treat repository text, HTTP responses, package metadata and advisory
    descriptions as untrusted prompt content.
-   Defend against prompt injection: content under analysis must never
    change system policy, authorize new targets, request secrets, or
    invoke arbitrary tools.
-   Require structured output validated by Pydantic.
-   Validate that every factual claim references supplied
    finding/evidence IDs.
-   If the provider fails, preserve the deterministic finding and mark
    explanation as unavailable.
-   Store model/provider/version, prompt template version, timestamp and
    evidence references for reproducibility.
-   Do not allow LLM output to alter severity/status without
    deterministic policy approval.

### Output schema

For each finding, produce:

-   concise summary
-   technical explanation
-   impact
-   affected component
-   evidence references
-   remediation steps
-   validation/retest guidance
-   uncertainty and limitations

### Tests

-   Mock provider only in unit tests.
-   Invalid JSON and schema failures.
-   Hallucinated evidence IDs.
-   Prompt-injection strings inside repository files and HTTP responses.
-   Timeout, quota, provider outage and malformed output.
-   Secret-redaction assertions.
-   No-network unit tests.

### Acceptance criteria

-   AI explanation is optional and cannot create a confirmed finding.
-   All claims are grounded in stored evidence.
-   LLM failure never loses scanner results.
-   Sensitive material is redacted before provider invocation.

# Phase 10 --- LangChain and LangGraph orchestration

### Goal

Introduce agentic orchestration only after deterministic tools,
contracts, evidence, and worker execution are stable.

### LangChain use

Use LangChain only where it provides a concrete benefit, such as
provider adapters, structured model output, or retrieval integration. Do
not wrap every service in an agent abstraction.

### LangGraph workflow

A bounded graph may contain:

1.  `load_assessment`
2.  `validate_authorization`
3.  `plan_enabled_checks`
4.  `run_repository_checks`
5.  `run_dependency_checks`
6.  `run_crawler`
7.  `run_runtime_checks`
8.  `normalize_evidence`
9.  `apply_deterministic_finding_policy`
10. `explain_findings`
11. `generate_report`
12. `finalize_run`

The graph may choose among pre-approved checks based on available
evidence and assessment configuration. It must not invent targets or
arbitrary URLs.

### Tool governance

-   Allowlisted tools only.
-   Typed inputs and outputs.
-   Per-tool budgets and timeouts.
-   Maximum graph steps and retry counts.
-   Persisted graph state.
-   Human approval for any new target or higher-risk test category.
-   No shell execution, arbitrary Python execution, or unrestricted
    network tools.
-   Deterministic policy remains authoritative for confirmed findings.

### Acceptance criteria

-   Workflow is bounded and replayable.
-   State is persisted and recoverable.
-   Tool invocation is authorized and auditable.
-   Agent decisions cannot bypass target policy or resource budgets.
-   The deterministic pipeline still works with AI disabled.

# Phase 11 --- Curated security RAG

### Goal

Provide grounded remediation context from a curated security knowledge
base.

### Sources

Use approved, versioned sources such as: - OWASP guidance and cheat
sheets. - CWE descriptions. - CVE/advisory records from the selected
advisory provider. - Project-maintained remediation guidance.

Respect source licenses, attribution, update cadence and content
provenance. Do not indiscriminately ingest arbitrary websites.

### Pipeline

-   Collect approved documents.
-   Store source, version, publication/update date and license metadata.
-   Normalize and chunk content.
-   Generate embeddings through a configured provider.
-   Store vectors in FAISS initially if local deployment is appropriate.
-   Retrieve a small number of relevant chunks.
-   Filter by finding category/CWE and source freshness.
-   Cite source IDs in generated explanations.
-   Treat retrieved text as untrusted context, not instructions.
-   Provide a graceful fallback if vector search or embedding provider
    is unavailable.

### Tests

-   Chunking and metadata preservation.
-   Retrieval relevance on a small curated fixture.
-   Source attribution.
-   Stale document handling.
-   Prompt-injection text inside retrieved content.
-   Embedding/provider failure.
-   No secrets in indexed documents.

### Acceptance criteria

-   AI explanations cite retrieved source IDs.
-   Retrieval never changes finding status.
-   Knowledge base is reproducible and versioned.
-   RAG can be disabled without breaking scanning.

# Phase 12 --- JSON and HTML reporting

### Goal

Generate trustworthy, portable assessment reports.

### Report content

-   Assessment identity and authorized target summary.
-   Run timestamps and tool versions.
-   Scope and policy configuration.
-   Executive summary.
-   Finding counts by severity and status.
-   Individual findings with affected locations.
-   Evidence and verification method.
-   Remediation recommendations.
-   Checks not run, failures and limitations.
-   Dependency advisory references.
-   AI explanation clearly labeled as AI-generated and
    evidence-grounded.
-   Report generation timestamp and report version.

### Security

-   Escape all HTML output.
-   Use templates with autoescaping.
-   Prevent stored/reflected XSS in report fields.
-   Do not expose absolute server paths, secrets, raw tokens or
    sensitive headers.
-   Enforce assessment authorization on report download.
-   Apply response size limits and safe content disposition.
-   Avoid loading remote resources in generated reports by default.

### Tests

-   HTML escaping with malicious titles/paths/evidence.
-   Sensitive-value redaction.
-   Authorization.
-   Empty/partial/failed runs.
-   Deterministic JSON schema.
-   Report versioning.

### Acceptance criteria

-   JSON and HTML reports agree with persisted findings.
-   Reports explicitly show incomplete checks.
-   HTML output is safely escaped.
-   Report access follows existing assessment authorization.

# Phase 13 --- PostgreSQL support

### Goal

Make the persistence layer genuinely portable and verify concurrency
semantics against PostgreSQL.

### Work

-   Inspect SQLAlchemy models and Alembic migrations for SQLite-specific
    assumptions.
-   Add PostgreSQL driver and documented configuration.
-   Review partial indexes, constraints, JSON types, server defaults,
    transaction behavior and locking.
-   Verify atomic job claim/lease updates.
-   Verify unique constraints and expected integrity-error
    classification.
-   Test migration from an empty database and supported upgrade path.
-   Add a PostgreSQL test service in CI or a reproducible local Compose
    test setup.
-   Verify concurrent session refresh, token consumption, role
    assignment, job claiming and finding persistence.
-   Document backup/restore and migration operations.

### Acceptance criteria

-   All migrations apply on PostgreSQL.
-   Model drift check passes.
-   Concurrency tests pass on PostgreSQL, not merely SQLite.
-   No claim of PostgreSQL production support until these checks are
    recorded.
-   SQLite remains supported for local development if practical.

------------------------------------------------------------------------

## 6. Cross-cutting non-functional requirements

Every phase must consider:

### Reliability

-   Explicit timeouts and cancellation.
-   Bounded retries with jitter where appropriate.
-   Idempotent writes.
-   Clear partial-failure behavior.
-   Structured run-stage events.

### Security

-   Authentication and assessment authorization on every relevant API.
-   Explicit target authorization.
-   SSRF-resistant HTTP client.
-   Safe file path handling and archive extraction if archive intake is
    later added.
-   Secret redaction.
-   No shell execution of target content.
-   No arbitrary tool invocation from LLM output.
-   Secure configuration and safe defaults.

### Observability

-   Structured logs with run/assessment correlation IDs.
-   Never log secrets, tokens, full sensitive bodies or raw credentials.
-   Metrics for run duration, tool failures, queue depth, rate limiting
    and resource use.
-   Retention policies for audit, evidence and token records.

### Performance

-   File, page, response, request, CPU/time and concurrency budgets.
-   Avoid repeatedly parsing the same repository files; consider a
    shared parsed-source cache after profiling.
-   Do not let summary/report GET endpoints rerun scans.
-   Avoid loading huge evidence blobs into memory.

### Compatibility

-   Keep API schemas versioned.
-   Document migrations and configuration changes.
-   Add Windows and POSIX path tests.
-   Keep deterministic tools usable without external AI providers.

------------------------------------------------------------------------

## 7. Suggested delivery sequence

This is a substantial project. Do not attempt all phases in one Claude
Code session.

  ------------------------------------------------------------------------------
  Milestone               Scope                          Exit condition
  ----------------------- ------------------------------ -----------------------
  M0                      Repository re-audit and        Current contracts and
                          architecture decisions         safe extension plan
                                                         approved

  M1                      Shared tool/evidence contracts Existing tests pass;
                                                         typed tool seam works

  M2                      Secret scanning                Deterministic,
                                                         redacted, tested
                                                         results

  M3                      Dependency/CVE analysis        Reproducible advisory
                                                         matches and freshness

  M4                      Safe HTTP client and target    SSRF and redirect
                          authorization                  protections tested

  M5                      Runtime crawler                Bounded endpoint/form
                                                         inventory

  M6                      XSS/SQLi checks                Safe controlled checks
                                                         with evidence-based
                                                         statuses

  M7                      Evidence correlation and       Unified trustworthy
                          finding policy                 findings

  M8                      Durable                        Restart-safe job
                          worker/cancellation/recovery   execution

  M9                      LLM explanations               Optional grounded
                                                         output with redaction

  M10                     LangGraph orchestration        Bounded, auditable
                                                         workflow

  M11                     RAG                            Curated, attributed
                                                         retrieval

  M12                     HTML/JSON reports              Safe authorized report
                                                         generation

  M13                     PostgreSQL                     Migration and
                                                         concurrency
                                                         verification
  ------------------------------------------------------------------------------

Do not skip M4 before runtime scanning. Do not start M9--M11 before
deterministic findings and evidence are stable. Do not start M10 just to
claim that LangGraph is used.

------------------------------------------------------------------------

## 8. Required Claude Code working protocol

Use this prompt at the start of implementation:

> You are the senior backend architect and application security engineer
> implementing the next major capabilities of the existing AI Security
> Analyst project.
>
> Read this blueprint and inspect the actual repository before changing
> code. Also read the current README, release report, technical
> reference, project context and original project plan when available.
>
> Do not assume this blueprint describes existing code. Verify every
> model, service, route, migration, test and setting.
>
> Start with **M0 only**. Produce:
>
> 1.  Current architecture and feature inventory.
> 2.  Mapping of existing code to the shared contracts in this
>     blueprint.
> 3.  Gaps and design decisions.
> 4.  Proposed file-level change plan for M1.
> 5.  Migration/API compatibility risks.
> 6.  Security risks and test plan.
> 7.  Exact acceptance criteria.
>
> Do not implement M1 or any later milestone until the owner reviews and
> approves the M0 report.
>
> For each approved milestone:
>
> -   Make small, reviewable changes.
> -   Add tests with the implementation.
> -   Keep unit tests offline and deterministic.
> -   Use temporary databases for migration tests.
> -   Use local fixtures for runtime tests.
> -   Never scan an unauthorized target.
> -   Run the full relevant test suite.
> -   Inspect the complete diff.
> -   Report changed files, commands, results, known gaps and risks.
> -   Stop and wait for approval before moving to the next milestone.
>
> Preserve existing work. Never reset, clean, discard, or overwrite user
> changes. Never commit or push without explicit approval.
>
> Deterministic scanners and evidence policy are authoritative. AI is an
> optional explanation/orchestration layer and must never invent
> evidence, authorize targets, or independently mark a finding
> confirmed.

------------------------------------------------------------------------

## 9. Definition of done for the major project

The expanded backend should not be called complete until all of the
following are true:

-   [ ] Repository secret scanning works with safe redaction.
-   [ ] Dependency inventory and advisory matching work with
    source/freshness metadata.
-   [ ] Target authorization and SSRF-safe HTTP client are tested.
-   [ ] Crawler discovers pages, endpoints, forms and parameters within
    limits.
-   [ ] Runtime XSS and SQLi checks work against controlled fixtures and
    DVWA.
-   [ ] Findings are backed by normalized evidence and deterministic
    verification rules.
-   [ ] Partial, skipped, failed and inconclusive checks are represented
    honestly.
-   [ ] Background runs survive process restart and support
    cancellation/recovery.
-   [ ] LLM explanations are optional, redacted and grounded in
    evidence.
-   [ ] LangGraph orchestration is bounded and cannot bypass security
    policy.
-   [ ] RAG uses curated, attributed, versioned sources.
-   [ ] JSON and HTML reports are safe and authorized.
-   [ ] PostgreSQL migrations and concurrency tests pass.
-   [ ] Windows and POSIX test suites pass.
-   [ ] Documentation accurately describes the implemented scope.

**Final principle:** Build a credible security assessment platform, not
an AI wrapper around a few HTTP requests. Evidence quality, safety
boundaries, repeatability, and engineering rigor are what make this
project impressive.
