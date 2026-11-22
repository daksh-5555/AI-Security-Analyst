# ADR-0004: Target authorization and network safety policy

- Status: **Accepted** (interfaces M1; egress client M3, ADR-0006; persistence and enforcement M4)
- Date: 2026-11-16

## Context

Repository targets are confined to shared `REPOSITORY_ALLOWED_ROOTS` but have no
owner (open finding S-7). Runtime checks will send HTTP requests, which creates
SSRF, DNS rebinding, redirect, and unauthorized-scanning risks.

## Decision

1. `TargetAuthorizationPolicy.evaluate(TargetRequest) -> TargetDecision` is the only
   way to authorize a target. `TargetDecision.allowed` is true exactly when the
   reason is `authorized`. The default implementation, `DenyAllTargetPolicy`,
   denies everything.
2. M4 adds an `assessment_targets` record for repository and web targets with the
   creator, an explicit authorization confirmation (who, when, statement), the
   canonical target, a policy snapshot, and a status. Web targets also require a
   deployment-level allowlist entry. Existing repository targets are backfilled
   with the assessment owner. Rows with no owner are blocked from new runs until
   they are confirmed.
3. `NetworkSafetyPolicy` holds safe defaults for every runtime tool:
   - HTTP/HTTPS only, at most 5 redirects;
   - connect, read, and total timeouts;
   - a 2 MiB response limit and a decompression-ratio limit;
   - a content-type allowlist and per-target rate and concurrency budgets;
   - a scanner User-Agent.

   `is_address_permitted` blocks loopback, private, CGNAT, link-local,
   documentation, multicast, reserved, and unspecified ranges. It also blocks the
   IPv4-mapped, IPv4-compatible, 6to4, Teredo, and NAT64 forms of those addresses,
   and cloud metadata addresses. A narrow `allowed_local_networks` list can permit
   a local test network such as DVWA on loopback; metadata addresses can never be
   allowlisted.
4. The M4 guarded client must:
   - resolve DNS itself, check every resolved address, and connect to the checked
     address (preventing rebinding);
   - recheck the scheme, host, and addresses on every redirect;
   - reject credentials in URLs;
   - be the only component that opens network connections.

## Implementation (M4)

- `assessment_targets` (migration `0016`) holds one row per (assessment, target
  type): `canonical_target`, `status` (`pending_authorization`, `authorized`,
  `revoked`), `authorization_basis` (`owner_registration`,
  `explicit_confirmation`, `legacy_backfill`), the statement, who created,
  authorized, and revoked it and when, and a `policy_snapshot`.
- **Repository targets** are authorized by the owner's registration within the
  allowed roots (`owner_registration`). The migration backfilled existing targets:
  owned ones are `legacy_backfill`; ownerless ones are `pending_authorization` and
  blocked.
- **Web targets** (`POST …/web-target`) require: a `web_security` assessment in
  `queued`, an http(s) base URL without credentials, query, or fragment
  (canonicalised: IDNA host, default port, normalised path), a host on
  `WEB_TARGET_ALLOWED_HOSTS`, `confirm_authorized: true`, and a written
  `authorization_statement` (20–1000 characters). Registration is audited
  (`assessment_target.authorized`).
- Targets can be revoked and re-authorized (`assessment_target.revoked`,
  `assessment_target.authorized`). Only users who can manage the assessment (its
  owner or an Admin) may do so.
- **Enforcement.** `execute_assessment_analysis` and
  `discover_registered_repository` (which the attack-surface summary also uses)
  require an `authorized` record and return `409 Target authorization is required
  before analysis`; no run record is created.
  `DatabaseTargetAuthorizationPolicy` checks web requests by origin, a
  segment-aware base path, status, and the allowlist.
  `build_target_client` is the only way to get a network client for a web target:
  bound to that host, under the web network policy, refused for pending, revoked,
  or non-allowlisted targets.
- **Repository isolation (resolves S-7).** `REPOSITORY_ISOLATION=per_user`
  confines each owner to `<allowed root>/<owner user id>/`, checked at
  registration *and* at analysis time. Ownerless assessments get no root. Rejections
  use the same generic 422 as any other invalid location, so they do not reveal
  that another user's directory exists. `shared` keeps the previous single-team
  layout. Staging and production must set the value explicitly.
- `WEB_TARGET_ALLOWED_LOCAL_NETWORKS` (for example a DVWA lab on 127.0.0.0/8) is
  refused in staging and production.
- DNS is **not** resolved at registration. Address checks happen in the guarded
  client on every connection and redirect hop.
