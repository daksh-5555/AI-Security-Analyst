# ADR-0008: Safe crawler for authorized web targets

- Status: Accepted (M5)
- Date: 2026-11-16

## Context

Runtime checks (M6) need an inventory of pages, parameters, and forms on an
explicitly authorized web application such as a DVWA lab. A crawler can cause
harm on its own: by following "log out" or "delete" links, submitting forms,
leaving the authorized scope, or overloading the target.

## Decision

1. **Execution.** `web_security` analysis runs use the authorized web target
   (ADR-0004) instead of a repository. Before any run record is created, the target
   must be `authorized` and its host still on `WEB_TARGET_ALLOWED_HOSTS`;
   otherwise the API returns 409 (or 404 when no web target exists). The crawler
   is a registry tool (`web_crawl`) that receives the target URL and the
   `GuardedHttpClient` from `build_target_client`, bound to the target host. It
   never builds a client itself.
2. **Requests.** GET only, breadth-first, deterministic order. Forms are never
   submitted: they are parsed and classified (`login`, `credential`, `upload`,
   `state_changing`, `search`, `query`) and recorded with `submitted: false`.
3. **Scope.** The crawler stays on the same scheme, host, and port, inside the
   target's base path (segment-aware), and outside `CRAWLER_EXCLUDED_PATHS`.
   Links with ignored schemes (`mailto:`, `javascript:`, `data:`, …) and fragments
   are dropped. URLs are canonicalised (lower-case host, default port removed,
   dot segments resolved, sorted query) for deduplication.
4. **Safety list.** Links whose path or query matches a state-changing pattern
   (log out/sign out, delete/remove/destroy/drop/reset/purge, purchase/checkout/
   payment/order, upload, unsubscribe/deactivate/disable, shutdown/reboot/kill/wipe,
   transfer/withdraw, and DVWA's `setup.php`, `security.php`, and `install`) are
   never requested and are counted as `skipped_unsafe_link`.
5. **Budgets.** `CRAWLER_MAX_DEPTH` (3), `CRAWLER_MAX_PAGES` (50),
   `CRAWLER_MAX_REQUESTS` (150, including redirects and robots.txt), and
   `CRAWLER_MAX_VARIANTS_PER_PATH` (3 query-value variants per path and
   parameter-name set). The guarded client adds per-request timeouts, size limits,
   2 requests per second and 2 concurrent requests per target, and the run deadline
   and cancellation (checked before every request).
6. **robots.txt** is honoured by default (`CRAWLER_RESPECT_ROBOTS`). This is
   courtesy, not authorization: an unreachable or non-text robots.txt imposes no
   restriction, and it never widens scope.
7. **Evidence** (source type `crawler`):
   - `crawler.page` records status, content type, depth, sanitised title,
     parameter names, redirect count, and link and form counts;
   - `crawler.form` records method, same-origin action path, enctype,
     classification, field names, types, and `required`;
   - `crawler.auth_boundary` records `http_401`, `http_403`, `www_authenticate`,
     `redirect_to_login`, and `login_form`.

   Locations are origin-relative paths with parameter *names* only. Query values,
   form values (including hidden CSRF tokens), cookies, and bodies are never
   stored. Credentials are never guessed or submitted.
8. **Honest status.** Budget stops, depth or variant limits, request failures, and
   HTML extraction caps make the tool `partial`. If no page could be fetched, the
   tool is `failed` (`unavailable`, or `policy_denied` for egress-policy denials).
   Unsafe, out-of-scope, and robots-disallowed links are counted policy
   exclusions. The crawler produces no findings; its bounded inventory is stored in
   the run's `analysis_metadata.crawl_inventory`.

## Consequences

- No JavaScript execution: links created by scripts are not discovered.
- Only HTML link and form extraction (standard-library `html.parser`; no new
  dependency). Sitemaps and API descriptions are not consumed.
- Authenticated areas are only detected, not crawled (no credentials or session
  handling).
