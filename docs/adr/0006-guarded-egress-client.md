# ADR-0006: Guarded egress HTTP client

- Status: Accepted (M3; this implements the client portion of ADR-0004, as agreed
  in M0 decision D8)
- Date: 2026-11-16

## Context

M3 is the first feature that needs outbound network access (the advisory
database). Later milestones add crawling and runtime probes against assessment
targets. One unsafe call site would be enough to enable SSRF, DNS rebinding, or
scanning of unauthorized systems.

## Decision

1. `app/services/net/guarded_client.py` (`GuardedHttpClient`) is the only component
   that may open analysis network connections. It uses only the standard library
   (`http.client`, `socket`, `ssl`, `zlib`). No scanner may import `httpx`,
   `requests`, `urllib.request`, or raw sockets.
2. Per request, in order:
   1. validate the scheme (policy allowlist), reject URL credentials and invalid
      ports, and require the host (IDNA-normalised) to be in the client's explicit
      `allowed_hosts`. IP literals are refused unless allowlisted;
   2. resolve DNS in the client. **Every** answer must pass
      `NetworkSafetyPolicy.is_address_permitted` (loopback, private, link-local,
      CGNAT, metadata, documentation, multicast, and their IPv4-mapped, 6to4,
      Teredo, NAT64, and IPv4-compatible forms are blocked unless a narrow local
      test network is allowlisted; metadata addresses never are);
   3. connect to the vetted IP. HTTPS wraps that socket with
      `ssl.create_default_context()` and `server_hostname=<original host>`, so the
      certificate and SNI are checked for the name while the connection cannot be
      re-pointed by a second DNS answer (rebinding);
   4. apply the per-host concurrency semaphore and minimum request interval;
   5. send fixed `Host`, `User-Agent`, `Accept-Encoding`, and `Connection` headers
      that callers cannot override;
   6. read at most `max_response_bytes` (checking `Content-Length` first),
      enforce the content-type allowlist, decompress gzip/deflate up to
      `min(limit, compressed_size × max_decompression_ratio)`, and enforce the
      connect, read, and total timeouts;
   7. follow redirects manually: every `Location` is joined, then fully
      revalidated as in step 1 (scheme, credentials, host allowlist) and step 2
      (fresh DNS check). Loops and more than `max_redirects` hops fail. A 303, or
      a 301/302 after POST, becomes GET.
3. Errors are `EgressError` with a non-sensitive code only (`host_not_allowed`,
   `blocked_address`, `timeout`, …), never the URL, address, headers, or body.
   Redirect chains returned to callers are redacted (`redact_url`).
4. Callers pass the run's `AnalysisExecutionContext`; cancellation is checked
   before each hop.

## Consequences

- The advisory provider (ADR-0007) is the first user. Its client allows only the
  configured OSV host over HTTPS, with no local networks.
- The M5 crawler and M6 probes must reuse this client with the per-assessment
  target authorization from ADR-0004. That authorization (the `assessment_targets`
  record) is not built yet, so ADR-0004 stays *proposed*.
- Tests use a loopback fake server, a stub resolver, and an explicitly allowlisted
  127.0.0.0/8. The test suite also blocks every non-loopback socket connection.
