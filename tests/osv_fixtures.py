"""A local fake OSV API and synthetic advisories for offline tests (M3).

All advisory content here is synthetic. The server listens on loopback only and
is reached through the real ``GuardedHttpClient`` with a test resolver that maps
``osv.test`` to 127.0.0.1.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from app.services.dependencies.osv import AdvisoryCache, OsvAdvisoryProvider
from app.services.net import GuardedHttpClient
from app.services.tooling.target_policy import NetworkSafetyPolicy

ADVISORIES: dict[str, dict[str, Any]] = {
    "GHSA-test-0001": {
        "id": "GHSA-test-0001",
        "aliases": ["CVE-2099-0001"],
        "summary": "Synthetic request smuggling in demo-http",
        "published": "2099-01-01T00:00:00Z",
        "modified": "2099-01-02T00:00:00Z",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "demo-http"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.3"}]}
                ],
                "database_specific": {"severity": "HIGH"},
            }
        ],
    },
    "GHSA-test-0002": {
        "id": "GHSA-test-0002",
        "aliases": [],
        "summary": "Synthetic prototype pollution\x07 in demo-merge <script>alert(1)</script>",
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "demo-merge"},
                "ranges": [
                    {"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.2.0"}]}
                ],
            }
        ],
        "database_specific": {"severity": "MODERATE"},
    },
}
# package (ecosystem, name, version) -> advisory ids the fake server reports
MATCHES: dict[tuple[str, str, str], list[str]] = {
    ("PyPI", "demo-http", "2.0.1"): ["GHSA-test-0001"],
    ("npm", "demo-merge", "1.1.0"): ["GHSA-test-0002"],
    # The provider claims a match the local range check will not confirm.
    ("PyPI", "demo-http", "9.9.9"): ["GHSA-test-0001"],
}


class FakeOsvHandler(BaseHTTPRequestHandler):
    advisories: dict[str, dict[str, Any]] = ADVISORIES
    matches: dict[tuple[str, str, str], list[str]] = MATCHES
    mode = "normal"  # normal | slow | invalid | rate_limited
    requests: list[str] = []

    def log_message(self, *_args: object) -> None:
        return

    def _send(self, status: int, payload: Any) -> None:
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _guard(self) -> bool:
        FakeOsvHandler.requests.append(f"{self.command} {self.path}")
        if FakeOsvHandler.mode == "slow":
            time.sleep(1.0)
        if FakeOsvHandler.mode == "rate_limited":
            self._send(429, {"error": "quota"})
            return False
        if FakeOsvHandler.mode == "invalid":
            self._send(200, b"<html>not json")
            return False
        return True

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("content-length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}")
        if not self._guard():
            return
        if self.path == "/v1/querybatch":
            results = []
            for query in body.get("queries", []):
                key = (query["package"]["ecosystem"], query["package"]["name"], query["version"])
                results.append({"vulns": [{"id": vid} for vid in self.matches.get(key, [])]})
            self._send(200, {"results": results})
        else:
            self._send(404, {})

    def do_GET(self) -> None:  # noqa: N802
        if not self._guard():
            return
        advisory_id = self.path.rsplit("/", 1)[-1]
        if self.path.startswith("/v1/vulns/") and advisory_id in self.advisories:
            self._send(200, self.advisories[advisory_id])
        else:
            self._send(404, {})


@contextmanager
def fake_osv_server() -> Iterator[int]:
    FakeOsvHandler.mode = "normal"
    FakeOsvHandler.requests = []
    FakeOsvHandler.matches = dict(MATCHES)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), FakeOsvHandler)
    thread = threading.Thread(target=httpd.serve_forever, args=(0.02,), daemon=True)
    thread.start()
    try:
        yield httpd.server_address[1]
    finally:
        httpd.shutdown()
        httpd.server_close()


def local_client(*, total_timeout: float = 3.0) -> GuardedHttpClient:
    policy = NetworkSafetyPolicy(
        allowed_local_networks=(ipaddress.ip_network("127.0.0.0/8"),),
        allowed_content_types=frozenset({"application/json"}),
        max_requests_per_second=1000.0,
        connect_timeout_seconds=min(1.0, total_timeout),
        read_timeout_seconds=min(1.0, total_timeout),
        total_timeout_seconds=total_timeout,
    )

    def resolve(host: str, _port: int) -> list[str]:
        if host != "osv.test":
            raise socket.gaierror("unknown")
        return ["127.0.0.1"]

    return GuardedHttpClient(policy, allowed_hosts=frozenset({"osv.test"}), resolver=resolve)


class FakeClock:
    def __init__(self) -> None:
        self.now = datetime(2099, 6, 1, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now


def make_provider(
    port: int | None,
    *,
    mode: str = "online",
    cache: AdvisoryCache | None = None,
    clock: FakeClock | None = None,
    cache_dir: Path | None = None,
    total_timeout: float = 3.0,
) -> OsvAdvisoryProvider:
    clock = clock or FakeClock()
    return OsvAdvisoryProvider(
        base_url=f"http://osv.test:{port or 1}",
        cache=cache or AdvisoryCache(cache_dir, ttl_seconds=3600, clock=clock),
        mode=mode,  # type: ignore[arg-type]
        client=local_client(total_timeout=total_timeout) if mode == "online" else None,
        clock=clock,
    )
