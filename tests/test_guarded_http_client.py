"""Guarded egress client tests against a local loopback server (M3, ADR-0006)."""

from __future__ import annotations

import gzip
import ipaddress
import socket
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from app.services.analysis_execution_context import (
    AnalysisExecutionAbortedError,
    AnalysisExecutionContext,
)
from app.services.net import EgressError, EgressErrorCode, GuardedHttpClient
from app.services.tooling.target_policy import NetworkSafetyPolicy

LOOPBACK = (ipaddress.ip_network("127.0.0.0/8"),)


class Handler(BaseHTTPRequestHandler):
    routes: dict[str, tuple[int, dict[str, str], bytes]] = {}
    seen: list[tuple[str, str, dict[str, str]]] = []

    def log_message(self, *_args: object) -> None:  # silence test server
        return

    def _respond(self) -> None:
        length = int(self.headers.get("content-length") or 0)
        if length:
            self.rfile.read(length)
        Handler.seen.append((self.command, self.path, dict(self.headers)))
        if self.path == "/slow":
            time.sleep(1.5)
        status, headers, body = Handler.routes.get(self.path, (404, {}, b"missing"))
        self.send_response(status)
        headers = {"Content-Type": "application/json", **headers}
        for name, value in headers.items():
            self.send_header(name, value)
        if "Content-Length" not in headers:
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _respond  # noqa: N815
    do_POST = _respond  # noqa: N815


@pytest.fixture
def server() -> Iterator[int]:
    Handler.routes = {}
    Handler.seen = []
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, args=(0.02,), daemon=True)
    thread.start()
    try:
        yield httpd.server_address[1]
    finally:
        httpd.shutdown()
        httpd.server_close()


def make_client(
    *,
    resolver: dict[str, list[str]] | None = None,
    allowed_hosts: frozenset[str] = frozenset({"service.test", "other.test"}),
    local: tuple = LOOPBACK,
    connected: list[str] | None = None,
    **policy_overrides: object,
) -> GuardedHttpClient:
    mapping = resolver if resolver is not None else {"service.test": ["127.0.0.1"]}
    values: dict[str, object] = {
        "allowed_local_networks": local,
        "max_requests_per_second": 1000.0,
        "connect_timeout_seconds": 1.0,
        "read_timeout_seconds": 1.0,
        "total_timeout_seconds": 3.0,
    }
    values.update(policy_overrides)

    def resolve(host: str, _port: int) -> list[str]:
        if host not in mapping:
            raise socket.gaierror("unknown host")
        return list(mapping[host])

    def factory(address: str, port: int, timeout: float) -> socket.socket:
        if connected is not None:
            connected.append(address)
        return socket.create_connection((address, port), timeout=timeout)

    return GuardedHttpClient(
        NetworkSafetyPolicy(**values),
        allowed_hosts=allowed_hosts,
        resolver=resolve,
        socket_factory=factory,
    )


def url(port: int, path: str, host: str = "service.test") -> str:
    return f"http://{host}:{port}{path}"


def code_of(excinfo: pytest.ExceptionInfo[EgressError]) -> EgressErrorCode:
    return excinfo.value.code


def test_successful_request_sets_identity_and_returns_body(server: int) -> None:
    Handler.routes["/ok"] = (200, {}, b'{"ok": true}')
    connected: list[str] = []
    response = make_client(connected=connected).request("GET", url(server, "/ok"))

    assert response.status == 200
    assert response.body == b'{"ok": true}'
    assert connected == ["127.0.0.1"]
    method, path, headers = Handler.seen[0]
    assert (method, path) == ("GET", "/ok")
    assert "authorized security assessment" in headers["User-Agent"]
    assert headers["Host"] == f"service.test:{server}"


@pytest.mark.parametrize(
    ("target", "code"),
    [
        ("ftp://service.test/x", EgressErrorCode.SCHEME_NOT_ALLOWED),
        ("file:///etc/passwd", EgressErrorCode.SCHEME_NOT_ALLOWED),
        ("http://user:pass@service.test/x", EgressErrorCode.CREDENTIALS_IN_URL),
        ("http://evil.test/x", EgressErrorCode.HOST_NOT_ALLOWED),
        ("http://127.0.0.1/x", EgressErrorCode.HOST_NOT_ALLOWED),
        ("http:///nohost", EgressErrorCode.INVALID_URL),
        ("http://service.test:99999/x", EgressErrorCode.INVALID_URL),
    ],
)
def test_invalid_or_unapproved_urls_are_refused_before_any_connection(
    target: str, code: EgressErrorCode
) -> None:
    connected: list[str] = []
    with pytest.raises(EgressError) as excinfo:
        make_client(connected=connected).request("GET", target)
    assert code_of(excinfo) is code
    assert connected == []


@pytest.mark.parametrize(
    "answers",
    [["10.0.0.5"], ["169.254.169.254"], ["127.0.0.1", "10.0.0.5"], ["::ffff:192.168.1.1"], []],
)
def test_public_name_resolving_to_blocked_addresses_is_refused(answers: list[str]) -> None:
    connected: list[str] = []
    client = make_client(resolver={"service.test": answers}, connected=connected)
    with pytest.raises(EgressError) as excinfo:
        client.request("GET", "http://service.test/x")
    assert code_of(excinfo) in {EgressErrorCode.BLOCKED_ADDRESS, EgressErrorCode.DNS_FAILURE}
    assert connected == []


def test_loopback_is_blocked_without_an_explicit_local_allowlist(server: int) -> None:
    with pytest.raises(EgressError) as excinfo:
        make_client(local=()).request("GET", url(server, "/ok"))
    assert code_of(excinfo) is EgressErrorCode.BLOCKED_ADDRESS


def test_connection_uses_the_vetted_address_not_a_second_lookup(server: int) -> None:
    """DNS rebinding: a later answer cannot redirect an already-vetted connection."""
    Handler.routes["/ok"] = (200, {}, b"{}")
    answers = iter([["127.0.0.1"], ["169.254.169.254"]])
    connected: list[str] = []

    def rebinding(host: str, port: int) -> list[str]:
        return next(answers)

    client = make_client(connected=connected)
    client._resolver = rebinding  # noqa: SLF001 - simulate a rebinding resolver
    assert client.request("GET", url(server, "/ok")).status == 200
    assert connected == ["127.0.0.1"]
    # The next lookup returns metadata and is refused before connecting.
    with pytest.raises(EgressError) as excinfo:
        client.request("GET", url(server, "/ok"))
    assert code_of(excinfo) is EgressErrorCode.BLOCKED_ADDRESS
    assert connected == ["127.0.0.1"]


def test_permitted_redirect_is_followed_and_chain_is_redacted(server: int) -> None:
    Handler.routes["/start?token=abc"] = (302, {"Location": "/final"}, b"")
    Handler.routes["/final"] = (200, {}, b"{}")
    response = make_client().request("GET", url(server, "/start?token=abc"))

    assert response.status == 200
    assert response.redirect_chain[0].endswith("token=%5BREDACTED%5D")
    assert "abc" not in "".join(response.redirect_chain)


@pytest.mark.parametrize(
    ("location", "code"),
    [
        ("http://169.254.169.254/latest/meta-data", EgressErrorCode.HOST_NOT_ALLOWED),
        ("http://other.test/x", EgressErrorCode.BLOCKED_ADDRESS),
        ("http://unlisted.test/x", EgressErrorCode.HOST_NOT_ALLOWED),
        ("ftp://service.test/x", EgressErrorCode.SCHEME_NOT_ALLOWED),
        ("http://user:pw@service.test/x", EgressErrorCode.CREDENTIALS_IN_URL),
        ("http://[::1", EgressErrorCode.BAD_REDIRECT),
    ],
)
def test_redirects_are_revalidated_on_every_hop(
    server: int, location: str, code: EgressErrorCode
) -> None:
    Handler.routes["/go"] = (302, {"Location": location}, b"")
    client = make_client(
        resolver={"service.test": ["127.0.0.1"], "other.test": ["10.1.1.1"]},
    )
    with pytest.raises(EgressError) as excinfo:
        client.request("GET", url(server, "/go"))
    assert code_of(excinfo) is code


def test_redirect_loops_and_limits(server: int) -> None:
    Handler.routes["/a"] = (302, {"Location": "/b"}, b"")
    Handler.routes["/b"] = (302, {"Location": "/a"}, b"")
    with pytest.raises(EgressError) as excinfo:
        make_client().request("GET", url(server, "/a"))
    assert code_of(excinfo) is EgressErrorCode.REDIRECT_LOOP

    for index in range(5):
        Handler.routes[f"/hop{index}"] = (302, {"Location": f"/hop{index + 1}"}, b"")
    with pytest.raises(EgressError) as excinfo:
        make_client(max_redirects=2).request("GET", url(server, "/hop0"))
    assert code_of(excinfo) is EgressErrorCode.REDIRECT_LIMIT


def test_oversized_responses_are_rejected(server: int) -> None:
    Handler.routes["/big"] = (200, {}, b"x" * 5000)
    Handler.routes["/lying"] = (200, {"Content-Length": "100"}, b"x" * 100)
    with pytest.raises(EgressError) as excinfo:
        make_client(max_response_bytes=1000).request("GET", url(server, "/big"))
    assert code_of(excinfo) is EgressErrorCode.TOO_LARGE


def test_decompression_bomb_is_rejected(server: int) -> None:
    bomb = gzip.compress(b"0" * 900_000)
    Handler.routes["/bomb"] = (200, {"Content-Encoding": "gzip"}, bomb)
    Handler.routes["/small"] = (200, {"Content-Encoding": "gzip"}, gzip.compress(b'{"a":1}'))
    client = make_client(max_response_bytes=1_000_000, max_decompression_ratio=20)

    assert client.request("GET", url(server, "/small")).body == b'{"a":1}'
    with pytest.raises(EgressError) as excinfo:
        client.request("GET", url(server, "/bomb"))
    assert code_of(excinfo) is EgressErrorCode.DECOMPRESSION_LIMIT


def test_disallowed_content_types_are_rejected(server: int) -> None:
    Handler.routes["/bin"] = (200, {"Content-Type": "application/octet-stream"}, b"\x00")
    with pytest.raises(EgressError) as excinfo:
        make_client().request("GET", url(server, "/bin"))
    assert code_of(excinfo) is EgressErrorCode.CONTENT_TYPE


def test_slow_responses_time_out(server: int) -> None:
    Handler.routes["/slow"] = (200, {}, b"{}")
    client = make_client(read_timeout_seconds=0.3, total_timeout_seconds=1.0)
    with pytest.raises(EgressError) as excinfo:
        client.request("GET", url(server, "/slow"))
    assert code_of(excinfo) is EgressErrorCode.TIMEOUT


def test_cancellation_is_checked_before_sending(server: int) -> None:
    execution = AnalysisExecutionContext(10)
    execution.request_abort()
    with pytest.raises(AnalysisExecutionAbortedError):
        make_client().request("GET", url(server, "/ok"), execution=execution)
    assert Handler.seen == []


def test_post_body_and_caller_headers_cannot_override_identity(server: int) -> None:
    Handler.routes["/q"] = (200, {}, b"{}")
    make_client().request(
        "POST",
        url(server, "/q"),
        body=b'{"x":1}',
        headers={"Content-Type": "application/json", "User-Agent": "spoofed", "Host": "evil"},
    )
    method, _path, headers = Handler.seen[0]
    assert method == "POST"
    assert headers["User-Agent"] != "spoofed"
    assert headers["Host"].startswith("service.test")


def test_error_messages_contain_no_url_or_address() -> None:
    with pytest.raises(EgressError) as excinfo:
        make_client().request("GET", "http://evil.test/secret-path?token=abc")
    assert str(excinfo.value) == "host_not_allowed"


def test_unsupported_methods_are_rejected() -> None:
    with pytest.raises(ValueError):
        make_client().request("DELETE", "http://service.test/x")
