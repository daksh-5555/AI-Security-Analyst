"""A local fixture website for crawler tests (M5). Loopback only; logs every request."""

from __future__ import annotations

import ipaddress
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from app.services.net import GuardedHttpClient
from app.services.tooling.target_policy import NetworkSafetyPolicy

CSRF_VALUE = "CSRF-SECRET-VALUE-5e1f"
SESSION_VALUE = "session-token-9a8b"


def page(title: str, body: str) -> bytes:
    return f"<html><head><title>{title}</title></head><body>{body}</body></html>".encode()


SITE: dict[str, tuple[int, dict[str, str], bytes]] = {
    "/": (
        200,
        {},
        page(
            "Home \x07<b>",
            """
            <a href="/about">About</a>
            <a href="/products?id=1">1</a><a href="/products?id=2">2</a>
            <a href="/products?id=3">3</a><a href="/products?id=4">4</a>
            <a href="/logout">Log out</a>
            <a href="/delete?id=7">Delete</a>
            <a href="/admin/panel">Admin</a>
            <a href="http://other.test/x">Elsewhere</a>
            <a href="mailto:a@example.test">Mail</a>
            <a href="javascript:alert(1)">JS</a>
            <a href="#top">Top</a>
            <a href="/redirect">Redirect</a>
            <a href="/external-redirect">External</a>
            <a href="/image.png">Image</a>
            <a href="/private">Private</a>
            <a href="/login">Login</a>
            <a href="/deep/1">Deep</a>
            <a href="/secret-area">Robots</a>
            <a href="/user/@me">At</a>
            <form method="post" action="/comment">
              <input type="hidden" name="csrf" value="CSRF-SECRET-VALUE-5e1f">
              <textarea name="body" required></textarea>
              <input type="submit" value="Send">
            </form>
            <form action="/search"><input type="search" name="q"></form>
            """,
        ),
    ),
    "/about": (200, {}, page("About", '<a href="/">Home</a><a href="/about#team">Team</a>')),
    "/products?id=1": (200, {}, page("P1", "")),
    "/products?id=2": (200, {}, page("P2", "")),
    "/products?id=3": (200, {}, page("P3", "")),
    "/products?id=4": (200, {}, page("P4", "")),
    "/redirect": (302, {"Location": "/about"}, b""),
    "/external-redirect": (302, {"Location": "http://evil.test/"}, b""),
    "/image.png": (200, {"Content-Type": "text/plain"}, b"not really an image"),
    "/private": (401, {"WWW-Authenticate": 'Basic realm="lab"'}, page("Denied", "")),
    "/login": (
        200,
        {},
        page(
            "Login",
            '<form method="post" action="/login"><input name="username">'
            '<input type="password" name="password"><input type="submit"></form>',
        ),
    ),
    "/deep/1": (200, {}, page("D1", '<a href="/deep/2">next</a>')),
    "/deep/2": (200, {}, page("D2", '<a href="/deep/3">next</a>')),
    "/deep/3": (200, {}, page("D3", '<a href="/deep/4">next</a>')),
    "/deep/4": (200, {}, page("D4", "")),
    "/secret-area": (200, {}, page("Secret", "")),
    "/user/%40me": (200, {}, page("Me", "")),
    "/robots.txt": (
        200,
        {"Content-Type": "text/plain"},
        b"User-agent: *\nDisallow: /secret-area\n",
    ),
}


class SiteHandler(BaseHTTPRequestHandler):
    site: dict[str, tuple[int, dict[str, str], bytes]] = SITE
    log: list[tuple[str, str]] = []

    def log_message(self, *_args: object) -> None:
        return

    def _serve(self) -> None:
        SiteHandler.log.append((self.command, self.path))
        status, headers, body = self.site.get(self.path, (404, {}, page("Missing", "")))
        self.send_response(status)
        headers = {"Content-Type": "text/html; charset=utf-8", **headers}
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Set-Cookie", f"session={SESSION_VALUE}")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _serve  # noqa: N815
    do_POST = _serve  # noqa: N815
    do_PUT = _serve  # noqa: N815
    do_DELETE = _serve  # noqa: N815


@contextmanager
def fixture_site(site: dict | None = None) -> Iterator[int]:
    SiteHandler.site = site if site is not None else SITE
    SiteHandler.log = []
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), SiteHandler)
    thread = threading.Thread(target=httpd.serve_forever, args=(0.02,), daemon=True)
    thread.start()
    try:
        yield httpd.server_address[1]
    finally:
        httpd.shutdown()
        httpd.server_close()


def lab_client() -> GuardedHttpClient:
    """Client bound to the loopback lab host, as ``build_target_client`` would build it."""
    policy = NetworkSafetyPolicy(
        allowed_local_networks=(ipaddress.ip_network("127.0.0.0/8"),),
        max_requests_per_second=1000.0,
        connect_timeout_seconds=1.0,
        read_timeout_seconds=1.0,
        total_timeout_seconds=3.0,
    )
    return GuardedHttpClient(policy, allowed_hosts=frozenset({"127.0.0.1"}))
