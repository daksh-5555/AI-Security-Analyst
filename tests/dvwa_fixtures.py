"""Offline DVWA-like loopback fixture for lab-auth tests (M15).

Emulates the parts of DVWA that matter for authenticated scanning: a session
cookie (``PHPSESSID``), a per-session anti-CSRF token (``user_token``) on the
login form, a form login, and a reflected-XSS parameter reachable only after
login. Listens on 127.0.0.1 only; every request is logged so tests can assert
exactly how many login attempts were made (proving login-only, no guessing).
"""

from __future__ import annotations

import html
import secrets
import threading
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, parse_qsl, urlsplit

VALID = ("admin", "password")

_LOGIN_FORM = """<html><body><form action="/login.php" method="post">
<input type="text" name="username"><input type="password" name="password">
<input type="hidden" name="user_token" value="{token}">
<input type="submit" name="Login" value="Login"></form></body></html>"""

_INDEX = """<html><body><h1>Welcome admin</h1>
<a href="/vulnerabilities/xss_r/?name=test">reflected xss</a>
<a href="/logout.php">logout</a></body></html>"""


class DvwaHandler(BaseHTTPRequestHandler):
    log: list[tuple[str, str]] = []
    counters: Counter[str] = Counter()
    sessions: dict[str, dict[str, object]] = {}

    def log_message(self, *_args: object) -> None:
        return

    # -- helpers ----------------------------------------------------------------

    def _session(self) -> tuple[str, dict[str, object]]:
        jar: SimpleCookie = SimpleCookie(self.headers.get("Cookie", ""))
        sid = jar["PHPSESSID"].value if "PHPSESSID" in jar else ""
        if sid not in self.sessions:
            sid = secrets.token_hex(8)
            self.sessions[sid] = {"authed": False, "token": ""}
        return sid, self.sessions[sid]

    def _send(self, status: int, body: str, sid: str | None = None, location: str | None = None):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        if sid is not None:
            self.send_header("Set-Cookie", f"PHPSESSID={sid}; Path=/")
        if location is not None:
            self.send_header("Location", location)
        self.end_headers()
        self.wfile.write(data)

    # -- routes -----------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        parts = urlsplit(self.path)
        self.log.append(("GET", parts.path))
        sid, session = self._session()

        if parts.path == "/login.php":
            token = secrets.token_hex(16)
            session["token"] = token
            self._send(200, _LOGIN_FORM.format(token=token), sid=sid)
            return
        if not session["authed"]:
            self._send(302, "", sid=sid, location="/login.php")
            return
        if parts.path in ("/", "/index.php"):
            self._send(200, _INDEX, sid=sid)
            return
        if parts.path == "/vulnerabilities/xss_r/":
            name = parse_qs(parts.query).get("name", [""])[0]
            self._send(200, f"<html><body>Hello {name}</body></html>", sid=sid)  # reflected
            return
        self._send(404, "not found", sid=sid)

    def do_POST(self) -> None:  # noqa: N802
        parts = urlsplit(self.path)
        self.log.append(("POST", parts.path))
        sid, session = self._session()
        if parts.path != "/login.php":
            self._send(404, "not found", sid=sid)
            return
        self.counters["login_attempts"] += 1
        length = int(self.headers.get("Content-Length", "0"))
        form = dict(parse_qsl(self.rfile.read(length).decode()))
        token_ok = bool(session["token"]) and form.get("user_token") == session["token"]
        creds_ok = (form.get("username"), form.get("password")) == VALID
        if token_ok and creds_ok:
            session["authed"] = True
            self._send(302, "", sid=sid, location="/index.php")
        else:
            session["authed"] = False
            self._send(302, "", sid=sid, location="/login.php")


@contextmanager
def dvwa_site() -> Iterator[int]:
    DvwaHandler.log = []
    DvwaHandler.counters = Counter()
    DvwaHandler.sessions = {}
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), DvwaHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd.server_address[1]
    finally:
        httpd.shutdown()
        httpd.server_close()


def escape(value: str) -> str:
    return html.escape(value)
