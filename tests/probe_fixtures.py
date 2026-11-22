"""Deliberately vulnerable and safe loopback fixture app for probe tests (M6).

Endpoints use a real in-memory SQLite database. Everything listens on 127.0.0.1
only and every request is logged so tests can assert exactly what was sent.
"""

from __future__ import annotations

import html
import secrets
import sqlite3
import threading
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlsplit

INDEX = """<html><head><title>Lab</title></head><body>
<a href="/items?id=1">items</a>
<a href="/items-safe?id=1">safe items</a>
<a href="/items-errors?id=1">error items</a>
<a href="/noisy?id=1">noisy</a>
<a href="/search?q=a">search</a>
<a href="/search-safe?q=a">safe search</a>
<a href="/attr?q=a">attr</a>
<a href="/attr-safe?q=a">safe attr</a>
<a href="/script?q=a">script</a>
<a href="/flaky?q=a">flaky</a>
<a href="/profile?token=abc">profile</a>
<a href="/delete?id=1">delete</a>
<form method="post" action="/comment"><input name="body"></form>
<form action="/find"><input type="text" name="term">
<input type="hidden" name="csrf" value="x"></form>
</body></html>"""


def _db() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE items (id INTEGER, name TEXT)")
    connection.executemany("INSERT INTO items VALUES (?, ?)", [(1, "apple"), (2, "pear")])
    return connection


def _rows(rows: list[tuple]) -> str:
    if not rows:
        return "<p>No items</p>"
    return "<ul>" + "".join(f"<li>{html.escape(str(row[0]))}</li>" for row in rows) + "</ul>"


class ProbeHandler(BaseHTTPRequestHandler):
    log: list[tuple[str, str, dict[str, str]]] = []
    counters: Counter[str] = Counter()

    def log_message(self, *_args: object) -> None:
        return

    def _reply(self, status: int, body: str) -> None:
        data = f"<html><head><title>Lab</title></head><body>{body}</body></html>".encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:  # noqa: N802
        ProbeHandler.log.append(("POST", self.path, {}))
        self._reply(200, "posted")

    def do_GET(self) -> None:  # noqa: N802
        parts = urlsplit(self.path)
        params = dict(parse_qsl(parts.query, keep_blank_values=True))
        ProbeHandler.log.append(("GET", parts.path, params))
        path = parts.path
        ProbeHandler.counters[path] += 1
        value = params.get("id", params.get("q", params.get("term", "")))
        if path == "/":
            data = INDEX.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if path == "/items":  # VULNERABLE: string concatenation into SQL
            try:
                rows = _db().execute(f"SELECT name FROM items WHERE id = {value}").fetchall()
            except sqlite3.Error as exc:
                self._reply(500, f"sqlite3.OperationalError: {html.escape(str(exc))}")
                return
            self._reply(200, _rows(rows))
        elif path == "/items-safe":  # SAFE: parameterized
            rows = _db().execute("SELECT name FROM items WHERE id = ?", (value,)).fetchall()
            self._reply(200, _rows(rows))
        elif path == "/items-errors":  # error text on quotes, but not injectable
            if "'" in value:
                self._reply(500, "You have an error in your SQL syntax near the quote")
            else:
                self._reply(200, _rows([("apple",)]))
        elif path == "/noisy":
            lines = "".join(f"<p>{secrets.token_hex(8)}</p>" for _ in range(20))
            self._reply(200, lines)
        elif path == "/search":  # VULNERABLE: raw HTML reflection
            self._reply(200, f"<p>Results for {value}</p>")
        elif path == "/search-safe":
            self._reply(200, f"<p>Results for {html.escape(value)}</p>")
        elif path == "/attr":  # VULNERABLE: raw attribute reflection
            self._reply(200, f'<input name="q" value="{value}">')
        elif path == "/attr-safe":
            self._reply(200, f'<input name="q" value="{html.escape(value, quote=True)}">')
        elif path == "/script":  # VULNERABLE: raw script-string reflection
            self._reply(200, f"<script>var q = '{value}';</script>")
        elif path == "/flaky":  # first special-character probe raw, later ones encoded
            if "<" in value:
                ProbeHandler.counters["flaky-special"] += 1
            raw = ProbeHandler.counters["flaky-special"] <= 1
            self._reply(200, f"<p>{value if raw else html.escape(value)}</p>")
        elif path == "/find":
            self._reply(200, f"<p>{html.escape(value)}</p>")
        else:
            self._reply(404, "missing")


@contextmanager
def probe_site() -> Iterator[int]:
    ProbeHandler.log = []
    ProbeHandler.counters = Counter()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), ProbeHandler)
    thread = threading.Thread(target=httpd.serve_forever, args=(0.02,), daemon=True)
    thread.start()
    try:
        yield httpd.server_address[1]
    finally:
        httpd.shutdown()
        httpd.server_close()
