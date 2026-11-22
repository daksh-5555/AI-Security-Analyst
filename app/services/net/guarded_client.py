"""The single policy-enforcing HTTP client for all outbound network access (ADR-0006).

No other module may open network connections for analysis purposes. This client:

- accepts only allowlisted hosts and the policy's schemes, and rejects URL
  credentials and fragments;
- resolves DNS itself, requires *every* resolved address to be permitted by
  ``NetworkSafetyPolicy``, and connects to the vetted IP address (TLS still
  verifies the certificate for the original hostname via SNI), which prevents DNS
  rebinding between check and use;
- follows redirects manually, revalidating scheme, host, and addresses on every
  hop, with a hop limit and loop detection;
- enforces connect, read, and total timeouts, a response-size limit, a
  decompression-ratio limit, a content-type allowlist, and per-host request rate
  and concurrency budgets;
- identifies itself with the policy's User-Agent and never logs headers, bodies,
  or unredacted URLs.

Only the Python standard library is used.
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import threading
import time
import zlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from email.message import Message
from enum import StrEnum
from typing import Final
from urllib.parse import urljoin, urlsplit

from app.services.analysis_execution_context import AnalysisExecutionContext
from app.services.tooling.redaction import redact_headers, redact_url
from app.services.tooling.target_policy import NetworkSafetyPolicy

Resolver = Callable[[str, int], list[str]]
SocketFactory = Callable[[str, int, float], socket.socket]

_REDIRECT_STATUSES: Final[frozenset[int]] = frozenset({301, 302, 303, 307, 308})
_CHUNK_BYTES: Final[int] = 64 * 1024
_DEFAULT_PORTS: Final[dict[str, int]] = {"http": 80, "https": 443}


class EgressErrorCode(StrEnum):
    """Non-sensitive reasons a request was refused or failed."""

    SCHEME_NOT_ALLOWED = "scheme_not_allowed"
    HOST_NOT_ALLOWED = "host_not_allowed"
    CREDENTIALS_IN_URL = "credentials_in_url"
    INVALID_URL = "invalid_url"
    DNS_FAILURE = "dns_failure"
    BLOCKED_ADDRESS = "blocked_address"
    REDIRECT_LIMIT = "redirect_limit"
    REDIRECT_LOOP = "redirect_loop"
    BAD_REDIRECT = "bad_redirect"
    TIMEOUT = "timeout"
    TOO_LARGE = "response_too_large"
    DECOMPRESSION_LIMIT = "decompression_limit"
    CONTENT_TYPE = "content_type_not_allowed"
    CONNECTION_FAILED = "connection_failed"
    BUDGET = "request_budget_exhausted"


class EgressError(RuntimeError):
    """Raised when a request is refused by policy or fails safely.

    The message is the code only: no URL, address, header, or body is included.
    """

    def __init__(self, code: EgressErrorCode) -> None:
        super().__init__(code.value)
        self.code = code

    @property
    def is_policy_denial(self) -> bool:
        return self.code in {
            EgressErrorCode.SCHEME_NOT_ALLOWED,
            EgressErrorCode.HOST_NOT_ALLOWED,
            EgressErrorCode.CREDENTIALS_IN_URL,
            EgressErrorCode.BLOCKED_ADDRESS,
            EgressErrorCode.BAD_REDIRECT,
        }


@dataclass(frozen=True, slots=True)
class GuardedResponse:
    """A fully read, size-checked response."""

    status: int
    headers: Mapping[str, str]
    body: bytes
    final_url: str
    redirect_chain: tuple[str, ...]
    elapsed_seconds: float

    @property
    def content_type(self) -> str:
        return _media_type(self.headers.get("content-type", ""))

    def redacted_headers(self) -> dict[str, str]:
        return redact_headers(self.headers)


def system_resolver(host: str, port: int) -> list[str]:
    """Resolve ``host`` with the operating system resolver (TCP, any family)."""
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addresses: list[str] = []
    for _family, _type, _proto, _name, sockaddr in infos:
        address = str(sockaddr[0]).split("%", 1)[0]
        if address not in addresses:
            addresses.append(address)
    return addresses


def _default_socket_factory(address: str, port: int, timeout: float) -> socket.socket:
    return socket.create_connection((address, port), timeout=timeout)


def _media_type(value: str) -> str:
    message = Message()
    message["content-type"] = value
    return message.get_content_type().lower() if value else ""


@dataclass
class _HostBudget:
    semaphore: threading.BoundedSemaphore
    lock: threading.Lock = field(default_factory=threading.Lock)
    next_allowed_at: float = 0.0


class _PinnedConnection(http.client.HTTPConnection):
    """HTTP connection over an already-connected socket."""

    def __init__(self, host: str, port: int, sock: socket.socket, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self.sock = sock

    def connect(self) -> None:  # pragma: no cover - the socket is pre-connected
        raise RuntimeError("pinned connections never reconnect")


class GuardedHttpClient:
    """Policy-enforcing HTTP client (see module docstring)."""

    def __init__(
        self,
        policy: NetworkSafetyPolicy,
        *,
        allowed_hosts: frozenset[str],
        resolver: Resolver = system_resolver,
        socket_factory: SocketFactory = _default_socket_factory,
        monotonic: Callable[[], float] = time.monotonic,
        ssl_context: ssl.SSLContext | None = None,
        default_headers: Mapping[str, str] | None = None,
    ) -> None:
        if not allowed_hosts:
            raise ValueError("allowed_hosts must not be empty")
        self._policy = policy
        self._allowed_hosts = frozenset(host.lower().rstrip(".") for host in allowed_hosts)
        # Default headers (e.g. an authorized local-lab session cookie) are merged
        # into every request; they travel only to the single allowed host, and
        # per-request headers override them. Never logged (see redact_headers).
        self._default_headers = dict(default_headers or {})
        self._resolver = resolver
        self._socket_factory = socket_factory
        self._monotonic = monotonic
        self._ssl_context = ssl_context or ssl.create_default_context()
        self._budgets: dict[str, _HostBudget] = {}
        self._budgets_lock = threading.Lock()
        self.requests_made = 0

    @property
    def policy(self) -> NetworkSafetyPolicy:
        return self._policy

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
        execution: AnalysisExecutionContext | None = None,
    ) -> GuardedResponse:
        """Send one request, following permitted redirects. Raises ``EgressError``."""
        method = method.upper()
        if method not in {"GET", "HEAD", "POST"}:
            raise ValueError("only GET, HEAD, and POST are supported")
        effective_headers = {**self._default_headers, **(headers or {})} or None
        started = self._monotonic()
        deadline = started + self._policy.total_timeout_seconds
        chain: list[str] = []
        visited: set[str] = set()
        current = url

        for _hop in range(self._policy.max_redirects + 1):
            if execution is not None:
                execution.check()
            scheme, host, port, path = self._validate_url(current)
            canonical = f"{scheme}://{host}:{port}{path}"
            if canonical in visited:
                raise EgressError(EgressErrorCode.REDIRECT_LOOP)
            visited.add(canonical)
            chain.append(redact_url(current))
            address = self._resolve(host, port)
            status, response_headers, payload = self._send(
                method, scheme, host, port, path, address, effective_headers, body, deadline
            )
            if status in _REDIRECT_STATUSES and "location" in response_headers:
                location = response_headers["location"].strip()
                if not location or any(ord(char) < 32 for char in location):
                    raise EgressError(EgressErrorCode.BAD_REDIRECT)
                try:
                    current = urljoin(current, location)
                except ValueError as exc:
                    raise EgressError(EgressErrorCode.BAD_REDIRECT) from exc
                if status == 303 or (status in {301, 302} and method == "POST"):
                    method, body = "GET", None
                continue
            return GuardedResponse(
                status=status,
                headers=response_headers,
                body=payload,
                final_url=redact_url(current),
                redirect_chain=tuple(chain[:-1]),
                elapsed_seconds=self._monotonic() - started,
            )
        raise EgressError(EgressErrorCode.REDIRECT_LIMIT)

    # -- validation -------------------------------------------------------------

    def _validate_url(self, url: str) -> tuple[str, str, int, str]:
        try:
            parts = urlsplit(url)
            port = parts.port
        except ValueError as exc:
            raise EgressError(EgressErrorCode.INVALID_URL) from exc
        scheme = parts.scheme.lower()
        if scheme not in self._policy.allowed_schemes:
            raise EgressError(EgressErrorCode.SCHEME_NOT_ALLOWED)
        if parts.username is not None or parts.password is not None or "@" in parts.netloc:
            raise EgressError(EgressErrorCode.CREDENTIALS_IN_URL)
        host = (parts.hostname or "").rstrip(".")
        if not host:
            raise EgressError(EgressErrorCode.INVALID_URL)
        try:
            host = host.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise EgressError(EgressErrorCode.INVALID_URL) from exc
        if host not in self._allowed_hosts:
            raise EgressError(EgressErrorCode.HOST_NOT_ALLOWED)
        resolved_port = port if port is not None else _DEFAULT_PORTS[scheme]
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"
        if any(ord(char) < 33 for char in path):
            raise EgressError(EgressErrorCode.INVALID_URL)
        return scheme, host, resolved_port, path

    def _resolve(self, host: str, port: int) -> str:
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        if literal is not None:
            addresses = [str(literal)]
        else:
            try:
                addresses = self._resolver(host, port)
            except (OSError, UnicodeError) as exc:
                raise EgressError(EgressErrorCode.DNS_FAILURE) from exc
        if not addresses:
            raise EgressError(EgressErrorCode.DNS_FAILURE)
        # Every answer must be permitted: a mixed answer set is how rebinding and
        # split-horizon tricks slip a private address past a single check.
        if not all(self._policy.is_address_permitted(address) for address in addresses):
            raise EgressError(EgressErrorCode.BLOCKED_ADDRESS)
        return addresses[0]

    # -- transport --------------------------------------------------------------

    def _budget(self, host: str) -> _HostBudget:
        with self._budgets_lock:
            budget = self._budgets.get(host)
            if budget is None:
                budget = _HostBudget(
                    semaphore=threading.BoundedSemaphore(self._policy.max_concurrency_per_target)
                )
                self._budgets[host] = budget
            return budget

    def _remaining(self, deadline: float) -> float:
        remaining = deadline - self._monotonic()
        if remaining <= 0:
            raise EgressError(EgressErrorCode.TIMEOUT)
        return remaining

    def _send(
        self,
        method: str,
        scheme: str,
        host: str,
        port: int,
        path: str,
        address: str,
        headers: Mapping[str, str] | None,
        body: bytes | None,
        deadline: float,
    ) -> tuple[int, dict[str, str], bytes]:
        budget = self._budget(host)
        if not budget.semaphore.acquire(timeout=self._remaining(deadline)):
            raise EgressError(EgressErrorCode.BUDGET)
        try:
            with budget.lock:
                wait = budget.next_allowed_at - self._monotonic()
                if wait > 0:
                    if wait >= self._remaining(deadline):
                        raise EgressError(EgressErrorCode.BUDGET)
                    time.sleep(wait)
                budget.next_allowed_at = (
                    self._monotonic() + 1.0 / self._policy.max_requests_per_second
                )
            return self._exchange(
                method, scheme, host, port, path, address, headers, body, deadline
            )
        finally:
            budget.semaphore.release()

    def _exchange(
        self,
        method: str,
        scheme: str,
        host: str,
        port: int,
        path: str,
        address: str,
        headers: Mapping[str, str] | None,
        body: bytes | None,
        deadline: float,
    ) -> tuple[int, dict[str, str], bytes]:
        connect_timeout = min(self._policy.connect_timeout_seconds, self._remaining(deadline))
        try:
            raw = self._socket_factory(address, port, connect_timeout)
        except TimeoutError as exc:
            raise EgressError(EgressErrorCode.TIMEOUT) from exc
        except OSError as exc:
            raise EgressError(EgressErrorCode.CONNECTION_FAILED) from exc

        sock: socket.socket = raw
        try:
            read_timeout = min(self._policy.read_timeout_seconds, self._remaining(deadline))
            raw.settimeout(read_timeout)
            if scheme == "https":
                sock = self._ssl_context.wrap_socket(raw, server_hostname=host)
            connection = _PinnedConnection(host, port, sock, read_timeout)
            request_headers = {
                "Host": host if port == _DEFAULT_PORTS[scheme] else f"{host}:{port}",
                "User-Agent": self._policy.user_agent,
                "Accept-Encoding": "gzip, deflate",
                "Connection": "close",
            }
            for name, value in (headers or {}).items():
                if name.lower() not in {"host", "user-agent", "connection", "accept-encoding"}:
                    request_headers[name] = value
            connection.request(method, path, body=body, headers=request_headers)
            self.requests_made += 1
            response = connection.getresponse()
            status = response.status
            response_headers = {name.lower(): value for name, value in response.getheaders()}
            payload = b""
            if method != "HEAD" and status not in _REDIRECT_STATUSES:
                self._check_content_type(response_headers)
                payload = self._read_body(response, deadline)
                payload = self._decode(payload, response_headers.get("content-encoding", ""))
            return status, response_headers, payload
        except EgressError:
            raise
        except TimeoutError as exc:
            raise EgressError(EgressErrorCode.TIMEOUT) from exc
        except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
            raise EgressError(EgressErrorCode.CONNECTION_FAILED) from exc
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def _check_content_type(self, headers: Mapping[str, str]) -> None:
        allowed = self._policy.allowed_content_types
        media = _media_type(headers.get("content-type", ""))
        if allowed and media not in allowed:
            raise EgressError(EgressErrorCode.CONTENT_TYPE)

    def _read_body(self, response: http.client.HTTPResponse, deadline: float) -> bytes:
        limit = self._policy.max_response_bytes
        declared = response.getheader("content-length")
        if declared is not None and declared.isdigit() and int(declared) > limit:
            raise EgressError(EgressErrorCode.TOO_LARGE)
        chunks: list[bytes] = []
        total = 0
        while True:
            self._remaining(deadline)
            chunk = response.read(min(_CHUNK_BYTES, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise EgressError(EgressErrorCode.TOO_LARGE)
        return b"".join(chunks)

    def _decode(self, payload: bytes, encoding: str) -> bytes:
        encoding = encoding.strip().lower()
        if encoding in {"", "identity"}:
            return payload
        if encoding not in {"gzip", "x-gzip", "deflate"}:
            raise EgressError(EgressErrorCode.CONTENT_TYPE)
        limit = min(
            self._policy.max_response_bytes,
            max(len(payload), 1) * self._policy.max_decompression_ratio,
        )
        wbits = 16 + zlib.MAX_WBITS if "gzip" in encoding else zlib.MAX_WBITS
        decompressor = zlib.decompressobj(wbits)
        try:
            output = decompressor.decompress(payload, limit + 1)
        except zlib.error as exc:
            raise EgressError(EgressErrorCode.CONNECTION_FAILED) from exc
        if len(output) > limit or decompressor.unconsumed_tail:
            raise EgressError(EgressErrorCode.DECOMPRESSION_LIMIT)
        return output


__all__ = [
    "EgressError",
    "EgressErrorCode",
    "GuardedHttpClient",
    "GuardedResponse",
    "system_resolver",
]
