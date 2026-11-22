"""URL normalization, crawl scope, and safety classification (ADR-0008).

- Canonical URLs: lower-case scheme and host, default port removed, fragment
  dropped, dot segments resolved, query parameters sorted. These are the
  deduplication keys.
- Scope: same scheme, host, and port as the authorized target, inside its base
  path (segment-aware), and not under a configured excluded path prefix.
- Safety: links whose path or query suggests a state-changing action (log out,
  delete, purchase, upload, …) are never requested. Forms are never submitted;
  they are only classified.
- Evidence locations keep the path and parameter *names*; query values are
  never stored.
"""

from __future__ import annotations

import posixpath
import re
from typing import Final
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlsplit, urlunsplit

from app.services.crawler.html import ParsedForm
from app.services.target_authorization import CanonicalWebTarget, within_base_path

_DEFAULT_PORTS: Final[dict[str, int]] = {"http": 80, "https": 443}
_IGNORED_SCHEMES: Final[frozenset[str]] = frozenset(
    {"mailto", "javascript", "data", "tel", "ftp", "file", "about", "blob", "sms"}
)
DESTRUCTIVE: Final[re.Pattern[str]] = re.compile(
    r"(log[-_]?out|sign[-_]?out|log[-_]?off|delete|remove|destroy|drop|reset|purge|"
    r"purchase|checkout|payment|\bpay\b|order|upload|unsubscribe|deactivate|disable|"
    r"shutdown|reboot|kill|wipe|transfer|withdraw|setup\.php|install|security\.php)",
    re.IGNORECASE,
)
_LOGIN_PATH: Final[re.Pattern[str]] = re.compile(r"(log[-_]?in|sign[-_]?in|auth)", re.IGNORECASE)


def canonical_url(url: str) -> str | None:
    """Canonical absolute http(s) URL, or None if it cannot be crawled."""
    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS or not parts.hostname:
        return None
    if parts.username is not None or parts.password is not None:
        return None
    host = parts.hostname.lower().rstrip(".")
    if ":" in host:
        host = f"[{host}]"
    netloc = host if port in (None, _DEFAULT_PORTS[scheme]) else f"{host}:{port}"
    path = parts.path or "/"
    normalized = posixpath.normpath(path)
    if path.endswith("/") and normalized != "/":
        normalized += "/"
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    normalized = re.sub(r"/{2,}", "/", normalized)
    query = urlencode(sorted(parse_qsl(parts.query, keep_blank_values=True)))
    return urlunsplit((scheme, netloc, normalized, query, ""))


def resolve_link(base_url: str, href: str) -> str | None:
    href = href.strip()
    if not href or href.startswith("#"):
        return None
    scheme = urlsplit(href).scheme.lower()
    if scheme in _IGNORED_SCHEMES:
        return None
    try:
        return canonical_url(urljoin(base_url, href))
    except ValueError:
        return None


def in_scope(url: str, target: CanonicalWebTarget, excluded_prefixes: list[str]) -> bool:
    parts = urlsplit(url)
    port = parts.port or _DEFAULT_PORTS.get(parts.scheme, 0)
    if parts.scheme != target.scheme or (parts.hostname or "") != target.host:
        return False
    if port != target.port:
        return False
    path = parts.path or "/"
    if not within_base_path(path, target.base_path):
        return False
    return not any(within_base_path(path, prefix) for prefix in excluded_prefixes)


def is_destructive(url: str) -> bool:
    parts = urlsplit(url)
    return bool(DESTRUCTIVE.search(f"{parts.path}?{parts.query}"))


def is_login_path(url: str) -> bool:
    return bool(_LOGIN_PATH.search(urlsplit(url).path))


def template_key(url: str) -> str:
    """Path plus sorted parameter names: limits crawling many values of one page."""
    parts = urlsplit(url)
    names = sorted({name for name, _ in parse_qsl(parts.query, keep_blank_values=True)})
    return f"{parts.path}?{'&'.join(names)}"


def evidence_path(url: str) -> str:
    """Origin-relative path with parameter names only (values are never stored)."""
    parts = urlsplit(url)
    path = quote(parts.path or "/", safe="/-._~!$&'()*+,;=:%")
    names = sorted({name for name, _ in parse_qsl(parts.query, keep_blank_values=True)})
    query = "&".join(f"{quote(name, safe='')}=" for name in names)
    return f"{path}?{query}" if query else path


def parameter_names(url: str) -> list[str]:
    return sorted({name for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)})


def classify_form(form: ParsedForm, action_url: str | None) -> str:
    types = {field.type for field in form.fields}
    if "file" in types or (form.enctype or "").lower() == "multipart/form-data":
        return "upload"
    if "password" in types:
        return (
            "login"
            if len([t for t in types if t not in {"hidden", "submit"}]) <= 3
            else "credential"
        )
    if action_url is not None and is_destructive(action_url):
        return "state_changing"
    if form.method == "GET":
        return "search" if any(f.type in {"search", "text"} for f in form.fields) else "query"
    return "state_changing"


__all__ = [
    "DESTRUCTIVE",
    "canonical_url",
    "classify_form",
    "evidence_path",
    "in_scope",
    "is_destructive",
    "is_login_path",
    "parameter_names",
    "resolve_link",
    "template_key",
]
