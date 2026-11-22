"""OSV advisory provider with a freshness-labelled cache (ADR-0007).

Network access happens only through ``GuardedHttpClient`` and only to the
configured OSV host. Advisory data is untrusted: responses are size-limited by
the client, parsed as JSON, type-checked field by field, identifiers are
validated before they are placed in a URL path, and free text is stripped of
control characters and truncated.

Every package lookup ends in exactly one state:

- ``fresh``: answered from the provider or a cache entry younger than the TTL;
- ``stale``: answered from an expired cache entry because the provider was not
  used (offline mode) or failed;
- ``unavailable``: no data. This is reported as unchecked, never as
  "no vulnerabilities".
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Final, Literal

from app.services.analysis_execution_context import AnalysisExecutionContext
from app.services.dependencies.versions import Ecosystem, normalize_name
from app.services.net import EgressError, GuardedHttpClient

PROVIDER_NAME: Final[str] = "osv"
_ADVISORY_ID: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:\-]{1,99}$")
_CONTROL: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]+")
_BATCH_SIZE: Final[int] = 500
_MAX_PAGES: Final[int] = 10
_MAX_CACHE_FILE_BYTES: Final[int] = 4 * 1024 * 1024
_MAX_TEXT: Final[int] = 300


class Freshness(StrEnum):
    FRESH = "fresh"
    STALE = "stale"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class PackageQuery:
    ecosystem: Ecosystem
    name: str
    version: str

    @property
    def canonical_name(self) -> str:
        return normalize_name(self.ecosystem, self.name)

    @property
    def cache_key(self) -> str:
        name = normalize_name(self.ecosystem, self.name)
        return f"query:{self.ecosystem.value}:{name}:{self.version}"


@dataclass(frozen=True, slots=True)
class Advisory:
    id: str
    aliases: tuple[str, ...]
    summary: str
    severity: str | None
    published: str | None
    modified: str | None
    affected: tuple[dict[str, Any], ...]
    source_url: str
    fetched_at: datetime
    freshness: Freshness

    @property
    def cve_ids(self) -> tuple[str, ...]:
        return tuple(alias for alias in (self.id, *self.aliases) if alias.startswith("CVE-"))


@dataclass(frozen=True, slots=True)
class PackageAdvisories:
    query: PackageQuery
    freshness: Freshness
    advisories: tuple[Advisory, ...] = ()
    reason: str | None = None


@dataclass
class LookupResult:
    packages: dict[PackageQuery, PackageAdvisories] = field(default_factory=dict)
    requests_made: int = 0


def _clean(value: Any, limit: int = _MAX_TEXT) -> str:
    text = _CONTROL.sub(" ", str(value)).strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


class AdvisoryCache:
    """Process-memory cache, optionally persisted to ``directory`` as JSON files."""

    def __init__(
        self,
        directory: Path | None,
        *,
        ttl_seconds: int,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._directory = directory
        self._ttl = timedelta(seconds=ttl_seconds)
        self._clock = clock
        self._memory: dict[str, tuple[Any, datetime]] = {}
        self._lock = threading.Lock()

    def _path(self, key: str) -> Path | None:
        if self._directory is None:
            return None
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return self._directory / f"{digest}.json"

    def get(self, key: str) -> tuple[Any, datetime, bool] | None:
        """Return ``(payload, fetched_at, is_fresh)`` or None when absent."""
        with self._lock:
            entry = self._memory.get(key)
        if entry is None:
            entry = self._read_file(key)
            if entry is not None:
                with self._lock:
                    self._memory[key] = entry
        if entry is None:
            return None
        payload, fetched_at = entry
        return payload, fetched_at, self._clock() - fetched_at < self._ttl

    def put(self, key: str, payload: Any) -> None:
        fetched_at = self._clock()
        with self._lock:
            self._memory[key] = (payload, fetched_at)
        path = self._path(key)
        if path is None:
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            record = {"key": key, "fetched_at": fetched_at.isoformat(), "payload": payload}
            with tempfile.NamedTemporaryFile(
                "w", encoding="utf-8", dir=path.parent, delete=False, suffix=".tmp"
            ) as handle:
                json.dump(record, handle, sort_keys=True)
                temporary = Path(handle.name)
            os.replace(temporary, path)
        except OSError:
            return  # the in-memory entry still serves this process

    def _read_file(self, key: str) -> tuple[Any, datetime] | None:
        path = self._path(key)
        if path is None:
            return None
        try:
            if path.is_symlink() or path.stat().st_size > _MAX_CACHE_FILE_BYTES:
                return None
            record = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(record, dict) or record.get("key") != key:
                return None
            fetched_at = datetime.fromisoformat(record["fetched_at"])
            if fetched_at.tzinfo is None:
                return None
            return record.get("payload"), fetched_at
        except (OSError, ValueError, KeyError, TypeError):
            return None


class OsvAdvisoryProvider:
    """Looks up advisories for exact package versions."""

    name: Final[str] = PROVIDER_NAME

    def __init__(
        self,
        *,
        base_url: str,
        cache: AdvisoryCache,
        mode: Literal["online", "offline"],
        client: GuardedHttpClient | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if mode == "online" and client is None:
            raise ValueError("online mode requires a guarded client")
        self._base_url = base_url.rstrip("/")
        self._cache = cache
        self._mode = mode
        self._client = client
        self._clock = clock

    @property
    def mode(self) -> str:
        return self._mode

    # -- public -----------------------------------------------------------------

    def lookup(
        self,
        queries: Iterable[PackageQuery],
        execution: AnalysisExecutionContext | None = None,
    ) -> LookupResult:
        result = LookupResult()
        ordered = list(dict.fromkeys(queries))
        ids_by_query: dict[PackageQuery, tuple[list[str], datetime, Freshness]] = {}
        to_fetch: list[PackageQuery] = []

        for query in ordered:
            cached = self._cache.get(query.cache_key)
            if cached is not None and cached[2]:
                ids_by_query[query] = (self._valid_ids(cached[0]), cached[1], Freshness.FRESH)
            else:
                to_fetch.append(query)

        if self._mode == "online" and to_fetch:
            for start in range(0, len(to_fetch), _BATCH_SIZE):
                if execution is not None:
                    execution.check()
                chunk = to_fetch[start : start + _BATCH_SIZE]
                fetched = self._query_batch(chunk, execution, result)
                for query, ids in fetched.items():
                    self._cache.put(query.cache_key, ids)
                    ids_by_query[query] = (ids, self._clock(), Freshness.FRESH)

        for query in ordered:
            if query in ids_by_query:
                continue
            cached = self._cache.get(query.cache_key)
            if cached is not None:
                ids_by_query[query] = (self._valid_ids(cached[0]), cached[1], Freshness.STALE)
            else:
                reason = "offline_not_cached" if self._mode == "offline" else "provider_unavailable"
                result.packages[query] = PackageAdvisories(
                    query, Freshness.UNAVAILABLE, reason=reason
                )

        for query, (ids, _fetched_at, freshness) in ids_by_query.items():
            advisories: list[Advisory] = []
            missing = False
            for advisory_id in ids:
                if execution is not None:
                    execution.check()
                advisory = self._advisory(advisory_id, query, execution, result)
                if advisory is None:
                    missing = True
                    continue
                advisories.append(advisory)
            if missing:
                result.packages[query] = PackageAdvisories(
                    query, Freshness.UNAVAILABLE, tuple(advisories), "advisory_details_unavailable"
                )
                continue
            overall = (
                Freshness.STALE
                if freshness is Freshness.STALE
                or any(item.freshness is Freshness.STALE for item in advisories)
                else Freshness.FRESH
            )
            result.packages[query] = PackageAdvisories(query, overall, tuple(advisories))
        return result

    # -- provider calls ---------------------------------------------------------

    @staticmethod
    def _valid_ids(payload: Any) -> list[str]:
        if not isinstance(payload, list):
            return []
        return sorted({str(item) for item in payload if _ADVISORY_ID.fullmatch(str(item))})

    def _post(
        self,
        path: str,
        body: dict[str, Any],
        execution: AnalysisExecutionContext | None,
        result: LookupResult,
    ) -> Any:
        if self._client is None:
            raise ValueError("no client configured")
        response = self._client.request(
            "POST",
            f"{self._base_url}{path}",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            body=json.dumps(body, sort_keys=True).encode("utf-8"),
            execution=execution,
        )
        result.requests_made += 1
        if response.status != 200:
            raise ValueError("unexpected advisory status")
        return json.loads(response.body)

    def _query_batch(
        self,
        chunk: list[PackageQuery],
        execution: AnalysisExecutionContext | None,
        result: LookupResult,
    ) -> dict[PackageQuery, list[str]]:
        payload = {
            "queries": [
                {
                    "package": {"name": query.canonical_name, "ecosystem": query.ecosystem.value},
                    "version": query.version,
                }
                for query in chunk
            ]
        }
        try:
            data = self._post("/v1/querybatch", payload, execution, result)
            rows = data.get("results") if isinstance(data, dict) else None
            if not isinstance(rows, list) or len(rows) != len(chunk):
                return {}
        except (EgressError, ValueError, TypeError):
            return {}

        fetched: dict[PackageQuery, list[str]] = {}
        for query, row in zip(chunk, rows, strict=True):
            if not isinstance(row, dict):
                continue
            ids = [vuln.get("id") for vuln in row.get("vulns") or [] if isinstance(vuln, dict)]
            token = row.get("next_page_token")
            pages = 0
            complete = True
            while isinstance(token, str) and token and pages < _MAX_PAGES:
                pages += 1
                try:
                    page = self._post(
                        "/v1/query",
                        {
                            "package": {
                                "name": query.canonical_name,
                                "ecosystem": query.ecosystem.value,
                            },
                            "version": query.version,
                            "page_token": token,
                        },
                        execution,
                        result,
                    )
                except (EgressError, ValueError, TypeError):
                    complete = False
                    break
                if not isinstance(page, dict):
                    complete = False
                    break
                ids.extend(v.get("id") for v in page.get("vulns") or [] if isinstance(v, dict))
                token = page.get("next_page_token")
            if isinstance(token, str) and token:
                complete = False
            if complete:
                fetched[query] = self._valid_ids(ids)
        return fetched

    def _advisory(
        self,
        advisory_id: str,
        query: PackageQuery,
        execution: AnalysisExecutionContext | None,
        result: LookupResult,
    ) -> Advisory | None:
        key = f"vuln:{advisory_id}"
        cached = self._cache.get(key)
        record: Any = None
        fetched_at = self._clock()
        freshness = Freshness.FRESH
        if cached is not None and cached[2]:
            record, fetched_at = cached[0], cached[1]
        elif self._mode == "online":
            if self._client is None:
                return None
            try:
                response = self._client.request(
                    "GET",
                    f"{self._base_url}/v1/vulns/{advisory_id}",
                    headers={"Accept": "application/json"},
                    execution=execution,
                )
                result.requests_made += 1
                if response.status == 200:
                    record = json.loads(response.body)
                    self._cache.put(key, record)
            except (EgressError, ValueError):
                record = None
        if record is None and cached is not None:
            record, fetched_at, freshness = cached[0], cached[1], Freshness.STALE
        if not isinstance(record, dict) or record.get("id") != advisory_id:
            return None
        return self._to_advisory(record, query, fetched_at, freshness)

    @staticmethod
    def _to_advisory(
        record: dict[str, Any],
        query: PackageQuery,
        fetched_at: datetime,
        freshness: Freshness,
    ) -> Advisory:
        wanted = normalize_name(query.ecosystem, query.name)
        affected = []
        severity = None
        for entry in record.get("affected") or []:
            if not isinstance(entry, dict):
                continue
            package = entry.get("package") or {}
            if not isinstance(package, dict):
                continue
            if package.get("ecosystem") != query.ecosystem.value:
                continue
            if normalize_name(query.ecosystem, str(package.get("name", ""))) != wanted:
                continue
            affected.append(
                {"ranges": entry.get("ranges") or [], "versions": entry.get("versions") or []}
            )
            specific = entry.get("database_specific") or {}
            if isinstance(specific, dict) and isinstance(specific.get("severity"), str):
                severity = specific["severity"]
        top = record.get("database_specific") or {}
        if severity is None and isinstance(top, dict) and isinstance(top.get("severity"), str):
            severity = top["severity"]
        aliases = tuple(
            sorted(
                str(alias)
                for alias in record.get("aliases") or []
                if _ADVISORY_ID.fullmatch(str(alias))
            )
        )
        advisory_id = str(record["id"])
        return Advisory(
            id=advisory_id,
            aliases=aliases,
            summary=_clean(
                record.get("summary") or record.get("details") or "No summary provided."
            ),
            severity=_clean(severity, 20) if severity else None,
            published=_clean(record["published"], 40) if record.get("published") else None,
            modified=_clean(record["modified"], 40) if record.get("modified") else None,
            affected=tuple(affected),
            source_url=f"https://osv.dev/vulnerability/{advisory_id}",
            fetched_at=fetched_at,
            freshness=freshness,
        )


__all__ = [
    "Advisory",
    "AdvisoryCache",
    "Freshness",
    "LookupResult",
    "OsvAdvisoryProvider",
    "PackageAdvisories",
    "PackageQuery",
]
