"""Repository secret scanner (M2, ADR-0005).

Reads only files listed in the validated discovery inventory, including `.env`
and key files (M0 decision D5): those are exactly where committed credentials
live. Unlike the other analyzers, this tool therefore does open sensitive files,
but nothing it reads leaves the process unredacted:

- the secret span is masked in a bounded excerpt before an ``EvidenceRecord`` is
  built;
- only a keyed HMAC fingerprint of the value is kept (for deduplication);
- no value, excerpt, or path is logged, and no network call is ever made.

The scanner never executes, imports, or validates anything it finds.
"""

from __future__ import annotations

import fnmatch
import secrets
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import PurePosixPath
from typing import Final

from app.core.config import SecretAllowlistEntry, settings
from app.schemas.tooling import (
    EvidenceLocation,
    EvidenceProvenance,
    EvidenceRecord,
    EvidenceSourceType,
    ToolIdentity,
    ToolLimitation,
    ToolResult,
    ToolStatus,
)
from app.services.repository_targets import validate_repository_location
from app.services.secret_scanning.rules import (
    EXCERPT_MASK_PATTERNS,
    RULE_SET_VERSION,
    SecretRule,
    is_placeholder,
    rule_catalog,
    shannon_entropy,
)
from app.services.tooling.files import read_bounded
from app.services.tooling.protocol import ToolContext
from app.services.tooling.redaction import evidence_key, keyed_fingerprint, redact_excerpt

SECRET_SCAN_STAGE: Final[str] = "secret_scan"
TOOL_VERSION: Final[str] = "1.0.0"
MAX_SCAN_LINE_CHARS: Final[int] = 4_096
EXCERPT_CONTEXT_CHARS: Final[int] = 60
MAX_PRIVATE_KEY_LINES: Final[int] = 400
_BINARY_SNIFF_BYTES: Final[int] = 8_192

# A process-local key is used only when no deployment key is configured
# (development/test). Startup validation requires a key in staging/production.
_EPHEMERAL_FINGERPRINT_KEY: Final[bytes] = secrets.token_bytes(32)

_BINARY_EXTENSIONS: Final[frozenset[str]] = frozenset(
    {
        "png", "jpg", "jpeg", "gif", "bmp", "ico", "webp", "tif", "tiff", "psd",
        "pdf", "zip", "gz", "tgz", "bz2", "xz", "7z", "rar", "jar", "war", "ear",
        "class", "so", "dll", "dylib", "exe", "bin", "o", "a", "lib", "pyc", "pyo",
        "whl", "egg", "woff", "woff2", "ttf", "otf", "eot", "mp3", "mp4", "mov",
        "avi", "wav", "flac", "ogg", "webm", "sqlite", "sqlite3", "db", "parquet",
    }
)  # fmt: skip
_LOCK_FILES: Final[frozenset[str]] = frozenset(
    {
        "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
        "poetry.lock", "pipfile.lock", "cargo.lock", "composer.lock", "go.sum",
        "gemfile.lock", "pdm.lock", "uv.lock",
    }
)  # fmt: skip
_VENDORED_SEGMENTS: Final[frozenset[str]] = frozenset(
    {"vendor", "third_party", "third-party", "site-packages", "bower_components", "jspm_packages"}
)
_GENERATED_SUFFIXES: Final[tuple[str, ...]] = (".min.js", ".min.css", ".map", ".bundle.js")
_TEST_SEGMENTS: Final[frozenset[str]] = frozenset(
    {"test", "tests", "__tests__", "spec", "specs", "fixture", "fixtures", "testdata", "test_data"}
)
_EXAMPLE_SEGMENTS: Final[frozenset[str]] = frozenset(
    {"example", "examples", "sample", "samples", "docs", "doc"}
)
_EXAMPLE_MARKERS: Final[tuple[str, ...]] = (".example", ".sample", ".template", ".dist", ".tmpl")

# Skip reasons that are documented policy exclusions versus coverage gaps.
_POLICY_EXCLUSIONS: Final[frozenset[str]] = frozenset(
    {"binary", "lock_file", "vendored", "generated"}
)


class SecretScanError(RuntimeError):
    """Raised for an unusable scanner configuration or repository root."""


@dataclass
class _Match:
    rule: SecretRule
    path: str
    line_number: int
    line: str
    span: tuple[int, int]
    fingerprint: str
    context: str


@dataclass
class _ScanState:
    files_scanned: int = 0
    bytes_scanned: int = 0
    placeholders_ignored: int = 0
    long_lines_truncated: int = 0
    skipped: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    allowlisted: dict[int, int] = field(default_factory=lambda: defaultdict(int))
    truncation: list[str] = field(default_factory=list)
    matches: list[_Match] = field(default_factory=list)


def _file_context(relative_path: str) -> str:
    path = PurePosixPath(relative_path)
    parts = {part.lower() for part in path.parts[:-1]}
    name = path.name.lower()
    if parts & _TEST_SEGMENTS or (
        name.startswith("test_")
        or name.endswith(("_test.py", "_test.go", ".test.js", ".test.ts", ".spec.js", ".spec.ts"))
    ):
        return "test_fixture"
    if parts & _EXAMPLE_SEGMENTS or any(marker in name for marker in _EXAMPLE_MARKERS):
        return "example"
    return "source"


def _is_dotenv(relative_path: str) -> bool:
    name = PurePosixPath(relative_path).name.lower()
    return name == ".env" or name.startswith(".env.") or name.endswith(".env")


def _policy_exclusion(relative_path: str, extension: str | None) -> str | None:
    path = PurePosixPath(relative_path)
    name = path.name.lower()
    if extension and extension.lower() in _BINARY_EXTENSIONS:
        return "binary"
    if name in _LOCK_FILES:
        return "lock_file"
    if any(part.lower() in _VENDORED_SEGMENTS for part in path.parts[:-1]):
        return "vendored"
    if name.endswith(_GENERATED_SUFFIXES):
        return "generated"
    return None


def _fingerprint_key() -> tuple[bytes, bool]:
    configured = settings.evidence_fingerprint_key
    if configured is None:
        return _EPHEMERAL_FINGERPRINT_KEY, True
    return configured.get_secret_value().encode("utf-8"), False


def _allowlist_index(
    entries: list[SecretAllowlistEntry], rule_id: str, relative_path: str
) -> int | None:
    for index, entry in enumerate(entries):
        if entry.rule_id == rule_id and fnmatch.fnmatchcase(relative_path, entry.path_glob):
            return index
    return None


class SecretScannerTool:
    """Deterministic, offline secret scanner over a discovery inventory."""

    def __init__(self) -> None:
        self._identity = ToolIdentity(
            name="secret_scanner",
            version=TOOL_VERSION,
            rule_set_version=RULE_SET_VERSION,
        )

    @property
    def identity(self) -> ToolIdentity:
        return self._identity

    def applies_to(self, context: ToolContext) -> bool:
        return context.discovery is not None

    def run(self, context: ToolContext) -> ToolResult:
        discovery = context.discovery
        if discovery is None:
            raise SecretScanError("discovery inventory is required")
        started_at = context.clock()
        root = validate_repository_location(discovery.root)

        rules = rule_catalog(list(settings.secret_scan_custom_rules))
        allowlist = list(settings.secret_scan_allowlist)
        key, ephemeral = _fingerprint_key()
        state = _ScanState()
        max_files = settings.secret_scan_max_files
        max_total = settings.secret_scan_max_total_bytes
        max_matches = settings.secret_scan_max_matches

        for entry in discovery.files:
            context.execution.check()
            exclusion = _policy_exclusion(entry.relative_path, entry.extension)
            if exclusion is not None:
                state.skipped[exclusion] += 1
                continue
            if state.files_scanned >= max_files:
                state.truncation.append("max_files")
                break
            if state.bytes_scanned + entry.size_bytes > max_total:
                state.truncation.append("max_total_bytes")
                break
            data, outcome = read_bounded(
                root, entry.relative_path, settings.secret_scan_max_file_size_bytes
            )
            if data is None:
                state.skipped[outcome] += 1
                continue
            if b"\x00" in data[:_BINARY_SNIFF_BYTES]:
                state.skipped["binary"] += 1
                continue
            state.files_scanned += 1
            state.bytes_scanned += len(data)
            self._scan_text(
                data.decode("utf-8", errors="replace"),
                entry.relative_path,
                rules,
                allowlist,
                key,
                state,
            )
            if len(state.matches) >= max_matches:
                state.truncation.append("max_matches")
                break

        observed_at = context.clock()
        evidence = self._evidence(state.matches[:max_matches], observed_at)
        limitations = self._limitations(state, allowlist, ephemeral, discovery.summary.is_complete)
        coverage_gap = (
            bool(state.truncation)
            or state.long_lines_truncated > 0
            or not discovery.summary.is_complete
            or any(reason not in _POLICY_EXCLUSIONS for reason in state.skipped)
        )
        counts = {
            "files_scanned": state.files_scanned,
            "bytes_scanned": state.bytes_scanned,
            "matches": len(evidence),
            "placeholders_ignored": state.placeholders_ignored,
            "allowlisted": sum(state.allowlisted.values()),
            "long_lines_truncated": state.long_lines_truncated,
        }
        counts.update(
            {f"skipped_{reason}": count for reason, count in sorted(state.skipped.items())}
        )
        return ToolResult(
            tool=self._identity,
            stage=SECRET_SCAN_STAGE,
            status=ToolStatus.PARTIAL if coverage_gap else ToolStatus.COMPLETED,
            started_at=started_at,
            finished_at=context.clock(),
            counts=counts,
            evidence=evidence,
            limitations=limitations,
        )

    def _scan_text(
        self,
        text: str,
        relative_path: str,
        rules: tuple[SecretRule, ...],
        allowlist: list[SecretAllowlistEntry],
        key: bytes,
        state: _ScanState,
    ) -> None:
        dotenv = _is_dotenv(relative_path)
        file_context = _file_context(relative_path)
        lines = text.splitlines()
        # ``claimed`` spans resolve overlaps between rules. ``masked`` spans are
        # hidden in excerpts: every candidate value on the line, including ones
        # rejected as placeholders or for low entropy, so an excerpt never shows a
        # credential that a rule chose not to report.
        claimed: dict[int, list[tuple[int, int]]] = defaultdict(list)
        masked: dict[int, list[tuple[int, int]]] = defaultdict(list)
        file_matches: list[_Match] = []

        for index, raw_line in enumerate(lines):
            line = raw_line
            if len(line) > MAX_SCAN_LINE_CHARS:
                line = line[:MAX_SCAN_LINE_CHARS]
                state.long_lines_truncated += 1
            for rule in rules:
                if rule.file_scope == "dotenv" and not dotenv:
                    continue
                for match in rule.pattern.finditer(line):
                    span = rule.secret_span(match)
                    if span[0] == span[1]:
                        continue
                    if any(start < span[1] and span[0] < end for start, end in claimed[index]):
                        continue  # a more specific rule already reported this text
                    value = line[span[0] : span[1]]
                    if rule.multiline_block:
                        # The header line is not secret; the key body is fingerprinted
                        # but never placed in an excerpt.
                        value = self._private_key_block(lines, index)
                    else:
                        masked[index].append(span)
                        if is_placeholder(value):
                            state.placeholders_ignored += 1
                            claimed[index].append(span)
                            continue
                    if rule.min_entropy is not None and shannon_entropy(value) < rule.min_entropy:
                        continue
                    claimed[index].append(span)
                    allowed = _allowlist_index(allowlist, rule.rule_id, relative_path)
                    if allowed is not None:
                        state.allowlisted[allowed] += 1
                        continue
                    file_matches.append(
                        _Match(
                            rule=rule,
                            path=relative_path,
                            line_number=index + 1,
                            line=line,
                            span=span,
                            fingerprint=keyed_fingerprint(value, key),
                            context=file_context,
                        )
                    )
        for match in file_matches:
            line_index = match.line_number - 1
            for pattern in EXCERPT_MASK_PATTERNS:
                for extra in pattern.finditer(match.line):
                    if extra.span(1)[0] < extra.span(1)[1]:
                        masked[line_index].append(extra.span(1))
            match.line = redact_excerpt_source(
                match.line, masked[match.line_number - 1], anchor=match.span
            )
        state.matches.extend(file_matches)

    @staticmethod
    def _private_key_block(lines: list[str], start: int) -> str:
        block = []
        for line in lines[start : start + MAX_PRIVATE_KEY_LINES]:
            block.append(line.strip())
            if line.strip().startswith("-----END "):
                break
        return "\n".join(block)

    def _evidence(self, matches: list[_Match], observed_at: datetime) -> list[EvidenceRecord]:
        records: dict[str, EvidenceRecord] = {}
        for match in matches:
            rule = match.rule
            location = EvidenceLocation(path=match.path, line=match.line_number)
            key = evidence_key(self._identity.name, rule.rule_id, location, match.fingerprint)
            if key in records:
                continue
            confidence = rule.confidence * (0.5 if match.context != "source" else 1.0)
            limitations = [
                "Credential validity was not tested; the value is treated as exposed.",
            ]
            if match.context != "source":
                limitations.append(
                    f"Found in a {match.context.replace('_', ' ')} path; it may be a "
                    "non-production value, but committed credentials should still be rotated."
                )
            records[key] = EvidenceRecord(
                evidence_key=key,
                source_type=EvidenceSourceType.REPOSITORY,
                provenance=EvidenceProvenance(
                    tool=self._identity,
                    rule_id=rule.rule_id,
                    observed_at=observed_at,
                    method=f"pattern rule {rule.rule_id} ({RULE_SET_VERSION})",
                ),
                location=location,
                summary=f"{rule.title} detected ({rule.description})"[:1000],
                redacted_excerpt=match.line,
                fingerprint=match.fingerprint,
                limitations=limitations,
                metadata={
                    "rule_title": rule.title,
                    "severity": rule.severity,
                    "confidence": round(confidence, 3),
                    "file_context": match.context,
                    "remediation": rule.remediation,
                },
            )
        return [records[key] for key in sorted(records)]

    @staticmethod
    def _limitations(
        state: _ScanState,
        allowlist: list[SecretAllowlistEntry],
        ephemeral: bool,
        discovery_complete: bool,
    ) -> list[ToolLimitation]:
        items: list[ToolLimitation] = []
        for reason in sorted(set(state.truncation)):
            items.append(
                ToolLimitation(
                    code=f"truncated.{reason}",
                    detail=f"Scanning stopped early ({reason}); later files were not scanned.",
                )
            )
        if not discovery_complete:
            items.append(
                ToolLimitation(
                    code="discovery_incomplete",
                    detail="The repository inventory was incomplete; some files were not scanned.",
                )
            )
        for reason, count in sorted(state.skipped.items()):
            kind = "excluded by policy" if reason in _POLICY_EXCLUSIONS else "could not be scanned"
            items.append(
                ToolLimitation(
                    code=f"skipped.{reason}",
                    detail=f"{count} file(s) {kind} ({reason.replace('_', ' ')}).",
                )
            )
        if state.long_lines_truncated:
            items.append(
                ToolLimitation(
                    code="long_lines_truncated",
                    detail=(
                        f"{state.long_lines_truncated} line(s) longer than "
                        f"{MAX_SCAN_LINE_CHARS} characters were scanned only in part."
                    ),
                )
            )
        for index, count in sorted(state.allowlisted.items()):
            entry = allowlist[index]
            items.append(
                ToolLimitation(
                    code=f"allowlisted.{entry.rule_id}",
                    detail=(
                        f"{count} match(es) for {entry.rule_id} under '{entry.path_glob}' "
                        f"suppressed by allowlist: {entry.reason}"
                    )[:1000],
                )
            )
        if state.placeholders_ignored:
            items.append(
                ToolLimitation(
                    code="placeholders_ignored",
                    detail=(
                        f"{state.placeholders_ignored} match(es) were documented example or "
                        "placeholder values and were not reported."
                    ),
                )
            )
        if ephemeral:
            items.append(
                ToolLimitation(
                    code="fingerprint_key_ephemeral",
                    detail=(
                        "EVIDENCE_FINGERPRINT_KEY is not set; fingerprints are not comparable "
                        "across processes."
                    ),
                )
            )
        unique = {item.code: item for item in items}
        return [unique[code] for code in sorted(unique)]


def redact_excerpt_source(
    line: str,
    spans: list[tuple[int, int]],
    *,
    anchor: tuple[int, int],
) -> str:
    """Bounded excerpt centred on ``anchor`` with every candidate span masked."""
    window_start = max(0, anchor[0] - EXCERPT_CONTEXT_CHARS)
    window_end = min(len(line), anchor[1] + EXCERPT_CONTEXT_CHARS)
    window = line[window_start:window_end]
    shifted = [
        (max(0, start - window_start), min(len(window), end - window_start))
        for start, end in spans
        if end > window_start and start < window_end
    ]
    return redact_excerpt(window, shifted)


__all__ = ["SECRET_SCAN_STAGE", "SecretScanError", "SecretScannerTool"]
