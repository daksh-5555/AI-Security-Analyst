"""Validation tests for the shared tool and evidence contracts (M1)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from app.schemas.tooling import (
    MAX_EXCERPT_LENGTH,
    EvidenceLocation,
    EvidenceProvenance,
    EvidenceRecord,
    EvidenceSourceType,
    SafeErrorCode,
    ToolIdentity,
    ToolLimitation,
    ToolResult,
    ToolStatus,
    is_absolute_host_path,
)

NOW = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)
TOOL = ToolIdentity(name="example_tool", version="1.0.0")


def _record(key: str = "example_tool:rule.one:abc", **overrides: object) -> EvidenceRecord:
    values: dict[str, object] = {
        "evidence_key": key,
        "source_type": EvidenceSourceType.REPOSITORY,
        "provenance": EvidenceProvenance(
            tool=TOOL, rule_id="rule.one", observed_at=NOW, method="unit test"
        ),
        "location": EvidenceLocation(path="src/app.py", line=3),
        "summary": "Something was observed.",
    }
    values.update(overrides)
    return EvidenceRecord(**values)


def _result(**overrides: object) -> ToolResult:
    values: dict[str, object] = {
        "tool": TOOL,
        "stage": "example",
        "status": ToolStatus.COMPLETED,
        "started_at": NOW,
        "finished_at": NOW + timedelta(seconds=1),
    }
    values.update(overrides)
    return ToolResult(**values)


@pytest.mark.parametrize(
    "path",
    [
        "/etc/passwd",
        "/srv/repositories/project/app.py",
        "C:\\Users\\alice\\repo\\app.py",
        "C:/Users/alice/repo/app.py",
        "\\\\server\\share\\repo\\app.py",
        "//server/share/app.py",
        "~/repo/app.py",
        "D:relative-drive.py",
    ],
)
def test_locations_reject_absolute_host_paths(path: str) -> None:
    assert is_absolute_host_path(path)
    with pytest.raises(ValidationError):
        EvidenceLocation(path=path)


@pytest.mark.parametrize("path", ["src/app.py", "src\\app.py", "app.py", ".env", "a/b/c.txt"])
def test_locations_accept_relative_paths_and_normalize_separators(path: str) -> None:
    location = EvidenceLocation(path=path, line=1)
    assert "\\" not in (location.path or "")
    assert not is_absolute_host_path(location.path or "")


def test_locations_reject_traversal_and_require_an_anchor() -> None:
    with pytest.raises(ValidationError):
        EvidenceLocation(path="src/../../etc/passwd")
    with pytest.raises(ValidationError):
        EvidenceLocation()
    with pytest.raises(ValidationError):
        EvidenceLocation(url_path="/login", line=4)


@pytest.mark.parametrize(
    "url_path",
    ["https://example.com/x", "//example.com/x", "relative/path", "/user:pass@host/x"],
)
def test_url_locations_must_be_origin_relative_without_credentials(url_path: str) -> None:
    with pytest.raises(ValidationError):
        EvidenceLocation(url_path=url_path)


def test_url_location_accepts_path_and_parameter() -> None:
    location = EvidenceLocation(url_path="/search?q=", parameter="q")
    assert location.parameter == "q"


def test_excerpt_is_bounded_and_digests_are_validated() -> None:
    with pytest.raises(ValidationError):
        _record(redacted_excerpt="x" * (MAX_EXCERPT_LENGTH + 1))
    with pytest.raises(ValidationError):
        _record(content_hash="not-a-digest")
    with pytest.raises(ValidationError):
        _record(fingerprint="A" * 64)
    assert _record(content_hash="a" * 64).content_hash == "a" * 64


def test_evidence_record_has_no_raw_value_field() -> None:
    with pytest.raises(ValidationError):
        _record(raw_value="AKIAIOSFODNN7EXAMPLE")
    assert "raw" not in " ".join(EvidenceRecord.model_fields)


@pytest.mark.parametrize("name", ["Upper", "has space", "", "-leading", "x" * 201])
def test_identifiers_are_constrained(name: str) -> None:
    with pytest.raises(ValidationError):
        ToolIdentity(name=name, version="1")


@pytest.mark.parametrize(
    ("status", "error_code"),
    [
        (ToolStatus.FAILED, None),
        (ToolStatus.CANCELLED, None),
        (ToolStatus.SKIPPED, None),
        (ToolStatus.COMPLETED, SafeErrorCode.TOOL_ERROR),
    ],
)
def test_status_and_error_code_must_be_consistent(
    status: ToolStatus, error_code: SafeErrorCode | None
) -> None:
    with pytest.raises(ValidationError):
        _result(status=status, error_code=error_code)


def test_partial_results_must_explain_the_gap() -> None:
    with pytest.raises(ValidationError):
        _result(status=ToolStatus.PARTIAL)
    partial = _result(
        status=ToolStatus.PARTIAL,
        limitations=[ToolLimitation(code="max_files", detail="Stopped after 10 files.")],
    )
    assert not partial.is_clean


def test_failed_and_skipped_results_cannot_carry_evidence() -> None:
    with pytest.raises(ValidationError):
        _result(
            status=ToolStatus.FAILED,
            error_code=SafeErrorCode.TOOL_ERROR,
            evidence=[_record()],
        )


def test_time_ordering_and_unique_evidence_keys() -> None:
    with pytest.raises(ValidationError):
        _result(finished_at=NOW - timedelta(seconds=1))
    with pytest.raises(ValidationError):
        _result(evidence=[_record(), _record()])
    with pytest.raises(ValidationError):
        _result(counts={"files": -1})


def test_clean_means_completed_without_evidence() -> None:
    assert _result().is_clean
    assert not _result(evidence=[_record()]).is_clean
    assert not _result(status=ToolStatus.SKIPPED, error_code=SafeErrorCode.DISABLED).is_clean


def test_serialization_is_deterministic() -> None:
    first = _result(evidence=[_record()], counts={"b": 1, "a": 2}).model_dump_json()
    second = _result(evidence=[_record()], counts={"b": 1, "a": 2}).model_dump_json()
    assert first == second
    assert ToolResult.model_validate_json(first) == _result(
        evidence=[_record()], counts={"b": 1, "a": 2}
    )
