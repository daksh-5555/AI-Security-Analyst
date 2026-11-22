import json
from typing import Any

import pytest
from pydantic import ValidationError

from app.schemas import (
    AssessmentStatus,
    Evidence,
    Finding,
    FindingSeverity,
    FindingStatus,
)


def finding_payload() -> dict[str, Any]:
    return {
        "title": "SQL injection in search endpoint",
        "category": "SQL injection",
        "severity": "high",
        "status": "inconclusive",
        "confidence": 0.6,
        "summary": "User input reaches a query without parameterization.",
        "evidence": [
            Evidence(
                description="Request input is concatenated into a SQL query.",
                source="static-analysis",
                details={"rule_id": "sql-injection"},
            )
        ],
    }


def make_finding(**overrides: Any) -> Finding:
    payload = finding_payload()
    payload.update(overrides)
    return Finding.model_validate(payload)


def test_finding_construction_with_all_fields() -> None:
    finding = make_finding(
        severity="critical",
        status="confirmed",
        confidence=0.98,
        affected_component="app/search.py:42",
        remediation="Use parameterized queries.",
    )

    assert finding.title == "SQL injection in search endpoint"
    assert finding.category == "SQL injection"
    assert finding.severity is FindingSeverity.CRITICAL
    assert finding.status is FindingStatus.CONFIRMED
    assert finding.confidence == 0.98
    assert finding.affected_component == "app/search.py:42"
    assert finding.evidence[0].source == "static-analysis"
    assert finding.evidence[0].details == {"rule_id": "sql-injection"}
    assert finding.remediation == "Use parameterized queries."


def test_optional_fields_default_to_none() -> None:
    finding = make_finding()

    assert finding.affected_component is None
    assert finding.remediation is None


def test_evidence_details_are_optional() -> None:
    evidence = Evidence(
        description="Port 443 accepts TLS connections.",
        source="network-probe",
    )

    assert evidence.details is None


def test_empty_evidence_collection_is_allowed_when_explicit() -> None:
    finding = make_finding(evidence=[])

    assert finding.evidence == []


def test_enum_vocabularies() -> None:
    assert [status.value for status in AssessmentStatus] == [
        "queued",
        "running",
        "completed",
        "failed",
    ]
    assert [severity.value for severity in FindingSeverity] == [
        "critical",
        "high",
        "medium",
        "low",
        "informational",
        "unknown",
    ]
    assert [status.value for status in FindingStatus] == [
        "confirmed",
        "potential",
        "not_reproduced",
        "inconclusive",
        "not_tested",
    ]


@pytest.mark.parametrize("invalid_status", ["pending", "done", ""])
def test_invalid_assessment_status_rejected(invalid_status: str) -> None:
    with pytest.raises(ValueError):
        AssessmentStatus(invalid_status)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("severity", "severe"),
        ("status", "open"),
    ],
)
def test_invalid_finding_enum_rejected(field: str, value: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        make_finding(**{field: value})

    assert exc_info.value.errors()[0]["loc"] == (field,)


@pytest.mark.parametrize("confidence", [0.0, 0.5, 1.0])
def test_confidence_accepts_inclusive_bounds(confidence: float) -> None:
    assert make_finding(confidence=confidence).confidence == confidence


@pytest.mark.parametrize("confidence", [-0.01, 1.01, -1.0, 2.0])
def test_confidence_outside_bounds_rejected(confidence: float) -> None:
    with pytest.raises(ValidationError):
        make_finding(confidence=confidence)


@pytest.mark.parametrize("confidence", ["high", None])
def test_non_numeric_confidence_rejected(confidence: object) -> None:
    with pytest.raises(ValidationError):
        make_finding(confidence=confidence)


@pytest.mark.parametrize("field", ["status", "confidence", "evidence"])
def test_required_fields_have_no_defaults(field: str) -> None:
    payload = finding_payload()
    payload.pop(field)

    with pytest.raises(ValidationError) as exc_info:
        Finding.model_validate(payload)

    assert exc_info.value.errors()[0]["loc"] == (field,)


def test_finding_serialization_uses_plain_values() -> None:
    finding = make_finding(
        status="confirmed",
        affected_component="app/search.py:42",
        remediation="Use parameterized queries.",
    )

    dumped = finding.model_dump(mode="json")

    assert dumped["severity"] == "high"
    assert dumped["status"] == "confirmed"
    assert dumped["evidence"][0]["source"] == "static-analysis"
    assert dumped["evidence"][0]["details"] == {"rule_id": "sql-injection"}

    json_payload = json.loads(finding.model_dump_json())
    assert json_payload == dumped
    assert Finding.model_validate(json_payload) == finding


def test_optional_fields_serialize_as_null() -> None:
    dumped = json.loads(make_finding().model_dump_json())

    assert dumped["affected_component"] is None
    assert dumped["remediation"] is None
