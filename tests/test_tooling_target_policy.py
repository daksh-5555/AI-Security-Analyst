"""Target authorization and network safety policy contract tests (M1, ADR-0004)."""

from __future__ import annotations

import ipaddress
import uuid

import pytest

from app.services.tooling.target_policy import (
    DenyAllTargetPolicy,
    NetworkSafetyPolicy,
    TargetAuthorizationPolicy,
    TargetDecision,
    TargetDecisionReason,
    TargetKind,
    TargetRequest,
)


def test_default_authorization_policy_fails_closed() -> None:
    policy = DenyAllTargetPolicy()
    assert isinstance(policy, TargetAuthorizationPolicy)
    decision = policy.evaluate(
        TargetRequest(
            kind=TargetKind.WEB_APPLICATION,
            canonical_target="http://127.0.0.1:8080/",
            assessment_id=uuid.uuid4(),
            requested_by=uuid.uuid4(),
        )
    )
    assert decision == TargetDecision.deny(TargetDecisionReason.NOT_AUTHORIZED)
    assert not decision.allowed


def test_decision_allowed_flag_must_match_reason() -> None:
    assert TargetDecision.allow().allowed
    with pytest.raises(ValueError):
        TargetDecision(allowed=True, reason=TargetDecisionReason.BLOCKED_ADDRESS)
    with pytest.raises(ValueError):
        TargetDecision(allowed=False, reason=TargetDecisionReason.AUTHORIZED)


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "127.10.0.5",
        "0.0.0.0",
        "10.0.0.1",
        "172.16.5.4",
        "192.168.1.1",
        "100.64.0.1",
        "169.254.169.254",
        "169.254.170.2",
        "100.100.100.200",
        "224.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "fe80::1",
        "fc00::1",
        "fd00:ec2::254",
        "::ffff:127.0.0.1",
        "::ffff:169.254.169.254",
        "::ffff:10.0.0.1",
        "::7f00:1",
        "2002:7f00:0001::",
        "64:ff9b::7f00:1",
        "not-an-ip",
        "",
    ],
)
def test_special_purpose_addresses_are_blocked_by_default(address: str) -> None:
    assert not NetworkSafetyPolicy().is_address_permitted(address)


@pytest.mark.parametrize("address", ["93.184.215.14", "8.8.8.8", "2606:4700:4700::1111"])
def test_public_addresses_are_permitted(address: str) -> None:
    assert NetworkSafetyPolicy().is_address_permitted(address)


def test_local_test_network_can_be_allowlisted_but_metadata_never() -> None:
    policy = NetworkSafetyPolicy(allowed_local_networks=(ipaddress.ip_network("127.0.0.0/8"),))
    assert policy.is_address_permitted("127.0.0.1")
    assert policy.is_address_permitted("::ffff:127.0.0.1")
    assert not policy.is_address_permitted("169.254.169.254")
    assert not policy.is_address_permitted("10.0.0.1")

    with pytest.raises(ValueError):
        NetworkSafetyPolicy(allowed_local_networks=(ipaddress.ip_network("169.254.0.0/16"),))
    with pytest.raises(ValueError):
        NetworkSafetyPolicy(allowed_local_networks=(ipaddress.ip_network("0.0.0.0/0"),))


@pytest.mark.parametrize(
    "overrides",
    [
        {"allowed_schemes": frozenset({"ftp"})},
        {"allowed_schemes": frozenset()},
        {"max_redirects": 11},
        {"connect_timeout_seconds": 0},
        {"total_timeout_seconds": 1, "read_timeout_seconds": 5},
        {"max_response_bytes": 0},
        {"max_requests_per_second": 0},
        {"user_agent": " "},
    ],
)
def test_unsafe_policy_values_are_rejected(overrides: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        NetworkSafetyPolicy(**overrides)


def test_defaults_are_conservative() -> None:
    policy = NetworkSafetyPolicy()
    assert policy.allowed_schemes == frozenset({"http", "https"})
    assert policy.max_redirects <= 5
    assert policy.max_response_bytes <= 2 * 1024 * 1024
    assert policy.allowed_local_networks == ()
    assert "authorized" in policy.user_agent
