"""Target authorization and network safety policy interfaces (ADR-0004, proposed).

This module defines contracts only. It opens no connections and resolves no DNS.
The guarded HTTP client (M4) must call ``NetworkSafetyPolicy.is_address_permitted``
for every resolved address, before connecting and again after every redirect.

Defaults fail closed: the default authorization policy denies every target, and
loopback, private, link-local, metadata, and other special-purpose ranges are
blocked unless a deployment explicitly allowlists a local test network.
"""

from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final, Protocol, runtime_checkable

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class TargetKind(StrEnum):
    REPOSITORY = "repository"
    WEB_APPLICATION = "web_application"


class TargetDecisionReason(StrEnum):
    AUTHORIZED = "authorized"
    NOT_AUTHORIZED = "not_authorized"
    NOT_ALLOWLISTED = "not_allowlisted"
    AUTHORIZATION_EXPIRED = "authorization_expired"
    SCHEME_NOT_ALLOWED = "scheme_not_allowed"
    CREDENTIALS_IN_TARGET = "credentials_in_target"
    BLOCKED_ADDRESS = "blocked_address"
    INVALID_TARGET = "invalid_target"


@dataclass(frozen=True, slots=True)
class TargetRequest:
    """A request to assess one canonical target on behalf of a user."""

    kind: TargetKind
    canonical_target: str
    assessment_id: uuid.UUID
    requested_by: uuid.UUID


@dataclass(frozen=True, slots=True)
class TargetDecision:
    """Outcome of a target authorization check. Only ``AUTHORIZED`` allows."""

    allowed: bool
    reason: TargetDecisionReason

    def __post_init__(self) -> None:
        if self.allowed != (self.reason is TargetDecisionReason.AUTHORIZED):
            raise ValueError("allowed must be True exactly when reason is AUTHORIZED")

    @classmethod
    def allow(cls) -> TargetDecision:
        return cls(allowed=True, reason=TargetDecisionReason.AUTHORIZED)

    @classmethod
    def deny(cls, reason: TargetDecisionReason) -> TargetDecision:
        return cls(allowed=False, reason=reason)


@runtime_checkable
class TargetAuthorizationPolicy(Protocol):
    """Decides whether a target may be assessed. Implemented in M4."""

    def evaluate(self, request: TargetRequest) -> TargetDecision: ...


class DenyAllTargetPolicy:
    """Fail-closed default used until explicit target authorization exists."""

    def evaluate(self, request: TargetRequest) -> TargetDecision:
        return TargetDecision.deny(TargetDecisionReason.NOT_AUTHORIZED)


CLOUD_METADATA_ADDRESSES: Final[frozenset[IPAddress]] = frozenset(
    {
        ipaddress.ip_address("169.254.169.254"),
        ipaddress.ip_address("169.254.170.2"),
        ipaddress.ip_address("100.100.100.200"),
        ipaddress.ip_address("fd00:ec2::254"),
    }
)
DEFAULT_BLOCKED_NETWORKS: Final[tuple[IPNetwork, ...]] = tuple(
    ipaddress.ip_network(network)
    for network in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/128",
        "::1/128",
        "64:ff9b::/96",
        "100::/64",
        "2001:db8::/32",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    )
)


def _unwrap(address: IPAddress) -> IPAddress:
    """Map IPv4-mapped, IPv4-compatible, 6to4, and Teredo forms to the IPv4 address."""
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            return address.ipv4_mapped
        if address.sixtofour is not None:
            return address.sixtofour
        if address.teredo is not None:
            return address.teredo[1]
        packed = address.packed
        if packed[:12] == bytes(12) and packed[12:] != bytes(4):
            # Deprecated IPv4-compatible form ::a.b.c.d (but not :: or ::1).
            candidate = ipaddress.IPv4Address(packed[12:])
            if str(address) != "::1":
                return candidate
    return address


@dataclass(frozen=True, slots=True)
class NetworkSafetyPolicy:
    """Safe defaults for every runtime network tool (enforced by the M4 client)."""

    allowed_schemes: frozenset[str] = frozenset({"http", "https"})
    max_redirects: int = 5
    connect_timeout_seconds: float = 5.0
    read_timeout_seconds: float = 10.0
    total_timeout_seconds: float = 30.0
    max_response_bytes: int = 2 * 1024 * 1024
    max_decompression_ratio: int = 20
    allowed_content_types: frozenset[str] = frozenset(
        {"text/html", "application/xhtml+xml", "application/json", "text/plain"}
    )
    max_requests_per_second: float = 2.0
    max_concurrency_per_target: int = 2
    user_agent: str = "AI-Security-Analyst/0.1 (authorized security assessment)"
    blocked_networks: tuple[IPNetwork, ...] = DEFAULT_BLOCKED_NETWORKS
    allowed_local_networks: tuple[IPNetwork, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not self.allowed_schemes or not self.allowed_schemes <= {"http", "https"}:
            raise ValueError("allowed_schemes must be a non-empty subset of http/https")
        if not 0 <= self.max_redirects <= 10:
            raise ValueError("max_redirects must be between 0 and 10")
        for name in ("connect_timeout_seconds", "read_timeout_seconds", "total_timeout_seconds"):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")
        if self.total_timeout_seconds < max(
            self.connect_timeout_seconds, self.read_timeout_seconds
        ):
            raise ValueError("total timeout must cover the connect and read timeouts")
        if self.max_response_bytes <= 0 or self.max_decompression_ratio <= 0:
            raise ValueError("response limits must be positive")
        if self.max_requests_per_second <= 0 or self.max_concurrency_per_target <= 0:
            raise ValueError("rate and concurrency budgets must be positive")
        if not self.user_agent.strip():
            raise ValueError("user_agent must identify the scanner")
        for network in self.allowed_local_networks:
            if any(
                address in network for address in CLOUD_METADATA_ADDRESSES
            ) or network.prefixlen < (8 if network.version == 4 else 32):
                raise ValueError("allowed_local_networks must be narrow and exclude metadata")

    def is_address_permitted(self, address: str | IPAddress) -> bool:
        """Return True when a resolved destination address may be contacted."""
        try:
            parsed = ipaddress.ip_address(address) if isinstance(address, str) else address
        except ValueError:
            return False
        candidates = {parsed, _unwrap(parsed)}
        if any(candidate in CLOUD_METADATA_ADDRESSES for candidate in candidates):
            return False
        if any(
            candidate in network
            for candidate in candidates
            for network in self.allowed_local_networks
            if candidate.version == network.version
        ):
            return True
        for candidate in candidates:
            if any(
                candidate in network
                for network in self.blocked_networks
                if candidate.version == network.version
            ):
                return False
            if not candidate.is_global:
                return False
        return True


__all__ = [
    "CLOUD_METADATA_ADDRESSES",
    "DEFAULT_BLOCKED_NETWORKS",
    "DenyAllTargetPolicy",
    "NetworkSafetyPolicy",
    "TargetAuthorizationPolicy",
    "TargetDecision",
    "TargetDecisionReason",
    "TargetKind",
    "TargetRequest",
]
