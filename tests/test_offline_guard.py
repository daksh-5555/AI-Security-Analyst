"""The test suite itself must never reach the network (M3)."""

import socket

import pytest

from app.core.config import settings


def test_non_loopback_connections_are_blocked_in_tests() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(AssertionError, match="non-loopback"):
            sock.connect(("93.184.215.14", 443))
        with pytest.raises(AssertionError, match="non-loopback"):
            sock.connect_ex(("8.8.8.8", 53))
    finally:
        sock.close()


def test_dependency_audit_runs_offline_in_tests() -> None:
    assert settings.dependency_audit_mode == "offline"
