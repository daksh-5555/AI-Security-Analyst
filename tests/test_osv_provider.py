"""OSV provider behaviour: fetch, cache freshness, offline, and failures (M3)."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest
from osv_fixtures import FakeClock, FakeOsvHandler, fake_osv_server, make_provider

from app.services.dependencies.osv import AdvisoryCache, Freshness, PackageQuery
from app.services.dependencies.versions import Ecosystem

VULNERABLE = PackageQuery(Ecosystem.PYPI, "Demo_HTTP", "2.0.1")
CLEAN = PackageQuery(Ecosystem.PYPI, "demo-http", "2.0.3")
NPM = PackageQuery(Ecosystem.NPM, "demo-merge", "1.1.0")


def test_online_lookup_returns_matching_advisories() -> None:
    with fake_osv_server() as port:
        result = make_provider(port).lookup([VULNERABLE, CLEAN, NPM])

    vulnerable = result.packages[VULNERABLE]
    assert vulnerable.freshness is Freshness.FRESH
    advisory = vulnerable.advisories[0]
    assert advisory.id == "GHSA-test-0001"
    assert advisory.cve_ids == ("CVE-2099-0001",)
    assert advisory.severity == "HIGH"
    assert advisory.source_url == "https://osv.dev/vulnerability/GHSA-test-0001"
    assert len(advisory.affected) == 1
    assert result.packages[CLEAN].advisories == ()
    assert result.packages[CLEAN].freshness is Freshness.FRESH
    assert result.packages[NPM].advisories[0].severity == "MODERATE"


def test_untrusted_advisory_text_is_sanitized() -> None:
    with fake_osv_server() as port:
        advisory = make_provider(port).lookup([NPM]).packages[NPM].advisories[0]
    assert "\x07" not in advisory.summary
    assert len(advisory.summary) <= 300


def test_fresh_cache_avoids_network_and_expiry_labels_stale(tmp_path: Path) -> None:
    clock = FakeClock()
    cache = AdvisoryCache(tmp_path / "cache", ttl_seconds=3600, clock=clock)
    with fake_osv_server() as port:
        make_provider(port, cache=cache, clock=clock).lookup([VULNERABLE])
        FakeOsvHandler.requests.clear()
        again = make_provider(port, cache=cache, clock=clock).lookup([VULNERABLE])
        assert FakeOsvHandler.requests == []
        assert again.packages[VULNERABLE].freshness is Freshness.FRESH

    clock.now += timedelta(hours=2)
    offline = make_provider(None, mode="offline", cache=cache, clock=clock).lookup([VULNERABLE])
    package = offline.packages[VULNERABLE]
    assert package.freshness is Freshness.STALE
    assert package.advisories[0].freshness is Freshness.STALE


def test_file_cache_survives_a_new_process(tmp_path: Path) -> None:
    clock = FakeClock()
    with fake_osv_server() as port:
        make_provider(port, cache_dir=tmp_path / "c", clock=clock).lookup([VULNERABLE])
    fresh_cache = AdvisoryCache(tmp_path / "c", ttl_seconds=3600, clock=clock)
    result = make_provider(None, mode="offline", cache=fresh_cache, clock=clock).lookup(
        [VULNERABLE]
    )
    assert result.packages[VULNERABLE].advisories[0].id == "GHSA-test-0001"


def test_offline_without_cache_is_unavailable_not_clean() -> None:
    result = make_provider(None, mode="offline").lookup([VULNERABLE])
    package = result.packages[VULNERABLE]
    assert package.freshness is Freshness.UNAVAILABLE
    assert package.reason == "offline_not_cached"
    assert result.requests_made == 0


@pytest.mark.parametrize("mode", ["slow", "invalid", "rate_limited"])
def test_provider_failures_are_unavailable(mode: str) -> None:
    with fake_osv_server() as port:
        FakeOsvHandler.mode = mode
        result = make_provider(port, total_timeout=0.5).lookup([VULNERABLE])
    assert result.packages[VULNERABLE].freshness is Freshness.UNAVAILABLE
    assert result.packages[VULNERABLE].reason == "provider_unavailable"


def test_provider_outage_falls_back_to_stale_cache() -> None:
    clock = FakeClock()
    cache = AdvisoryCache(None, ttl_seconds=3600, clock=clock)
    with fake_osv_server() as port:
        make_provider(port, cache=cache, clock=clock).lookup([VULNERABLE])
        clock.now += timedelta(days=1)
        FakeOsvHandler.mode = "rate_limited"
        result = make_provider(port, cache=cache, clock=clock).lookup([VULNERABLE])
    assert result.packages[VULNERABLE].freshness is Freshness.STALE
    assert result.packages[VULNERABLE].advisories[0].id == "GHSA-test-0001"


def test_invalid_advisory_ids_are_never_requested() -> None:
    with fake_osv_server() as port:
        FakeOsvHandler.matches = {
            **FakeOsvHandler.matches,
            ("PyPI", "evil", "1.0"): ["../../admin", "GHSA-test-0001"],
        }
        make_provider(port).lookup([PackageQuery(Ecosystem.PYPI, "evil", "1.0")])
        assert not any("admin" in request for request in FakeOsvHandler.requests)


def test_online_mode_requires_a_guarded_client() -> None:
    from app.services.dependencies.osv import OsvAdvisoryProvider

    with pytest.raises(ValueError):
        OsvAdvisoryProvider(
            base_url="https://osv.test",
            cache=AdvisoryCache(None, ttl_seconds=60),
            mode="online",
            client=None,
        )
