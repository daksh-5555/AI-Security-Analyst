"""Safe crawler behaviour against a local fixture site (M5, ADR-0008)."""

from __future__ import annotations

import json

import pytest
from crawl_fixtures import CSRF_VALUE, SESSION_VALUE, SiteHandler, fixture_site, lab_client

from app.core.config import settings
from app.schemas.tooling import SafeErrorCode, ToolResult, ToolStatus
from app.services.analysis_execution_context import (
    AnalysisExecutionAbortedError,
    AnalysisExecutionContext,
)
from app.services.crawler import CrawlerTool
from app.services.crawler.html import parse_html
from app.services.crawler.scope import (
    canonical_url,
    classify_form,
    evidence_path,
    in_scope,
    is_destructive,
    resolve_link,
)
from app.services.target_authorization import canonicalize_web_target
from app.services.tooling import ToolContext


def crawl(port: int, path: str = "/", **overrides: object) -> ToolResult:
    with pytest.MonkeyPatch.context() as patch:
        for name, value in overrides.items():
            patch.setattr(settings, name, value)
        context = ToolContext(
            execution=AnalysisExecutionContext(60),
            web_target_url=f"http://127.0.0.1:{port}{path}",
            http_client=lab_client(),
        )
        return CrawlerTool().run(context)


def paths(result: ToolResult, rule: str) -> set[str]:
    return {r.location.url_path for r in result.evidence if r.provenance.rule_id == rule}


def requested() -> list[str]:
    return [path for _method, path in SiteHandler.log]


def test_crawl_inventories_pages_forms_and_parameters() -> None:
    with fixture_site() as port:
        result = crawl(port)

    pages = paths(result, "crawler.page")
    assert {"/", "/about", "/login", "/private", "/image.png", "/deep/1"} <= pages
    assert "/products?id=" in pages  # parameter names only, never values
    forms = [r for r in result.evidence if r.provenance.rule_id == "crawler.form"]
    by_class = {f.metadata["classification"]: f.metadata for f in forms}
    assert by_class["state_changing"]["method"] == "POST"
    assert by_class["state_changing"]["action"] == "/comment"
    assert {f["name"] for f in by_class["state_changing"]["fields"]} == {"csrf", "body"}
    assert by_class["search"]["method"] == "GET"
    assert by_class["login"]["fields"][1] == {
        "name": "password",
        "type": "password",
        "required": False,
    }
    assert all(f.metadata["submitted"] is False for f in forms)


def test_crawler_only_sends_get_and_never_submits_forms() -> None:
    with fixture_site() as port:
        crawl(port)
        methods = {method for method, _path in SiteHandler.log}
        log = requested()
    assert methods == {"GET"}
    assert "/comment" not in log and "/search" not in log


def test_destructive_excluded_robots_and_out_of_scope_urls_are_never_requested() -> None:
    with fixture_site() as port:
        result = crawl(port, crawler_excluded_paths=["/admin"])
        log = requested()
    for forbidden in ("/logout", "/delete?id=7", "/admin/panel", "/secret-area"):
        assert forbidden not in log
    assert result.counts["skipped_unsafe_link"] == 2
    assert result.counts["skipped_robots_disallowed"] == 1
    assert result.counts["skipped_out_of_scope"] >= 2  # other host and /admin


def test_robots_can_be_disabled_but_is_not_authorization() -> None:
    with fixture_site() as port:
        crawl(port, crawler_respect_robots=False)
        log = requested()
    assert "/secret-area" in log
    assert "/robots.txt" not in log


def test_redirects_inside_scope_are_followed_and_external_ones_refused() -> None:
    with fixture_site() as port:
        result = crawl(port)
    assert result.counts["request_errors"] >= 1
    assert "request_failed.host_not_allowed" in {item.code for item in result.limitations}
    assert result.status is ToolStatus.PARTIAL


def test_auth_boundaries_are_detected_without_guessing_credentials() -> None:
    with fixture_site() as port:
        result = crawl(port)
        log = requested()
    signals = {
        (r.location.url_path, r.metadata["signal"])
        for r in result.evidence
        if r.provenance.rule_id == "crawler.auth_boundary"
    }
    assert ("/private", "http_401") in signals
    assert ("/private", "www_authenticate") in signals
    assert ("/login", "login_form") in signals
    assert log.count("/login") == 1  # visited once, never submitted


def test_depth_page_request_and_variant_budgets() -> None:
    with fixture_site() as port:
        shallow = crawl(port, crawler_max_depth=1)
        assert "/deep/2" not in paths(shallow, "crawler.page")
        assert "skipped.depth_limit" in {item.code for item in shallow.limitations}

        few_pages = crawl(port, crawler_max_pages=3)
        assert few_pages.counts["pages_fetched"] == 3
        assert "truncated.max_pages" in {item.code for item in few_pages.limitations}

        few_requests = crawl(port, crawler_max_requests=2)
        assert few_requests.counts["requests_made"] <= 3
        assert "truncated.max_requests" in {item.code for item in few_requests.limitations}

        SiteHandler.log = []
        crawl(port)
        products = [path for path in requested() if path.startswith("/products")]
    assert len(products) == 3  # max_variants_per_path


def test_base_path_scope_is_enforced() -> None:
    site = {
        "/app/": (
            200,
            {},
            b'<a href="/app/a">a</a><a href="/application">x</a><a href="/other">o</a>',
        ),
        "/app/a": (200, {}, b"<title>A</title>"),
    }
    with fixture_site(site) as port:
        result = crawl(port, "/app/", crawler_respect_robots=False)
        log = requested()
    assert log == ["/app/", "/app/a"]
    assert paths(result, "crawler.page") == {"/app/", "/app/a"}


def test_no_secret_values_cookies_or_bodies_are_recorded() -> None:
    with fixture_site() as port:
        result = crawl(port)
    dumped = result.model_dump_json()
    assert CSRF_VALUE not in dumped
    assert SESSION_VALUE not in dumped
    assert "id=1" not in dumped and "id=2" not in dumped
    assert "\x07" not in dumped and "Home" in dumped  # titles sanitized


def test_results_are_repeatable() -> None:
    with fixture_site() as port:
        first = crawl(port)
        second = crawl(port)
    assert [r.evidence_key for r in first.evidence] == [r.evidence_key for r in second.evidence]
    assert first.counts == second.counts


def test_unreachable_target_fails_without_evidence() -> None:
    context = ToolContext(
        execution=AnalysisExecutionContext(10),
        web_target_url="http://127.0.0.1:9/",
        http_client=lab_client(),
    )
    result = CrawlerTool().run(context)
    assert result.status is ToolStatus.FAILED
    assert result.error_code is SafeErrorCode.UNAVAILABLE
    assert result.evidence == []


def test_cancellation_stops_the_crawl() -> None:
    with fixture_site() as port:
        execution = AnalysisExecutionContext(60)
        execution.request_abort()
        context = ToolContext(
            execution=execution,
            web_target_url=f"http://127.0.0.1:{port}/",
            http_client=lab_client(),
        )
        with pytest.raises(AnalysisExecutionAbortedError):
            CrawlerTool().run(context)
        assert requested() == [] or requested() == ["/robots.txt"]


def test_not_applicable_without_target_or_client() -> None:
    context = ToolContext(execution=AnalysisExecutionContext(10))
    assert CrawlerTool().applies_to(context) is False


# --- pure helpers -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("HTTP://Example.TEST:80/a/./b/../c?z=1&a=2#frag", "http://example.test/a/c?a=2&z=1"),
        ("https://example.test:443//x//y/", "https://example.test/x/y/"),
        ("http://user:pw@example.test/", None),
        ("ftp://example.test/", None),
    ],
)
def test_canonical_url(raw: str, expected: str | None) -> None:
    assert canonical_url(raw) == expected


def test_link_resolution_and_scope() -> None:
    base = "http://lab.test/app/page"
    assert resolve_link(base, "next") == "http://lab.test/app/next"
    assert resolve_link(base, "javascript:void(0)") is None
    assert resolve_link(base, "#x") is None
    target = canonicalize_web_target("http://lab.test/app/")
    assert in_scope("http://lab.test/app/x", target, [])
    assert not in_scope("http://lab.test/application", target, [])
    assert not in_scope("https://lab.test/app/x", target, [])
    assert not in_scope("http://lab.test:8080/app/x", target, [])
    assert not in_scope("http://lab.test/app/admin/x", target, ["/app/admin"])


@pytest.mark.parametrize(
    "url",
    [
        "http://x/logout",
        "http://x/user/delete?id=1",
        "http://x/cart?action=checkout",
        "http://x/setup.php",
        "http://x/upload",
    ],
)
def test_destructive_links(url: str) -> None:
    assert is_destructive(url)


def test_evidence_path_drops_values_and_html_limits() -> None:
    assert evidence_path("http://x/s?q=secret&page=2") == "/s?page=&q="
    page = parse_html("<a href='/x'>" * 600 + "<form><input name='a'>" * 60)
    assert len(page.links) == 500 and len(page.forms) == 50 and page.truncated
    form = parse_html("<form method=post><input type=file name=f></form>").forms[0]
    assert classify_form(form, "http://x/files") == "upload"
    json.dumps(page.links[:1])
