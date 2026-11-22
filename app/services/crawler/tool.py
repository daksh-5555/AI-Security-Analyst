"""Safe, bounded crawler for authorized web targets (M5, ADR-0008).

Starts at the authorized target's base URL and follows same-origin links inside
its base path, breadth-first and deterministically. Every request goes through
the ``GuardedHttpClient`` bound to the target (``ToolContext.http_client``), so
host allowlisting, address vetting, redirect revalidation, and size, time, and
rate limits are enforced there.

The crawler only sends GET requests. It never submits forms, never follows links
whose path or query suggests a state-changing action, never guesses credentials,
and records parameter *names* only (no query values, form values, cookies, or
bodies).
"""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Final
from urllib.parse import urljoin, urlsplit
from urllib.robotparser import RobotFileParser

from app.core.config import settings
from app.schemas.tooling import (
    EvidenceLocation,
    EvidenceProvenance,
    EvidenceRecord,
    EvidenceSourceType,
    SafeErrorCode,
    ToolIdentity,
    ToolLimitation,
    ToolResult,
    ToolStatus,
)
from app.services.crawler.html import ParsedPage, clean_text, parse_html
from app.services.crawler.scope import (
    canonical_url,
    classify_form,
    evidence_path,
    in_scope,
    is_destructive,
    is_login_path,
    parameter_names,
    resolve_link,
    template_key,
)
from app.services.net import EgressError, GuardedHttpClient, GuardedResponse
from app.services.target_authorization import canonicalize_web_target
from app.services.tooling.protocol import ToolContext
from app.services.tooling.redaction import content_hash, evidence_key

CRAWL_STAGE: Final[str] = "web_crawl"
TOOL_VERSION: Final[str] = "1.0.0"
ROBOTS_AGENT: Final[str] = "AI-Security-Analyst"
_HTML_TYPES: Final[frozenset[str]] = frozenset({"text/html", "application/xhtml+xml"})
MAX_FORMS_RECORDED: Final[int] = 200


@dataclass
class _CrawlState:
    pages: int = 0
    errors: Counter[str] = field(default_factory=Counter)
    skipped: Counter[str] = field(default_factory=Counter)
    truncation: list[str] = field(default_factory=list)
    parse_truncated: int = 0
    forms_recorded: int = 0
    records: dict[str, EvidenceRecord] = field(default_factory=dict)


class CrawlerTool:
    """Breadth-first crawler over one authorized web target."""

    def __init__(self) -> None:
        self._identity = ToolIdentity(
            name="web_crawler", version=TOOL_VERSION, rule_set_version="crawl-policy-1"
        )

    @property
    def identity(self) -> ToolIdentity:
        return self._identity

    def applies_to(self, context: ToolContext) -> bool:
        return context.web_target_url is not None and context.http_client is not None

    def run(self, context: ToolContext) -> ToolResult:
        if context.web_target_url is None or context.http_client is None:
            raise ValueError("an authorized web target and its client are required")
        client: GuardedHttpClient = context.http_client
        target = canonicalize_web_target(context.web_target_url)
        start_url = canonical_url(target.url) or target.url
        started_at = context.clock()
        requests_before = client.requests_made
        excluded = list(settings.crawler_excluded_paths)
        state = _CrawlState()
        robots = (
            self._robots(client, target.origin, context)
            if settings.crawler_respect_robots
            else None
        )

        queue: deque[tuple[str, int]] = deque([(start_url, 0)])
        seen: set[str] = {start_url}
        variants: Counter[str] = Counter()

        while queue:
            context.execution.check()
            if state.pages >= settings.crawler_max_pages:
                state.truncation.append("max_pages")
                break
            if client.requests_made - requests_before >= settings.crawler_max_requests:
                state.truncation.append("max_requests")
                break
            url, depth = queue.popleft()
            if robots is not None and not robots.can_fetch(ROBOTS_AGENT, url):
                state.skipped["robots_disallowed"] += 1
                continue
            key = template_key(url)
            if variants[key] >= settings.crawler_max_variants_per_path:
                state.skipped["variant_limit"] += 1
                continue
            variants[key] += 1

            try:
                response = client.request("GET", url, execution=context.execution)
            except EgressError as exc:
                state.errors[exc.code.value] += 1
                continue
            state.pages += 1
            final_url = canonical_url(response.final_url) or url
            page = self._record_page(state, url, final_url, depth, response, context)
            if page is None or not in_scope(final_url, target, excluded):
                if page is not None:
                    state.skipped["redirected_out_of_scope"] += 1
                continue
            if depth >= settings.crawler_max_depth:
                if page.links:
                    state.skipped["depth_limit"] += 1
                continue
            base = (
                page.base_href
                if page.base_href
                and urlsplit(urljoin(final_url, page.base_href)).netloc
                == urlsplit(final_url).netloc
                else None
            )
            base_url = urljoin(final_url, base) if base else final_url
            candidates = list(page.links)
            if page.refresh:
                candidates.append(page.refresh)
            for href in candidates:
                link = resolve_link(base_url, href)
                if link is None or link in seen:
                    continue
                seen.add(link)
                if not in_scope(link, target, excluded):
                    state.skipped["out_of_scope"] += 1
                    continue
                if is_destructive(link):
                    state.skipped["unsafe_link"] += 1
                    continue
                queue.append((link, depth + 1))

        return self._result(state, context, started_at, client.requests_made - requests_before)

    # -- robots -----------------------------------------------------------------

    def _robots(
        self, client: GuardedHttpClient, origin: str, context: ToolContext
    ) -> RobotFileParser | None:
        parser = RobotFileParser()
        try:
            response = client.request("GET", f"{origin}/robots.txt", execution=context.execution)
        except EgressError:
            return None  # unavailable robots.txt imposes no extra restriction
        if response.status >= 400 or response.content_type != "text/plain":
            return None
        parser.parse(response.body.decode("utf-8", errors="replace").splitlines()[:2000])
        return parser

    # -- recording --------------------------------------------------------------

    def _location(self, url: str) -> EvidenceLocation:
        return EvidenceLocation(url_path=evidence_path(url).replace("@", "%40"))

    def _add(
        self,
        state: _CrawlState,
        rule_id: str,
        url: str,
        summary: str,
        metadata: dict[str, Any],
        observed_at: datetime,
        discriminator: str = "",
    ) -> None:
        location = self._location(url)
        digest = content_hash(f"{rule_id}|{location.url_path}|{discriminator}")
        key = evidence_key(self._identity.name, rule_id, location, digest)
        if key in state.records:
            return
        state.records[key] = EvidenceRecord(
            evidence_key=key,
            source_type=EvidenceSourceType.CRAWLER,
            provenance=EvidenceProvenance(
                tool=self._identity,
                rule_id=rule_id,
                observed_at=observed_at,
                method="same-origin GET crawl (no form submission)",
            ),
            location=location,
            summary=summary[:1000],
            content_hash=digest,
            metadata=metadata,
        )

    def _record_page(
        self,
        state: _CrawlState,
        url: str,
        final_url: str,
        depth: int,
        response: GuardedResponse,
        context: ToolContext,
    ) -> ParsedPage | None:
        observed_at = context.clock()
        is_html = response.content_type in _HTML_TYPES
        page = parse_html(response.body.decode("utf-8", errors="replace")) if is_html else None
        if page is not None and page.truncated:
            state.parse_truncated += 1
        self._add(
            state,
            "crawler.page",
            final_url,
            f"HTTP {response.status} {response.content_type or 'unknown'} at depth {depth}",
            {
                "status": response.status,
                "content_type": response.content_type or None,
                "depth": depth,
                "title": page.title if page else None,
                "parameters": parameter_names(final_url),
                "redirects": len(response.redirect_chain),
                "link_count": len(page.links) if page else 0,
                "form_count": len(page.forms) if page else 0,
            },
            observed_at,
        )
        signals: list[str] = []
        if response.status in {401, 403}:
            signals.append(f"http_{response.status}")
        if "www-authenticate" in response.headers:
            signals.append("www_authenticate")
        if response.redirect_chain and is_login_path(final_url) and not is_login_path(url):
            signals.append("redirect_to_login")
        if page is not None:
            for index, form in enumerate(page.forms):
                action = resolve_link(final_url, form.action) if form.action else final_url
                classification = classify_form(form, action)
                if classification in {"login", "credential"}:
                    signals.append("login_form")
                if state.forms_recorded >= MAX_FORMS_RECORDED:
                    state.truncation.append("max_forms_recorded")
                    continue
                state.forms_recorded += 1
                same_origin = (
                    action is not None and urlsplit(action).netloc == urlsplit(final_url).netloc
                )
                self._add(
                    state,
                    "crawler.form",
                    final_url,
                    f"{form.method} form ({classification}) with {len(form.fields)} field(s)",
                    {
                        "method": form.method,
                        "action": evidence_path(action) if action and same_origin else None,
                        "action_same_origin": same_origin,
                        "enctype": clean_text(form.enctype, 60) if form.enctype else None,
                        "classification": classification,
                        "fields": [
                            {"name": f.name, "type": f.type, "required": f.required}
                            for f in form.fields
                        ],
                        "submitted": False,
                    },
                    observed_at,
                    discriminator=f"{index}|{form.method}|{form.action}",
                )
        for signal in dict.fromkeys(signals):
            self._add(
                state,
                "crawler.auth_boundary",
                final_url,
                f"Authentication boundary signal: {signal}",
                {"signal": signal, "status": response.status},
                observed_at,
                discriminator=signal,
            )
        return page

    def _result(
        self, state: _CrawlState, context: ToolContext, started_at: datetime, requests: int
    ) -> ToolResult:
        limitations: list[ToolLimitation] = []
        for reason in sorted(set(state.truncation)):
            limitations.append(
                ToolLimitation(
                    code=f"truncated.{reason}", detail=f"Crawl stopped early ({reason})."
                )
            )
        for code, count in sorted(state.errors.items()):
            limitations.append(
                ToolLimitation(
                    code=f"request_failed.{code}", detail=f"{count} request(s) failed ({code})."
                )
            )
        for reason, count in sorted(state.skipped.items()):
            limitations.append(
                ToolLimitation(
                    code=f"skipped.{reason}", detail=f"{count} URL(s) not requested ({reason})."
                )
            )
        if state.parse_truncated:
            limitations.append(
                ToolLimitation(
                    code="parse_truncated",
                    detail=f"{state.parse_truncated} page(s) exceeded HTML extraction limits.",
                )
            )
        counts = {
            "pages_fetched": state.pages,
            "requests_made": requests,
            "forms_recorded": state.forms_recorded,
            "evidence_records": len(state.records),
            "request_errors": sum(state.errors.values()),
            **{f"skipped_{reason}": count for reason, count in sorted(state.skipped.items())},
        }
        finished_at = context.clock()
        if state.pages == 0:
            policy = any(code in {"blocked_address", "host_not_allowed"} for code in state.errors)
            return ToolResult(
                tool=self._identity,
                stage=CRAWL_STAGE,
                status=ToolStatus.FAILED,
                started_at=started_at,
                finished_at=finished_at,
                error_code=SafeErrorCode.POLICY_DENIED if policy else SafeErrorCode.UNAVAILABLE,
                counts=counts,
                limitations=limitations,
            )
        # Robots and unsafe/out-of-scope links are policy exclusions; budget stops,
        # request failures, and parse truncation are coverage gaps.
        partial = bool(
            state.truncation
            or state.errors
            or state.parse_truncated
            or state.skipped.get("depth_limit")
            or state.skipped.get("variant_limit")
        )
        return ToolResult(
            tool=self._identity,
            stage=CRAWL_STAGE,
            status=ToolStatus.PARTIAL if partial else ToolStatus.COMPLETED,
            started_at=started_at,
            finished_at=finished_at,
            counts=counts,
            evidence=[state.records[key] for key in sorted(state.records)],
            limitations=limitations,
        )


__all__ = ["CRAWL_STAGE", "CrawlerTool"]
