"""Bounded, non-destructive runtime XSS and SQL injection probes (M6, ADR-0009).

Scope and safety:

- Only GET parameters found by the crawl (``prior_results["web_crawl"]``) are
  probed: query parameters of crawled pages and fields of same-origin GET forms.
  POST forms are never submitted. Parameters with sensitive names (tokens,
  passwords, sessions) and endpoints that look state-changing are skipped.
- Every request goes through the target-bound ``GuardedHttpClient``. Request and
  parameter budgets apply, along with cancellation and the run deadline.
- Payloads are inert: XSS probes use a random alphanumeric marker plus
  ``"'<aisaNNNNNN>`` (an unknown tag with no attributes or script). SQL probes use
  only ``AND`` predicates (true/false pairs). There is no ``OR``, ``UNION``,
  stacked queries, comments, time delays, or data extraction.

Proof rules (ADR-0003):

- XSS: reflection without encoding of the special characters is ``potential``
  (``inconclusive`` if it does not reproduce). Executable XSS would require a
  browser harness, which is not implemented, so XSS is never ``confirmed``.
  Encoded reflection is recorded as a count, not a finding.
- SQLi: ``confirmed`` only when the baseline is stable and two independent boolean
  pairs each give true ≈ baseline and false ≠ baseline, with the false responses
  matching each other. A single differential pair that does not repeat is
  ``inconclusive``. A database error message that appears only after a quote is a
  ``potential`` signal. Status or length changes alone never decide anything.
"""

from __future__ import annotations

import difflib
import html
import re
import secrets
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Final
from urllib.parse import parse_qsl, quote, urlencode, urlsplit

from app.core.config import settings
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
from app.services.crawler import CRAWL_STAGE
from app.services.crawler.scope import in_scope, is_destructive
from app.services.net import EgressError, GuardedHttpClient, GuardedResponse
from app.services.target_authorization import CanonicalWebTarget, canonicalize_web_target
from app.services.tooling.protocol import ToolContext
from app.services.tooling.redaction import content_hash, evidence_key, is_sensitive_name

PROBE_STAGE: Final[str] = "runtime_probes"
TOOL_VERSION: Final[str] = "1.0.0"
XSS_RULE: Final[str] = "runtime.xss_reflection"
SQLI_RULE: Final[str] = "runtime.sqli_boolean"
SQLI_ERROR_RULE: Final[str] = "runtime.sqli_error_signal"
SAME: Final[float] = 0.98
DIFFERENT: Final[float] = 0.90
_SKIPPED_FIELD_TYPES: Final[frozenset[str]] = frozenset(
    {"hidden", "submit", "button", "reset", "password", "file", "image"}
)
_SQL_ERRORS: Final[re.Pattern[str]] = re.compile(
    r"(SQL syntax|syntax error|unrecognized token|unclosed quotation|unterminated quoted string|"
    r"quoted string not properly terminated|ORA-\d{5}|SQLSTATE|sqlite3?\.\w*Error|"
    r"near \".*\": syntax error|mysql_fetch|pg_query|ODBC|PDOException)",
    re.IGNORECASE,
)
_SQL_CONTEXTS: Final[tuple[tuple[str, str, str], ...]] = (
    ("numeric", "1 AND {a}={a}", "1 AND {a}={b}"),
    ("string", "1' AND '{a}'='{a}", "1' AND '{a}'='{b}"),
)


class ProbeBudgetExhausted(RuntimeError):
    """Raised internally when the request budget is spent."""


@dataclass(frozen=True, slots=True)
class Candidate:
    path: str
    parameter: str
    other_parameters: tuple[str, ...]
    source: str  # "query" or "get_form"


@dataclass
class _State:
    requests: int = 0
    skipped: Counter[str] = field(default_factory=Counter)
    outcomes: Counter[str] = field(default_factory=Counter)
    errors: Counter[str] = field(default_factory=Counter)
    truncated: list[str] = field(default_factory=list)
    records: dict[str, EvidenceRecord] = field(default_factory=dict)


def _split(url_path: str) -> tuple[str, list[str]]:
    parts = urlsplit(url_path)
    return parts.path or "/", sorted(
        {name for name, _ in parse_qsl(parts.query, keep_blank_values=True)}
    )


def collect_candidates(crawl: ToolResult | None) -> tuple[list[Candidate], Counter[str]]:
    """GET parameters worth probing, deterministic order, with skip reasons."""
    skipped: Counter[str] = Counter()
    found: dict[tuple[str, str], Candidate] = {}
    if crawl is None:
        return [], skipped
    for record in crawl.evidence:
        rule = record.provenance.rule_id
        meta = record.metadata
        if rule == "crawler.page" and record.location.url_path:
            path, names = _split(record.location.url_path)
            entries = [(name, names, "query") for name in names]
        elif rule == "crawler.form":
            if meta.get("method") != "GET" or not meta.get("action"):
                skipped["post_or_external_form"] += 1
                continue
            path, _ = _split(str(meta["action"]))
            fields = [
                f for f in meta.get("fields") or [] if f.get("type") not in _SKIPPED_FIELD_TYPES
            ]
            names = sorted({str(f["name"]) for f in fields})
            entries = [(name, names, "get_form") for name in names]
        else:
            continue
        for name, all_names, source in entries:
            if is_sensitive_name(name):
                skipped["sensitive_parameter"] += 1
                continue
            if is_destructive(f"http://x{path}?{name}="):
                skipped["unsafe_endpoint"] += 1
                continue
            others = tuple(other for other in all_names if other != name)
            found.setdefault((path, name), Candidate(path, name, others, source))
    return [found[key] for key in sorted(found)], skipped


def _normalize(body: bytes, probe: str) -> list[str]:
    text = body.decode("utf-8", errors="replace")
    for variant in {probe, html.escape(probe), html.escape(probe, quote=False), quote(probe)}:
        if variant:
            text = text.replace(variant, "")
    return [" ".join(line.split()) for line in text.splitlines()[:2000] if line.strip()]


def similarity(
    a: GuardedResponse, b: GuardedResponse, probe_a: str = "", probe_b: str = ""
) -> float:
    if a.status != b.status:
        return 0.0
    left, right = _normalize(a.body, probe_a), _normalize(b.body, probe_b)
    if left == right:
        return 1.0
    return difflib.SequenceMatcher(None, left, right, autojunk=False).ratio()


def reflection_context(body: str, marker: str) -> str:
    index = body.find(marker)
    if index < 0:
        return "none"
    before = body[:index].lower()
    if before.rfind("<script") > before.rfind("</script"):
        return "script"
    if before.rfind("<!--") > before.rfind("-->"):
        return "comment"
    if before.rfind("<") > before.rfind(">"):
        return "attribute"
    return "html_text"


class RuntimeProbeTool:
    """XSS reflection and boolean SQLi probes on crawled GET parameters."""

    def __init__(self, *, marker_factory: Any = None) -> None:
        self._identity = ToolIdentity(
            name="runtime_prober", version=TOOL_VERSION, rule_set_version="probe-policy-1"
        )
        self._marker = marker_factory or (lambda: "aisa" + secrets.token_hex(5))

    @property
    def identity(self) -> ToolIdentity:
        return self._identity

    def applies_to(self, context: ToolContext) -> bool:
        crawl = context.prior_results.get(CRAWL_STAGE)
        return (
            context.web_target_url is not None
            and context.http_client is not None
            and crawl is not None
            and crawl.status in {ToolStatus.COMPLETED, ToolStatus.PARTIAL}
        )

    def run(self, context: ToolContext) -> ToolResult:
        if context.web_target_url is None or context.http_client is None:
            raise ValueError("an authorized web target and its client are required")
        started_at = context.clock()
        target = canonicalize_web_target(context.web_target_url)
        candidates, skipped = collect_candidates(context.prior_results.get(CRAWL_STAGE))
        state = _State(skipped=skipped)
        limit = settings.runtime_probe_max_parameters
        if len(candidates) > limit:
            state.skipped["parameter_budget"] += len(candidates) - limit
            state.truncated.append("max_parameters")
        for candidate in candidates[:limit]:
            context.execution.check()
            url = f"{target.origin}{candidate.path}"
            if not in_scope(url, target, list(settings.crawler_excluded_paths)):
                state.skipped["out_of_scope"] += 1
                continue
            try:
                self._probe_xss(context, target, candidate, state)
                self._probe_sqli(context, target, candidate, state)
            except ProbeBudgetExhausted:
                state.truncated.append("max_requests")
                break
        return self._result(state, started_at, context.clock(), len(candidates))

    # -- transport --------------------------------------------------------------

    def _get(
        self,
        context: ToolContext,
        target: CanonicalWebTarget,
        candidate: Candidate,
        value: str,
        state: _State,
    ) -> GuardedResponse | None:
        if state.requests >= settings.runtime_probe_max_requests:
            raise ProbeBudgetExhausted
        context.execution.check()
        query = urlencode(
            sorted(
                [
                    (candidate.parameter, value),
                    *((name, "1") for name in candidate.other_parameters),
                ]
            )
        )
        state.requests += 1
        client: GuardedHttpClient = context.http_client  # type: ignore[assignment]
        try:
            return client.request(
                "GET", f"{target.origin}{candidate.path}?{query}", execution=context.execution
            )
        except EgressError as exc:
            state.errors[exc.code.value] += 1
            return None

    # -- XSS --------------------------------------------------------------------

    def _probe_xss(
        self, context: ToolContext, target: CanonicalWebTarget, candidate: Candidate, state: _State
    ) -> None:
        marker = self._marker()
        first = self._get(context, target, candidate, marker, state)
        if first is None or first.content_type not in {"text/html", "application/xhtml+xml"}:
            return
        body = first.body.decode("utf-8", errors="replace")
        if marker not in body:
            state.outcomes["xss_not_reflected"] += 1
            return
        reflection = reflection_context(body, marker)
        tag = f"aisa{marker[-6:]}"
        probe = f"{marker}\"'<{tag}>"
        second = self._get(context, target, candidate, probe, state)
        if second is None:
            self._xss_evidence(
                state,
                candidate,
                reflection,
                "inconclusive",
                False,
                context,
                first,
                "probe request failed",
            )
            return
        if not self._unencoded(second, marker, tag, reflection):
            state.outcomes["xss_reflected_encoded"] += 1
            return
        third = self._get(context, target, candidate, probe, state)
        reproduced = third is not None and self._unencoded(third, marker, tag, reflection)
        verdict = "potential" if reproduced else "inconclusive"
        self._xss_evidence(state, candidate, reflection, verdict, reproduced, context, second, None)

    @staticmethod
    def _unencoded(response: GuardedResponse, marker: str, tag: str, reflection: str) -> bool:
        body = response.body.decode("utf-8", errors="replace")
        if reflection in {"html_text", "comment"}:
            return f"<{tag}>" in body
        if reflection in {"attribute", "script"}:
            return f'{marker}"' in body or f"{marker}\"'" in body or f"{marker}'" in body
        return False

    def _xss_evidence(
        self,
        state: _State,
        candidate: Candidate,
        reflection: str,
        verdict: str,
        reproduced: bool,
        context: ToolContext,
        response: GuardedResponse,
        note: str | None,
    ) -> None:
        state.outcomes[f"xss_{verdict}"] += 1
        limitations = [
            "Executable script was not demonstrated (no browser harness); reflection without "
            "encoding is a signal, not proof of exploitable XSS.",
        ]
        if note:
            limitations.append(note)
        self._add(
            state,
            XSS_RULE,
            candidate,
            f"Input in '{candidate.parameter}' is reflected without HTML encoding "
            f"({reflection} context)",
            {
                "verdict": verdict,
                "reflection_context": reflection,
                "reproduced": reproduced,
                "probe": "inert marker with \" ' < > characters",
                "request_summary": {
                    "method": "GET",
                    "parameter": candidate.parameter,
                    "source": candidate.source,
                },
                "response_summary": {
                    "status": response.status,
                    "content_type": response.content_type,
                    "length": len(response.body),
                },
                "cwe_ids": ["CWE-79"],
            },
            context.clock(),
            limitations,
        )

    # -- SQLi -------------------------------------------------------------------

    def _probe_sqli(
        self, context: ToolContext, target: CanonicalWebTarget, candidate: Candidate, state: _State
    ) -> None:
        base1 = self._get(context, target, candidate, "1", state)
        base2 = self._get(context, target, candidate, "1", state)
        if base1 is None or base2 is None:
            return
        if similarity(base1, base2) < SAME:
            state.outcomes["sqli_unstable_baseline"] += 1
            return

        observations: list[dict[str, Any]] = []
        for name, true_template, false_template in _SQL_CONTEXTS:
            true_value = true_template.format(a=7)
            false_value = false_template.format(a=7, b=8)
            true_resp = self._get(context, target, candidate, true_value, state)
            false_resp = self._get(context, target, candidate, false_value, state)
            if true_resp is None or false_resp is None:
                continue
            t_sim = similarity(true_resp, base1, true_value, "1")
            f_sim = similarity(false_resp, base1, false_value, "1")
            observation = {
                "context": name,
                "true_similarity": round(t_sim, 3),
                "false_similarity": round(f_sim, 3),
            }
            observations.append(observation)
            if t_sim < SAME or f_sim > DIFFERENT:
                continue
            # Second, independent pair with different literals.
            true2 = true_template.format(a=3)
            false2 = false_template.format(a=3, b=4)
            true_resp2 = self._get(context, target, candidate, true2, state)
            false_resp2 = self._get(context, target, candidate, false2, state)
            confirmed = (
                true_resp2 is not None
                and false_resp2 is not None
                and similarity(true_resp2, base1, true2, "1") >= SAME
                and similarity(false_resp2, base1, false2, "1") <= DIFFERENT
                and similarity(false_resp2, false_resp, false2, false_value) >= 0.95
            )
            observation["repeated_pair_consistent"] = confirmed
            self._sqli_evidence(
                state,
                candidate,
                "confirmed" if confirmed else "inconclusive",
                name,
                observations,
                context,
                false_resp,
            )
            return

        quote_resp = self._get(context, target, candidate, "1'", state)
        if quote_resp is not None:
            quoted = quote_resp.body.decode("utf-8", errors="replace")
            baseline = base1.body.decode("utf-8", errors="replace")
            if _SQL_ERRORS.search(quoted) and not _SQL_ERRORS.search(baseline):
                state.outcomes["sqli_error_signal"] += 1
                self._add(
                    state,
                    SQLI_ERROR_RULE,
                    candidate,
                    f"A database error message appears when '{candidate.parameter}' "
                    "contains a quote",
                    {
                        "verdict": "potential",
                        "observations": observations,
                        "request_summary": {
                            "method": "GET",
                            "parameter": candidate.parameter,
                            "probe": "single quote",
                        },
                        "response_summary": {
                            "status": quote_resp.status,
                            "length": len(quote_resp.body),
                        },
                        "cwe_ids": ["CWE-89"],
                    },
                    context.clock(),
                    [
                        "An error message alone does not prove injection; the boolean "
                        "differential test did not confirm it."
                    ],
                )
                return
        state.outcomes["sqli_no_signal"] += 1

    def _sqli_evidence(
        self,
        state: _State,
        candidate: Candidate,
        verdict: str,
        sql_context: str,
        observations: list[dict[str, Any]],
        context: ToolContext,
        false_response: GuardedResponse,
    ) -> None:
        state.outcomes[f"sqli_{verdict}"] += 1
        limitations = ["Read-only boolean comparison; no data was extracted or modified."]
        if verdict != "confirmed":
            limitations.append("The differential did not repeat consistently with new literals.")
        self._add(
            state,
            SQLI_RULE,
            candidate,
            f"Boolean conditions in '{candidate.parameter}' change the response "
            f"({sql_context} context)",
            {
                "verdict": verdict,
                "sql_context": sql_context,
                "observations": observations,
                "thresholds": {"same": SAME, "different": DIFFERENT},
                "request_summary": {
                    "method": "GET",
                    "parameter": candidate.parameter,
                    "probe": "AND true/false pairs",
                },
                "response_summary": {
                    "status": false_response.status,
                    "length": len(false_response.body),
                },
                "cwe_ids": ["CWE-89"],
            },
            context.clock(),
            limitations,
        )

    # -- results ----------------------------------------------------------------

    def _add(
        self,
        state: _State,
        rule_id: str,
        candidate: Candidate,
        summary: str,
        metadata: dict[str, Any],
        observed_at: datetime,
        limitations: list[str],
    ) -> None:
        location = EvidenceLocation(
            url_path=quote(candidate.path, safe="/-._~!$&'()*+,;=:%")
            + f"?{quote(candidate.parameter, safe='')}=",
            parameter=candidate.parameter[:200],
        )
        digest = content_hash(f"{rule_id}|{candidate.path}|{candidate.parameter}")
        key = evidence_key(self._identity.name, rule_id, location, digest)
        state.records[key] = EvidenceRecord(
            evidence_key=key,
            source_type=EvidenceSourceType.RUNTIME_PROBE,
            provenance=EvidenceProvenance(
                tool=self._identity,
                rule_id=rule_id,
                observed_at=observed_at,
                method="bounded non-destructive GET probes (probe-policy-1)",
            ),
            location=location,
            summary=summary[:1000],
            content_hash=digest,
            request_summary=metadata.pop("request_summary", None),
            response_summary=metadata.pop("response_summary", None),
            limitations=limitations,
            metadata=metadata,
        )

    def _result(
        self, state: _State, started_at: datetime, finished_at: datetime, candidates: int
    ) -> ToolResult:
        limitations: list[ToolLimitation] = [
            ToolLimitation(
                code="post_forms_not_probed",
                detail="POST forms are never submitted; only GET parameters were probed.",
            )
        ]
        for reason in sorted(set(state.truncated)):
            limitations.append(
                ToolLimitation(
                    code=f"truncated.{reason}", detail=f"Probing stopped early ({reason})."
                )
            )
        for code, count in sorted(state.errors.items()):
            limitations.append(
                ToolLimitation(
                    code=f"request_failed.{code}",
                    detail=f"{count} probe request(s) failed ({code}).",
                )
            )
        for reason, count in sorted(state.skipped.items()):
            limitations.append(
                ToolLimitation(
                    code=f"skipped.{reason}", detail=f"{count} parameter(s) not probed ({reason})."
                )
            )
        if state.outcomes.get("sqli_unstable_baseline"):
            limitations.append(
                ToolLimitation(
                    code="unstable_baseline",
                    detail=(
                        f"{state.outcomes['sqli_unstable_baseline']} parameter(s) had unstable "
                        "responses; SQL injection was not tested on them."
                    ),
                )
            )
        counts = {
            "candidate_parameters": candidates,
            "probe_requests": state.requests,
            **{name: count for name, count in sorted(state.outcomes.items())},
            **{f"skipped_{reason}": count for reason, count in sorted(state.skipped.items())},
        }
        partial = bool(
            state.truncated or state.errors or state.outcomes.get("sqli_unstable_baseline")
        )
        return ToolResult(
            tool=self._identity,
            stage=PROBE_STAGE,
            status=ToolStatus.PARTIAL if partial else ToolStatus.COMPLETED,
            started_at=started_at,
            finished_at=finished_at,
            counts=counts,
            evidence=[state.records[key] for key in sorted(state.records)],
            limitations=limitations,
        )


__all__ = [
    "PROBE_STAGE",
    "RuntimeProbeTool",
    "collect_candidates",
    "reflection_context",
    "similarity",
]
