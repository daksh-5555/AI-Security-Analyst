"""Runtime XSS/SQLi probes against vulnerable and safe fixtures (M6, ADR-0009)."""

from __future__ import annotations

import json
import re

import httpx
import pytest
from crawl_fixtures import lab_client
from probe_fixtures import ProbeHandler, probe_site

from app.core.config import settings
from app.schemas.enums import FindingStatus
from app.schemas.tooling import ToolStatus
from app.services.analysis_execution_context import AnalysisExecutionContext
from app.services.analysis_tools import runtime_findings_from_result
from app.services.crawler import CrawlerTool
from app.services.runtime_probes import PROBE_STAGE, RuntimeProbeTool
from app.services.runtime_probes.tool import reflection_context
from app.services.tooling import StageRegistry, ToolContext, run_stages

URL = "/api/v1/assessments"
INERT = re.compile(
    r"^(1|aisa[0-9a-f]{10}|aisa[0-9a-f]{10}\"'<aisa[0-9a-f]{6}>|"
    r"1 AND (\d)=\d|1' AND '\d'='\d|1')$"
)


def probe_run(port: int, **overrides: object):  # noqa: ANN201
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(settings, "crawler_respect_robots", False)
        for name, value in overrides.items():
            patch.setattr(settings, name, value)
        registry = StageRegistry()
        registry.register("web_crawl", CrawlerTool(), order=100)
        registry.register(PROBE_STAGE, RuntimeProbeTool(), order=200)
        context = ToolContext(
            execution=AnalysisExecutionContext(120),
            web_target_url=f"http://127.0.0.1:{port}/",
            http_client=lab_client(),
        )
        outcome = run_stages(registry, context)
    return outcome.result_for(PROBE_STAGE)


def verdicts(result) -> dict[tuple[str, str, str], str]:  # noqa: ANN001
    return {
        (r.provenance.rule_id, r.location.url_path.split("?")[0], r.location.parameter): r.metadata[
            "verdict"
        ]
        for r in result.evidence
    }


@pytest.fixture(scope="module")
def probed():  # noqa: ANN201
    with probe_site() as port:
        result = probe_run(port)
        log = list(ProbeHandler.log)
    return result, log


def test_vulnerable_endpoints_are_classified_by_the_proof_rules(probed) -> None:  # noqa: ANN001
    result, _log = probed
    found = verdicts(result)
    assert found[("runtime.sqli_boolean", "/items", "id")] == "confirmed"
    assert found[("runtime.xss_reflection", "/search", "q")] == "potential"
    assert found[("runtime.xss_reflection", "/attr", "q")] == "potential"
    assert found[("runtime.xss_reflection", "/script", "q")] == "potential"
    assert found[("runtime.xss_reflection", "/flaky", "q")] == "inconclusive"
    assert found[("runtime.sqli_error_signal", "/items-errors", "id")] == "potential"


def test_safe_endpoints_produce_no_findings(probed) -> None:  # noqa: ANN001
    result, _log = probed
    paths = {path for _rule, path, _param in verdicts(result)}
    for safe in ("/items-safe", "/search-safe", "/attr-safe", "/find", "/noisy"):
        assert safe not in paths
    assert result.counts["xss_reflected_encoded"] >= 3
    assert result.counts["sqli_unstable_baseline"] == 1  # /noisy
    assert "unstable_baseline" in {item.code for item in result.limitations}
    assert result.status is ToolStatus.PARTIAL


def test_reflection_or_errors_alone_are_never_confirmed(probed) -> None:  # noqa: ANN001
    result, _log = probed
    for record in result.evidence:
        if record.provenance.rule_id != "runtime.sqli_boolean":
            assert record.metadata["verdict"] != "confirmed"
    findings = runtime_findings_from_result(result)
    xss = [f for f in findings if f.category == "xss"]
    assert xss and all(
        f.status in {FindingStatus.POTENTIAL, FindingStatus.INCONCLUSIVE} for f in xss
    )
    sqli = {f.title: f for f in findings if f.category == "sqli"}
    confirmed = [f for f in sqli.values() if f.status is FindingStatus.CONFIRMED]
    assert len(confirmed) == 1 and "'id' at /items" in confirmed[0].title
    assert confirmed[0].severity.value == "high"


def test_only_inert_get_probes_are_sent(probed) -> None:  # noqa: ANN001
    _result, log = probed
    assert {method for method, _path, _params in log} == {"GET"}
    assert "/delete" not in {path for _method, path, _params in log}
    assert "/comment" not in {path for _method, path, _params in log}
    for _method, path, params in log:
        if path == "/profile":
            assert params.get("token") == "abc"  # crawled, never probed (sensitive name)
        for name, value in params.items():
            if name in {"id", "q", "term"} and value not in {"a"}:
                assert INERT.match(value), f"unexpected probe value {value!r}"
            assert not re.search(r"(?i)\b(or|union|sleep|benchmark|waitfor)\b|;|--", value)


def test_get_forms_are_probed_but_post_forms_are_not(probed) -> None:  # noqa: ANN001
    result, log = probed
    find_values = [params.get("term") for _m, path, params in log if path == "/find"]
    assert find_values and all(INERT.match(value) for value in find_values)
    assert all(
        "csrf" not in params or params["csrf"] == "1" for _m, path, params in log if path == "/find"
    )
    assert "post_forms_not_probed" in {item.code for item in result.limitations}


def test_evidence_contains_no_response_bodies(probed) -> None:  # noqa: ANN001
    result, _log = probed
    dumped = result.model_dump_json()
    assert "apple" not in dumped and "Results for" not in dumped
    record = next(r for r in result.evidence if r.provenance.rule_id == "runtime.sqli_boolean")
    assert record.request_summary == {
        "method": "GET",
        "parameter": "id",
        "probe": "AND true/false pairs",
    }
    assert set(record.response_summary) == {"status", "length"}
    assert record.metadata["observations"][0]["true_similarity"] >= 0.98


def test_request_and_parameter_budgets() -> None:
    with probe_site() as port:
        limited = probe_run(port, runtime_probe_max_requests=5)
        assert limited.counts["probe_requests"] == 5
        assert "truncated.max_requests" in {item.code for item in limited.limitations}
        few = probe_run(port, runtime_probe_max_parameters=2)
        assert few.counts["skipped_parameter_budget"] >= 1
        assert "truncated.max_parameters" in {item.code for item in few.limitations}


def test_tool_is_skipped_without_a_crawl() -> None:
    context = ToolContext(
        execution=AnalysisExecutionContext(10),
        web_target_url="http://127.0.0.1:9/",
        http_client=lab_client(),
    )
    assert RuntimeProbeTool().applies_to(context) is False


@pytest.mark.parametrize(
    ("body", "context"),
    [
        ("<p>MARK</p>", "html_text"),
        ('<input value="MARK">', "attribute"),
        ("<script>var a='MARK'</script>", "script"),
        ("<!-- MARK -->", "comment"),
        ("<p>nothing</p>", "none"),
    ],
)
def test_reflection_context(body: str, context: str) -> None:
    assert reflection_context(body, "MARK") == context


# --- analysis-run integration -----------------------------------------------------


@pytest.mark.anyio
@pytest.mark.usefixtures("assessment_client")
async def test_web_run_with_probes_persists_findings(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "web_target_allowed_hosts", ["127.0.0.1"])
    monkeypatch.setattr(settings, "web_target_allowed_local_networks", ["127.0.0.0/8"])
    monkeypatch.setattr(settings, "web_target_max_requests_per_second", 50.0)
    monkeypatch.setattr(settings, "crawler_respect_robots", False)
    monkeypatch.setattr(settings, "runtime_probes_enabled", True)
    with probe_site() as port:
        assessment_id = (await client.post(URL, json={"assessment_type": "web_security"})).json()[
            "id"
        ]
        await client.post(
            f"{URL}/{assessment_id}/web-target",
            json={
                "base_url": f"http://127.0.0.1:{port}/",
                "authorization_statement": "Local deliberately vulnerable lab owned by the test.",
                "confirm_authorized": True,
            },
        )
        run = (await client.post(f"{URL}/{assessment_id}/analysis-runs")).json()
    findings = (await client.get(f"{URL}/{assessment_id}/findings")).json()

    tools = {tool["stage"]: tool for tool in run["analysis_metadata"]["tools"]}
    assert tools["runtime_probes"]["status"] in {"completed", "partial"}
    by_category = {}
    for item in findings:
        by_category.setdefault(item["category"], []).append(item)
    assert [f["status"] for f in by_category["sqli"] if f["status"] == "confirmed"] == ["confirmed"]
    assert {f["status"] for f in by_category["xss"]} <= {"potential", "inconclusive"}
    assert run["findings_count"] == len(findings)
    assert "apple" not in json.dumps(findings)


def test_probes_are_off_by_default_and_rate_is_bounded() -> None:
    from app.core.config import Settings

    defaults = Settings(_env_file=None, app_env="test")
    assert defaults.runtime_probes_enabled is False
    assert defaults.web_target_max_requests_per_second == 2.0
    from app.services.analysis_tools import web_tool_pipeline_config

    assert web_tool_pipeline_config().enabled_stages == frozenset({"web_crawl"})
