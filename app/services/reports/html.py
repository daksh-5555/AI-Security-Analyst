"""Self-contained, safely escaped HTML rendering of a report (M12, ADR-0015).

Autoescaping without a template engine: every value passed to ``h`` is
HTML-escaped (quotes included) unless it is a ``Safe`` fragment produced by this
module's own builders. A raw string can therefore never reach the output
unescaped, whatever a finding title, path, or excerpt contains.

The document loads nothing remote. It has no scripts, and its only stylesheet
is pinned in the Content-Security-Policy by hash. Links are rendered only for
``https://`` URLs, with ``rel="noopener noreferrer"``.
"""

from __future__ import annotations

import base64
import hashlib
import html
from collections.abc import Iterable
from typing import Any, Final

from app.services.reports.builder import AI_LABEL


class Safe(str):
    """A fragment this module built from escaped parts."""


def h(value: Any) -> Safe:
    if isinstance(value, Safe):
        return value
    if value is None:
        return Safe("")
    return Safe(html.escape(str(value), quote=True))


def join(parts: Iterable[Any]) -> Safe:
    return Safe("".join(h(part) for part in parts))


def tag(name: str, *children: Any, **attrs: Any) -> Safe:
    attributes = "".join(
        f' {key.rstrip("_").replace("_", "-")}="{h(value)}"'
        for key, value in attrs.items()
        if value is not None
    )
    return Safe(f"<{name}{attributes}>{join(children)}</{name}>")


def link(url: Any, label: Any) -> Safe:
    text = str(url or "")
    if not text.startswith("https://"):
        return h(label)
    return tag("a", label, href=text, rel="noopener noreferrer")


STYLE: Final = """
body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;margin:0 auto;max-width:960px;
padding:24px 16px;color:#1b1f24;background:#fff;line-height:1.5}
h1{font-size:1.6rem;margin:0 0 4px}h2{font-size:1.2rem;margin:28px 0 8px;
border-bottom:1px solid #d0d7de;padding-bottom:4px}h3{font-size:1.05rem;margin:0 0 6px}
table{border-collapse:collapse;width:100%;margin:8px 0;font-size:.9rem}
th,td{border:1px solid #d0d7de;padding:4px 8px;text-align:left;vertical-align:top}
th{background:#f6f8fa}code,pre{font-family:ui-monospace,Menlo,monospace;font-size:.85rem}
pre{background:#f6f8fa;padding:8px;white-space:pre-wrap;word-break:break-word}
.meta{color:#57606a;font-size:.85rem}.warn{background:#fff8c5;border:1px solid #d4a72c;
padding:8px 12px}.finding{border:1px solid #d0d7de;padding:12px;margin:12px 0}
.badge{display:inline-block;border:1px solid #57606a;border-radius:4px;padding:0 6px;
margin-right:6px;font-size:.8rem}.ai{border-left:4px solid #8250df;background:#fbefff;
padding:8px 12px;margin-top:8px}
""".strip()
_STYLE_HASH: Final = base64.b64encode(hashlib.sha256(STYLE.encode("utf-8")).digest()).decode()
CONTENT_SECURITY_POLICY: Final = (
    f"default-src 'none'; style-src 'sha256-{_STYLE_HASH}'; img-src 'none'; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)
_META_CSP: Final = CONTENT_SECURITY_POLICY.replace("; frame-ancestors 'none'", "")


def _table(headers: list[str], rows: Iterable[Iterable[Any]]) -> Safe:
    head = tag("tr", *(tag("th", header) for header in headers))
    body = join(tag("tr", *(tag("td", cell) for cell in row)) for row in rows)
    return tag("table", tag("thead", head), tag("tbody", body))


def _kv(pairs: Iterable[tuple[str, Any]]) -> Safe:
    return tag(
        "table",
        tag("tbody", *(tag("tr", tag("th", k), tag("td", v)) for k, v in pairs)),
    )


def _list(items: Iterable[Any]) -> Safe:
    rendered = [tag("li", item) for item in items]
    return tag("ul", *rendered) if rendered else h("None.")


def _evidence(items: list[dict[str, Any]], omitted: int) -> Safe:
    rows = []
    for item in items:
        location = item.get("location_path") or item.get("url_path") or ""
        if item.get("location_line"):
            location = f"{location}:{item['location_line']}"
        detail = join(
            [
                h(item.get("summary")),
                tag("pre", item["redacted_excerpt"]) if item.get("redacted_excerpt") else "",
            ]
        )
        rows.append(
            [tag("code", item.get("id")), item.get("tool"), item.get("method"), location, detail]
        )
    table = _table(["Evidence ID", "Tool", "Method", "Location", "Observation"], rows)
    note = tag("p", f"{omitted} more evidence item(s) not shown.", class_="meta") if omitted else ""
    return join([table, note])


def _ai(explanation: dict[str, Any] | None) -> Safe:
    if not explanation:
        return h("")
    sources = [
        join(
            [
                tag("code", source.get("id")),
                " ",
                source.get("title"),
                " (",
                source.get("license"),
                ") ",
                join(
                    link(ref.get("url"), ref.get("label")) for ref in source.get("references", [])
                ),
            ]
        )
        for source in explanation.get("sources", [])
    ]
    return tag(
        "div",
        tag("p", tag("strong", AI_LABEL)),
        tag(
            "p",
            f"{explanation.get('provider')} / {explanation.get('model')}, "
            f"template {explanation.get('prompt_template_version')}, "
            f"{explanation.get('created_at')}",
            class_="meta",
        ),
        tag("p", explanation.get("summary")),
        tag("p", explanation.get("technical_explanation")),
        tag("p", tag("strong", "Impact: "), explanation.get("impact")),
        tag("p", tag("strong", "Remediation")),
        _list(explanation.get("remediation_steps", [])),
        tag("p", tag("strong", "Validation and retest")),
        _list(explanation.get("validation_guidance", [])),
        tag("p", tag("strong", "Uncertainty: "), explanation.get("uncertainty")),
        tag(
            "p",
            "Cited evidence: ",
            join(tag("code", ref, " ") for ref in explanation.get("evidence_references", [])),
            class_="meta",
        ),
        tag("p", tag("strong", "Guidance sources")) if sources else "",
        _list(sources) if sources else "",
        class_="ai",
    )


def _finding(item: dict[str, Any]) -> Safe:
    badges = join(
        tag("span", text, class_="badge")
        for text in (item["severity"], item["status"], f"confidence {item['confidence']:.2f}")
    )
    details = _kv(
        [
            ("Finding ID", tag("code", item["id"])),
            ("Category", item.get("category")),
            ("Rule", item.get("rule_id")),
            ("Source stage", item.get("source_stage")),
            ("Affected component", item.get("affected_component")),
            ("Verification method", item.get("verification_method")),
            ("Why this status", item.get("status_rationale")),
            ("CWE", ", ".join(item.get("cwe_ids") or []) or None),
            ("CVE", ", ".join(item.get("cve_ids") or []) or None),
            ("First / last seen", f"{item.get('first_seen_at')} / {item.get('last_seen_at')}"),
            ("Previous status", item.get("previous_status")),
        ]
    )
    remediation = (
        join([tag("p", tag("strong", "Recommended remediation")), tag("p", item["remediation"])])
        if item.get("remediation")
        else h("")
    )
    return tag(
        "article",
        tag("h3", item.get("title")),
        tag("p", badges),
        tag("p", item.get("summary")),
        details,
        remediation,
        tag("p", tag("strong", "Evidence")),
        _evidence(item.get("evidence", []), item.get("evidence_omitted", 0)),
        _ai(item.get("ai_explanation")),
        class_="finding",
    )


def render_html(report: dict[str, Any]) -> str:
    run = report.get("run") or {}
    target = report.get("target") or {}
    counts = report["counts"]
    incomplete = bool(report["checks_not_run"]) or run.get("status") not in (None, "completed")
    sections = [
        tag("h1", "Security assessment report"),
        tag(
            "p",
            f"Generated {report['generated_at']} by {report['generator']['name']} "
            f"{report['generator']['version']}. Report schema {report['schema_version']}, "
            f"content hash {report['content_hash'][:16]}.",
            class_="meta",
        ),
        tag(
            "p",
            "Results are incomplete: some checks did not run or did not finish. See "
            "“Checks not run”.",
            class_="warn",
        )
        if incomplete
        else "",
        tag("h2", "Assessment"),
        _kv(
            [
                ("Assessment ID", tag("code", report["assessment"]["id"])),
                ("Type", report["assessment"]["type"]),
                ("Target", target.get("display")),
                ("Target type", target.get("type")),
                (
                    "Authorization",
                    f"{target.get('authorization_status')} "
                    f"({target.get('authorization_basis')}) {target.get('authorized_at') or ''}",
                ),
                ("Analysis run", tag("code", run.get("id")) if run else "none"),
                ("Run status", run.get("status")),
                ("Run started / completed", f"{run.get('started_at')} / {run.get('completed_at')}"),
                ("Run error", run.get("error_message")),
            ]
        ),
        tag("h2", "Executive summary"),
        _list(report["executive_summary"]),
        tag("h2", "Finding counts"),
        _table(["Severity", "Count"], counts["by_severity"].items()),
        _table(["Status", "Count"], counts["by_status"].items()),
        tag("h2", "Checks not run or incomplete"),
        _table(
            ["Check", "Status", "Reason"],
            ((c["stage"], c["status"], c.get("error_code")) for c in report["checks_not_run"]),
        )
        if report["checks_not_run"]
        else tag("p", "None. All configured checks completed."),
        tag("h2", "Scope and tools"),
        _table(
            ["Stage", "Tool", "Version", "Rule set", "Status"],
            (
                (
                    t["stage"],
                    t.get("tool"),
                    t.get("version"),
                    t.get("rule_set_version"),
                    t["status"],
                )
                for t in report["scope"]["tools"]
            ),
        ),
        _scope_workflow(report["scope"].get("workflow")),
        tag("h2", f"Findings ({counts['total']})"),
        join(_finding(item) for item in report["findings"]) or tag("p", "No findings recorded."),
        tag("p", f"{report['findings_omitted']} more finding(s) omitted.", class_="warn")
        if report["findings_omitted"]
        else "",
        tag("h2", "Dependency advisories"),
        _table(
            ["Advisory", "Package", "Version", "CVE", "Finding"],
            (
                (
                    link(a.get("reference"), a.get("advisory_id")),
                    a.get("package"),
                    a.get("version"),
                    ", ".join(a.get("cve_ids") or []),
                    tag("code", a["finding_id"]),
                )
                for a in report["advisories"]
            ),
        )
        if report["advisories"]
        else tag("p", "None."),
        tag("h2", "Limitations"),
        _list(report["limitations"]),
    ]
    body = join(sections)
    return (
        '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
        f'<meta http-equiv="Content-Security-Policy" content="{h(_META_CSP)}">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta name="referrer" content="no-referrer">'
        f"<title>{h('Security assessment report ' + report['assessment']['id'])}</title>"
        f"<style>{STYLE}</style></head><body>{body}</body></html>\n"
    )


def _scope_workflow(workflow: dict[str, Any] | None) -> Safe:
    if not workflow:
        return tag(
            "p",
            "This run was not started by a workflow, so no check plan was recorded.",
            class_="meta",
        )
    return join(
        [
            tag("p", tag("strong", f"Workflow plan ({workflow.get('graph_version')})")),
            _table(
                ["Check", "Risk", "Decision", "Reason", "Approval"],
                (
                    (
                        c.get("check"),
                        c.get("risk"),
                        c.get("decision"),
                        c.get("reason"),
                        (workflow.get("approvals") or {}).get(c.get("check"), {}).get("decision"),
                    )
                    for c in workflow.get("checks", [])
                ),
            ),
        ]
    )


__all__ = ["CONTENT_SECURITY_POLICY", "Safe", "h", "render_html", "tag"]
