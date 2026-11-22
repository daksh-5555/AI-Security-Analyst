"""Bounded HTML extraction for the crawler (standard-library ``html.parser``).

Extracts only what the crawler needs: the title, link targets, form structure,
``<base href>``, and meta refresh targets. Input *values* are never kept (hidden
fields often carry CSRF tokens or session data); only names, types, and whether
a field is required. All collections are capped so a hostile page cannot exhaust
memory.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Final

MAX_LINKS: Final[int] = 500
MAX_FORMS: Final[int] = 50
MAX_FIELDS: Final[int] = 100
MAX_TITLE: Final[int] = 200
_CONTROL: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]+")
_REFRESH: Final[re.Pattern[str]] = re.compile(r"url\s*=\s*['\"]?([^'\"]+)", re.IGNORECASE)
_FIELD_TAGS: Final[frozenset[str]] = frozenset({"input", "select", "textarea", "button"})


def clean_text(value: str, limit: int) -> str:
    text = " ".join(_CONTROL.sub(" ", value).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


@dataclass
class FormField:
    name: str
    type: str
    required: bool


@dataclass
class ParsedForm:
    action: str | None
    method: str
    enctype: str | None
    fields: list[FormField] = field(default_factory=list)


@dataclass
class ParsedPage:
    title: str | None = None
    base_href: str | None = None
    links: list[str] = field(default_factory=list)
    forms: list[ParsedForm] = field(default_factory=list)
    refresh: str | None = None
    truncated: bool = False


class _Extractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.page = ParsedPage()
        self._form: ParsedForm | None = None
        self._in_title = False
        self._title_parts: list[str] = []

    def _link(self, value: str | None) -> None:
        if not value:
            return
        if len(self.page.links) >= MAX_LINKS:
            self.page.truncated = True
            return
        self.page.links.append(value.strip())

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {name.lower(): value for name, value in attrs}
        if tag == "title":
            self._in_title = True
        elif tag == "base" and self.page.base_href is None:
            self.page.base_href = attributes.get("href")
        elif tag in {"a", "area"}:
            self._link(attributes.get("href"))
        elif tag in {"iframe", "frame"}:
            self._link(attributes.get("src"))
        elif tag == "meta" and (attributes.get("http-equiv") or "").lower() == "refresh":
            match = _REFRESH.search(attributes.get("content") or "")
            if match:
                self.page.refresh = match.group(1).strip()
        elif tag == "form":
            if len(self.page.forms) >= MAX_FORMS:
                self.page.truncated = True
                self._form = None
                return
            self._form = ParsedForm(
                action=attributes.get("action"),
                method=(attributes.get("method") or "get").strip().upper() or "GET",
                enctype=(attributes.get("enctype") or None),
            )
            self.page.forms.append(self._form)
        elif tag in _FIELD_TAGS and self._form is not None:
            name = (attributes.get("name") or "").strip()
            if not name:
                return
            if len(self._form.fields) >= MAX_FIELDS:
                self.page.truncated = True
                return
            kind = (attributes.get("type") or ("text" if tag == "input" else tag)).lower()
            self._form.fields.append(
                FormField(
                    name=clean_text(name, 100),
                    type=clean_text(kind, 30),
                    required="required" in attributes,
                )
            )

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        elif tag == "form":
            self._form = None

    def handle_data(self, data: str) -> None:
        if self._in_title and sum(map(len, self._title_parts)) < MAX_TITLE * 2:
            self._title_parts.append(data)


def parse_html(text: str) -> ParsedPage:
    extractor = _Extractor()
    try:
        extractor.feed(text)
        extractor.close()
    except (AssertionError, ValueError):  # malformed markup: keep what was parsed
        extractor.page.truncated = True
    page = extractor.page
    title = clean_text("".join(extractor._title_parts), MAX_TITLE)  # noqa: SLF001
    page.title = title or None
    return page


__all__ = ["FormField", "ParsedForm", "ParsedPage", "clean_text", "parse_html"]
