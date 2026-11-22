"""Load, validate, chunk, and version the curated knowledge base (M11).

Sources are local files only: the built-in project guidance shipped in
``app/knowledge`` and, optionally, an operator directory (``RAG_CORPUS_DIR``)
in the same format, for example OWASP or CWE material the operator has
licensed and reviewed. Nothing is fetched from the network.

Every document must declare its source type, version, update date, review
interval, license, and https references. A document that contains anything
that looks like a secret or personal data is rejected, never indexed.

The corpus version is the manifest version plus a SHA-256 over the canonical
chunk list, so the same files always produce the same version and index.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator

from app.services.explanations.redaction import contains_sensitive

BUILTIN_DIR: Final = Path(__file__).resolve().parents[2] / "knowledge"
SOURCE_TYPES: Final = frozenset({"project_guidance", "owasp", "cwe", "advisory"})
_ID: Final = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")
MAX_DOCUMENT_CHARS: Final = 50_000


class KnowledgeBaseError(RuntimeError):
    """The corpus is missing or invalid; retrieval is unavailable."""


class Reference(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str = Field(min_length=1, max_length=200)
    url: HttpUrl

    @field_validator("url")
    @classmethod
    def _https(cls, value: HttpUrl) -> HttpUrl:
        if value.scheme != "https":
            raise ValueError("references must use https")
        return value


class DocumentMeta(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    file: str
    title: str = Field(min_length=1, max_length=200)
    version: str = Field(min_length=1, max_length=40)
    updated_at: date
    review_interval_days: int = Field(ge=1, le=3650)
    source_type: str
    license: str = Field(min_length=3, max_length=300)
    categories: list[str] = Field(min_length=1)
    cwe_ids: list[str] = Field(default_factory=list)
    references: list[Reference] = Field(min_length=1)

    @field_validator("id")
    @classmethod
    def _id(cls, value: str) -> str:
        if not _ID.fullmatch(value):
            raise ValueError("document id must be lowercase letters, digits, and dashes")
        return value

    @field_validator("source_type")
    @classmethod
    def _source_type(cls, value: str) -> str:
        if value not in SOURCE_TYPES:
            raise ValueError(f"source_type must be one of {sorted(SOURCE_TYPES)}")
        return value

    @field_validator("cwe_ids")
    @classmethod
    def _cwe(cls, value: list[str]) -> list[str]:
        for item in value:
            if not re.fullmatch(r"CWE-\d{1,5}", item):
                raise ValueError("cwe_ids must look like CWE-89")
        return value

    @field_validator("file")
    @classmethod
    def _relative(cls, value: str) -> str:
        path = Path(value)
        if path.is_absolute() or ".." in path.parts or path.suffix != ".md":
            raise ValueError("file must be a relative .md path inside the corpus directory")
        return value

    def is_stale(self, today: date) -> bool:
        return today > self.updated_at + timedelta(days=self.review_interval_days)


class Manifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    knowledge_base: str = Field(min_length=1, max_length=100)
    version: str = Field(min_length=1, max_length=40)
    documents: list[DocumentMeta]


@dataclass(frozen=True)
class Chunk:
    id: str  # kb:<document id>#<n>
    document_id: str
    section: str
    text: str


@dataclass(frozen=True)
class Corpus:
    name: str
    manifest_version: str
    content_hash: str
    documents: dict[str, DocumentMeta]
    chunks: tuple[Chunk, ...]

    @property
    def version(self) -> str:
        return f"{self.name}@{self.manifest_version}+{self.content_hash[:16]}"


def chunk_markdown(document_id: str, text: str, max_chars: int) -> list[Chunk]:
    """Split on ``##`` sections, then on paragraphs, keeping each chunk bounded."""
    chunks: list[Chunk] = []
    title = ""
    sections: list[tuple[str, list[str]]] = []
    for line in text.splitlines():
        if line.startswith("# ") and not title:
            title = line[2:].strip()
        elif line.startswith("## "):
            sections.append((line[3:].strip(), []))
        elif sections:
            sections[-1][1].append(line)
        elif line.strip():
            sections.append(("Overview", [line]))
    for section, lines in sections:
        paragraphs = [p.strip() for p in "\n".join(lines).split("\n\n") if p.strip()]
        current = ""
        for paragraph in paragraphs:
            while len(paragraph) > max_chars:  # hard split very long paragraphs
                cut = paragraph.rfind(" ", 0, max_chars)
                cut = cut if cut > max_chars // 2 else max_chars
                pieces = paragraph[:cut].strip()
                if current:
                    chunks.append(_chunk(document_id, len(chunks), section, current))
                    current = ""
                chunks.append(_chunk(document_id, len(chunks), section, pieces))
                paragraph = paragraph[cut:].strip()
            if current and len(current) + 2 + len(paragraph) > max_chars:
                chunks.append(_chunk(document_id, len(chunks), section, current))
                current = ""
            current = f"{current}\n\n{paragraph}" if current else paragraph
        if current:
            chunks.append(_chunk(document_id, len(chunks), section, current))
    return chunks


def _chunk(document_id: str, index: int, section: str, text: str) -> Chunk:
    return Chunk(
        id=f"kb:{document_id}#{index}", document_id=document_id, section=section, text=text
    )


def _load_dir(directory: Path, max_chars: int) -> tuple[Manifest, list[Chunk]]:
    manifest_path = directory / "manifest.json"
    try:
        manifest = Manifest.model_validate(json.loads(manifest_path.read_text(encoding="utf-8")))
    except (OSError, ValueError) as exc:
        raise KnowledgeBaseError(f"invalid knowledge manifest in {directory.name}") from exc
    base = directory.resolve()
    chunks: list[Chunk] = []
    for meta in manifest.documents:
        path = (directory / meta.file).resolve()
        if base not in path.parents:
            raise KnowledgeBaseError(f"document {meta.id} is outside its corpus directory")
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise KnowledgeBaseError(f"document {meta.id} could not be read") from exc
        if len(text) > MAX_DOCUMENT_CHARS:
            raise KnowledgeBaseError(f"document {meta.id} is too large")
        if contains_sensitive(text):
            raise KnowledgeBaseError(f"document {meta.id} contains secret-like or personal data")
        chunks.extend(chunk_markdown(meta.id, text, max_chars))
    return manifest, chunks


def load_corpus(extra_dir: Path | None, *, max_chunk_chars: int) -> Corpus:
    manifest, chunks = _load_dir(BUILTIN_DIR, max_chunk_chars)
    documents = {meta.id: meta for meta in manifest.documents}
    version = manifest.version
    if extra_dir is not None:
        extra, extra_chunks = _load_dir(extra_dir, max_chunk_chars)
        for meta in extra.documents:
            if meta.id in documents:
                raise KnowledgeBaseError(f"duplicate document id {meta.id}")
            documents[meta.id] = meta
        chunks.extend(extra_chunks)
        version = f"{version}+{extra.knowledge_base}@{extra.version}"
    if len(documents) != len({d for d in documents}):  # pragma: no cover - defensive
        raise KnowledgeBaseError("duplicate document ids")
    canonical = json.dumps(
        {
            "documents": [documents[key].model_dump(mode="json") for key in sorted(documents)],
            "chunks": [[c.id, c.section, c.text] for c in chunks],
        },
        sort_keys=True,
        ensure_ascii=False,
    )
    return Corpus(
        name=manifest.knowledge_base,
        manifest_version=version,
        content_hash=hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        documents=documents,
        chunks=tuple(chunks),
    )


def document_summary(meta: DocumentMeta, today: date, chunk_count: int) -> dict[str, Any]:
    return {
        **meta.model_dump(mode="json", exclude={"file"}),
        "stale": meta.is_stale(today),
        "chunk_count": chunk_count,
    }
