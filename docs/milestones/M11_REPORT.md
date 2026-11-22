# M11 — Curated, Local Knowledge Retrieval

Status: **complete, awaiting owner review before M12.**

## Key decisions (please review)

- **No FAISS, numpy, or embedding SDK.** None is installed, and adding them needs
  your approval. Anthropic has no embeddings endpoint, so remote embeddings would
  also mean a new vendor and a new data flow. Retrieval is pure Python: BM25
  by default, or cosine similarity over a deterministic local hashing embedder.
  For a curated corpus of a few hundred chunks that is enough. A FAISS or
  remote-embedding backend can be added behind the same `EmbeddingProvider`
  interface later.
- **No OWASP or CWE text copied in.** OWASP cheat sheets are CC BY-SA 4.0, and
  CWE has its own terms of use. Importing their text brings obligations that
  are your call. The built-in corpus is therefore ten **original,
  project-maintained guidance documents**, one of the blueprint's approved
  source types. Each references the relevant OWASP and CWE pages by URL only.
  If you license OWASP or CWE material, put it in `RAG_CORPUS_DIR`, where the
  same validation applies and its license is recorded.
- **`RAG_ENABLED` defaults to true.** Retrieval is local and only affects
  explanations, which are themselves off by default. Please review the
  guidance text in `app/knowledge/docs/`. Each document has a review interval
  and drops out of retrieval when it goes stale.

## What was added

| Area | Files |
| --- | --- |
| Corpus | `app/knowledge/manifest.json` and 10 Markdown documents (SQLi, XSS, hardcoded secrets, vulnerable dependencies, command injection, path traversal and uploads, deserialization, code injection, archive extraction, verification/retest); shipped as package data |
| Loader | `app/services/knowledge/corpus.py`: manifest validation (source type, license, https references, contained paths, size), secret and personal-data rejection, section- and paragraph-based chunking, content-addressed version |
| Indexes | `app/services/knowledge/index.py`: BM25 with light stemming; `HashingEmbedder`; `VectorIndex`; `EmbeddingProvider` interface |
| Retrieval | `app/services/knowledge/retrieval.py`: category/CWE filtering with specific-first ranking, stale handling, vector-to-lexical fallback, attribution, shared cached service |
| Explanations | `source_references` in the contract; `<reference_material>` block (escaped, untrusted) in prompt `finding-explanation/2`; validation (`ungrounded_sources`, `uncited_sources`; `kb:` IDs may not stand in for finding evidence); `retrieval` provenance stored per explanation |
| Migration | `0021_add_explanation_retrieval.py`: nullable `finding_explanations.retrieval` |
| API | `GET /api/v1/knowledge`, `GET /api/v1/knowledge/search` |
| Settings | `RAG_ENABLED`, `RAG_BACKEND`, `RAG_MAX_CHUNKS`, `RAG_MAX_CHUNK_CHARS`, `RAG_INCLUDE_STALE`, `RAG_CORPUS_DIR` |
| Tests | `tests/test_knowledge.py` (38), `tests/test_migration_0021.py` (2) |
| Docs | ADR-0014, README, technical reference, `.env.example` |

## Blueprint acceptance criteria and tests

| Requirement | Evidence |
| --- | --- |
| Explanations cite retrieved source IDs | Cited IDs must be a subset of the supplied ones and non-empty when any were supplied (`test_explanations_cite_retrieved_sources`, `test_source_citations_are_validated`: uncited, invented source, source used as evidence) |
| Retrieval never changes finding status | Findings compared before and after in every explanation test; retrieval has no write path |
| Reproducible, versioned knowledge base | Same files give the same hash; any change gives a new hash (`test_corpus_version_is_reproducible_and_content_addressed`); version and sources stored per explanation |
| RAG can be disabled without breaking scanning | `RAG_ENABLED=false`: scanning and explanations work, no reference block, API returns 404 (`test_rag_disabled_keeps_scanning_and_explanations_working`) |
| Chunking and metadata preservation | `test_chunking_preserves_sections_and_bounds`, `test_builtin_corpus_is_attributed_versioned_and_secret_free` |
| Retrieval relevance on a curated fixture | 10 category/CWE cases each retrieve the right document first (`test_retrieval_relevance_on_the_curated_corpus`) |
| Source attribution | License, version, and references on every result, in the API and in stored explanations |
| Stale documents | Excluded by default; included and labelled with `RAG_INCLUDE_STALE` (`test_stale_documents_are_excluded_or_labelled`) |
| Prompt injection in retrieved content | A poisoned operator document stays inside one escaped block, with no `<system>` tag and one closing tag (`test_injection_inside_retrieved_content_stays_data`) |
| Embedding or provider failure | A failing embedder falls back to lexical retrieval with `fallback_reason`; a broken corpus makes retrieval `unavailable` while the explanation still succeeds, and the API returns 503 (`test_vector_backend_and_fallback`, `test_broken_corpus_degrades_gracefully`) |
| No secrets in indexed documents | Every built-in chunk passes the detector; operator documents with a key or an e-mail address are rejected (`test_invalid_or_unsafe_documents_are_rejected`) |

## Existing tests changed (intended)

- `tests/test_explanations.py`: the fake provider now cites the supplied
  `kb:` IDs, as a correct provider must under the new contract; the expected
  prompt template version is `finding-explanation/2`.
- Head pins `0020` → `0021`; the 0020 "is head" test was renamed.

No assertion was weakened.

## Issues found and fixed while testing

- Lexical retrieval missed the secrets guidance (`secret` vs `secrets`). I
  added light stemming, plus a relevance bonus and specific-first ranking for
  documents whose category or CWE matches the finding.

## Verification

| Check | Result |
| --- | --- |
| `pytest` (full) | **1654 passed, 0 failed, 7 skipped** (Windows-only), no warnings |
| Coverage | 89% overall; knowledge API 100%, retrieval 99%, index 99%, corpus 94% |
| `ruff check` / `ruff format --check` | clean |
| Alembic | head `0021`; `alembic check` reports no drift; full downgrade and re-upgrade OK |
| OpenAPI | 2 new paths; `FindingExplanationOutput.source_references` and `FindingExplanationRead.retrieval` added (optional); ID length limit raised from 64 to 120 characters so `kb:` IDs fit; nothing removed |
| Dependencies | none added; `pyproject.toml` only gained package data for the corpus |

## Known gaps and risks

- The guidance was written by me and still needs review by you or a security
  reviewer. It is concise remediation advice, not a full reference.
- The hashing embedder captures word overlap, not meaning. Real semantic
  retrieval needs an embedding model (your decision).
- An invalid operator corpus disables retrieval entirely rather than skipping
  one document. This is deliberate (fail closed) and is reported by the API
  as 503.
- The Windows test suite has still not been run. D14 (Docker, PostgreSQL, DVWA)
  remains open.

## Next milestone

M12: JSON and HTML reports. Authorized, safe report generation. Per D13 that
means Jinja2 with autoescaping and a strict Content-Security-Policy, which is
a new dependency needing your approval. Alternatively, HTML generation can use
the standard library with explicit escaping.
