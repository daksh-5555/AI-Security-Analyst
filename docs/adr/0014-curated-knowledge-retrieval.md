# ADR-0014: Curated, local knowledge retrieval for explanations

Status: accepted (M11). Date: 2026-11-17.

## Context

Phase 11 asks for remediation context from a curated, versioned knowledge base:
- approved sources only, with license and provenance;
- chunking, embeddings, FAISS if suitable, and filtering by category, CWE, and
  freshness;
- cited source IDs, with retrieved text treated as untrusted;
- graceful fallback, and RAG that can be disabled without affecting scanning.

Three constraints shaped the decision:

- **No new downloads without owner approval.** FAISS, numpy, and any embedding
  SDK are not installed. Anthropic provides no embeddings endpoint, so a remote
  embedding provider would be another new vendor and a new data flow.
- **Licensing.** OWASP cheat sheets are CC BY-SA 4.0, and CWE has its own terms
  of use. Copying their text into this repository would bring share-alike and
  attribution obligations that the owner should decide on. Copying it by hand
  would also be indiscriminate ingestion.
- **Size.** The corpus that matters is small: one guidance document per finding
  category the tools produce.

## Decision

1. **Built-in corpus: original, project-maintained guidance.** This is one of
   the blueprint's approved source types.
   - Ten documents live in `app/knowledge/` (manifest plus Markdown) and ship as
     package data: SQL injection, XSS, hardcoded secrets, vulnerable
     dependencies, command injection, path traversal and uploads, deserialization,
     code injection, archive extraction, and verification/retest.
   - Each carries its version, update date, review interval, license, the
     categories and CWE IDs it covers, and https references to the relevant
     OWASP and CWE pages, by URL only, with no copied text.
2. **Operator corpus.** `RAG_CORPUS_DIR` adds a directory in the same format,
   for example OWASP or CWE material the operator has licensed and reviewed.
   Loading it runs the same validation:
   - source type must be one of `project_guidance`, `owasp`, `cwe`, or
     `advisory`;
   - a license is required, and references must be https;
   - paths must stay inside the directory, documents are size-bounded, and
     document IDs must be unique;
   - **a document containing anything secret-like or personal is rejected and
     not indexed.**

   Nothing is fetched from the network.
3. **Reproducible versioning.** The corpus version is
   `name@manifest_version(+operator@version)+sha256(canonical chunks)[:16]`.
   The same files give the same version. Each explanation stores the version and
   the attributed source IDs it was given.
4. **Retrieval, dependency-free.**
   - Sections are chunked on `##` headings and paragraphs, bounded by
     `RAG_MAX_CHUNK_CHARS`.
   - The `lexical` backend (BM25 with light stemming) is the default.
   - The `vector` backend uses cosine similarity over a deterministic local
     hashing embedder, through an `EmbeddingProvider` interface that a remote
     provider can implement later.
   - Filtering: stale documents (past their review interval) are excluded
     unless `RAG_INCLUDE_STALE`, in which case they are labelled. Documents
     matching the finding's category or CWE rank first; general guidance comes
     after. If nothing matches, the whole corpus is searched and the result is
     marked `filtered: false`. Results are capped at `RAG_MAX_CHUNKS`.
   - An embedding failure falls back to lexical retrieval and records
     `fallback_reason`. An invalid corpus yields "no reference material". In
     neither case is the explanation blocked.
5. **Grounding and injection safety.**
   - Retrieved chunks go into the prompt in their own `<reference_material>`
     block: escaped JSON, labelled untrusted by the versioned system policy
     (`finding-explanation/2`).
   - `source_references` must be a subset of the supplied `kb:` IDs
     (`ungrounded_sources` otherwise). When references were supplied, at least
     one must be cited (`uncited_sources`).
   - `kb:` IDs may support remediation claims but may not stand in for finding
     evidence (`evidence_references` must stay finding or evidence IDs).
6. **No effect on findings.** Retrieval reads only guidance. Its output is used
   only in advisory explanations. Scanning, finding status, severity, and
   confidence never depend on it. `RAG_ENABLED=false` removes the reference
   block, and explanations and scanning keep working.
7. **API.** `GET /api/v1/knowledge` returns the version, hash, and per-document
   source, license, freshness, and chunk count. `GET /api/v1/knowledge/search`
   returns attributed chunks for a query, filtered by category or CWE.

## Consequences

- No new dependency. Everything runs offline and is tested.
- Pure-Python retrieval is right for hundreds of chunks. A FAISS backend, or a
  real embedding model, is an optional later change behind the same interface,
  and needs owner approval for the dependency and, for remote embeddings, the
  data flow.
- The built-in guidance is only as good as its review. Each document has a
  review interval, and stale documents drop out of retrieval by default, so the
  owner should review and re-date them.
- Bringing in OWASP or CWE text is the operator's decision, made in their own
  corpus directory, where its license is recorded.
