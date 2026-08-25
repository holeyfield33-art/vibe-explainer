# Phase 8 — Context Coverage & Bounded Cross-File Resolution

Phase 8 makes the assessment *context-aware* and adds *bounded* AST-based structure
resolution. It was driven by three real-repository validation runs (see
`PHASE-8-VALIDATION.md`), each of which surfaced a distinct bug/gap class that
fixture-only testing would not have.

## Design stance

- **AST for structure, not for taint.** Python `ast` (stdlib) resolves imports,
  symbol definitions, and call sites — facts a parser gives deterministically. It is
  NOT used to prove data flows along an edge at runtime; confidence is never HIGH from
  mere connection. JS/TS has no stdlib parser, so import extraction there is regex-
  based and explicitly lower-confidence. This asymmetry is intentional and stated.
- **Context weighting, not formula tampering.** The Phase 5 four-factor score is left
  exactly as-is. Context adjusts *severity band* and *reporting emphasis*, never the
  score. A test-only risk keeps its raw score as evidence but is capped one severity
  band and annotated.
- **Downgrade, never silently drop.** Ambiguous or non-production evidence is demoted
  in confidence/severity, not removed. Every file gets an explicit disposition; every
  finding keeps its evidence.

## Components

### Exclusion policy (`exclusion_policy.py`)
Centralized, exact-name directory exclusion with a category + reason + rule per
exclusion. Excludes only VCS metadata, dependency trees, build output, and caches.
Deliberately does NOT exclude `.github`, `tests`, `docs`, `examples`, `fixtures`, or
security tests. The historical `.github`-hidden-by-`.git` prefix bug is permanently
prevented by exact-name matching (regression-tested).

### File context taxonomy (`file_context.py`)
Eleven contexts — PRODUCTION, TEST, SECURITY_TEST, FIXTURE, EXAMPLE, DEMO,
DOCUMENTATION, CONFIGURATION, GENERATED, VENDOR, UNKNOWN — each with a confidence and
the list of reasons. Multi-signal: path + filename + extension + (optionally) content.
`tests/test_security_injection.py` becomes SECURITY_TEST, not plain TEST. PRODUCTION is
the conservative default. `context_classifier.py` remains as a backward-compat shim
exposing the original coarse 5-value API.

### Two-pass crawl (`crawl.py`)
Pass 1 inventories every file with a disposition (analyzed / excluded / unreadable /
binary / unsupported) — no silent drops, guaranteed by construction and checked by
`assert_no_silent_drops()`. Produces a coverage summary (counts by disposition,
context, and exclusion category) the report can surface.

### AST symbol index (`symbol_index.py`)
Python: stdlib `ast` extracts imports, function/class defs, and call sites. JS/TS:
regex import extraction. `resolve_python_import` / `resolve_js_import` resolve only
repo-internal targets — external packages (`openai`, `react`) resolve to `None`, so no
false cross-file edges are created. Confidence is keyed to resolution method
(IMPORT/LOCAL_SYMBOL/SAME_FILE/…), never HIGH for mere connection. Malformed files are
skipped gracefully, never crash the crawl.

## Integration into the pipeline

- **Discovery (8D):** every `AIFinding` carries `context` + `context_confidence`,
  classified once per file (content-aware) during the scan.
- **Attack surface (8J):** every `AttackSurfaceItem` carries the context of its source
  finding.
- **Risk (8E):** after scoring, a scenario driven entirely by non-production findings
  has its severity capped one band, `context_adjusted=True`, `primary_context` set, and
  a rationale note added. The score is untouched.
- **Readiness (8I):** content-classified SECURITY_TEST findings count as adversarial-
  testing evidence toward Level 2, alongside the existing path-convention scan.
- **Report (8K):** executive summary reports the production/non-production split using
  the fine-grained taxonomy; the consultant report annotates any context-capped
  scenario, explaining the reduction.

## Detection changes made during validation

These came from real repos, and each was matched to what the repo actually is (see
`PHASE-8-VALIDATION.md` for the full story):

- Tightened dynamic-code-execution to not match JS `.exec()`/`re.exec()` method calls.
- Added a match-context guard: a dangerous-call token, or an endpoint URL, inside a
  string literal or comment is downgraded to `low` (with a `comment_only` refinement so
  a URL inside a live `fetch()` template literal stays high).
- Added TS/JS AI idioms (OpenAI HTTP endpoint, Whisper, Vercel AI SDK, messages array,
  role messages, AI_* env vars) — recovering a large false-negative on a real TS AI app.
- Replaced the bare-word `webhook` pattern (16 hits across 3 repos, 0 real) with a
  webhook-handler idiom.

## Known limitations (unchanged philosophy)

- Static, bounded analysis. No runtime verification; no proof of exploitability.
- Cross-file resolution is structural (imports/symbols), not a proof of data flow.
  Confidence reflects this.
- JS/TS resolution is weaker than Python's (no stdlib parser), and is labelled so.
- File context is inferred from path/name/content signals, not declared metadata; a
  deliberately mislabeled file can defeat it. PRODUCTION-by-default keeps the failure
  mode conservative.

## Validation

Three real repos, three distinct fix classes, no fix damaging another repo's result.
244 tests passing including a dedicated Phase 8 integration matrix
(`test_phase8_integration.py`) covering crawl coverage, the `.github` regression,
context on findings, context-aware risk capping (and its production non-capping),
readiness security-test credit, and AST cross-file resolution (internal resolves,
external does not, malformed does not crash).
