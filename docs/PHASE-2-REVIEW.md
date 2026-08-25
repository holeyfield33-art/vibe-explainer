# Phase 2 Review — Data Model & Quality Gate

Scope: bounded review of `ai_discovery.py` / `attack_surface.py` before Phase 3 (data-flow).
No new product features added. Two minimum-change fixes applied for blocking issues found
during the review (below); everything else is documentation-only.

## 1. Data model review

`AIFinding`: `category`, `name`, `file`, `line`, `evidence`, `confidence` — all present as
required. **Added in this review:** `id` (deterministic 12-char hash of
`file:line:category:name`), because nothing previously gave a finding a stable identity
independent of its position in a list.

`AttackSurfaceItem`: full copy of the finding's fields plus `bucket` and
`security_relevance`. **Added in this review:** `finding_id`, tracing each attack-surface
item back to the exact `AIFinding.id` it was built from.

Nothing else was discarded going from discovery → attack-surface — every `AIFinding` field
survives into its `AttackSurfaceItem` (category/name/file/line/evidence/confidence are all
copied verbatim, not summarized or re-derived).

## 2. Phase 3 compatibility review

Minimum information Phase 3 (data-flow) will need, and its current status:

| Requirement | Status |
|---|---|
| Stable ID per finding, so edges (`prompt_surface → model`, `retrieval → model`, etc.) can reference nodes without re-deriving identity | **Fixed this pass** — `AIFinding.id` / `AttackSurfaceItem.finding_id` |
| A way to know a match happened even when suppressed by the noise cap | **Fixed this pass** — `DiscoveryResult.truncated` |
| File + line for every finding (needed to reason about proximity — e.g. "prompt template two lines above a `.create()` call") | Already present |
| Bucket assignment (which of Inputs/Model/Retrieval/Tools/Outputs/Storage) | Already present via `attack_surface.py` |

Not needed yet, deliberately not built: an actual graph/edge structure connecting findings.
Phase 3's job is to *produce* those edges (e.g. "this `prompt_surface` finding feeds this
`ai_usage` finding") using file/line proximity and import graphs — that's new logic, not a
gap in Phase 1–2's data model. The current structures give Phase 3 stable nodes to attach
edges to; they intentionally don't try to guess the edges themselves.

## 3. False-positive review

Spot-checked the categories most likely to false-positive on generic terms (the directive
specifically flagged "agent", "prompt", "tool"):

- `tool_agent` and `mcp` patterns require a specific construct (`@tool`, `tool_choice=`,
  `subprocess.run(`, `FastMCP(`, etc.) — bare words like `insurance_agent` or `tool_belt`
  do **not** match anything. **ACCEPTABLE FOR PHASE 1.**
- `prompt_surface` → "Generic prompt variable" matches `prompt = "..."` style assignments,
  which a non-AI CLI confirmation prompt would also trigger — but it's tagged `low`
  confidence specifically because of this. **ACCEPTABLE FOR PHASE 1** (confidence is doing
  its job here).
- `secret_config` → "Generic API key reference" only matches the bare token `API_KEY`, not
  compound names like `STRIPE_API_KEY` (word-boundary regex), so it won't conflate
  third-party keys with AI keys — but a literal `API_KEY = ...` for a non-AI service would
  still surface at `low` confidence. **ACCEPTABLE FOR PHASE 1.**
- **No directory-context tagging** — a finding inside `tests/` or `examples/` currently
  looks identical to one in production code (confirmed: scanning `vibe_explainer/` picks up
  fixture files the same way it picks up real source). This is a real limitation for a
  "defensible assessment" — test-only AI usage shouldn't weigh the same as production usage
  once we get to risk scoring. **DEFER TO LATER** (Phase 4/5, where confidence or relevance
  can be discounted by path — flagging it now so it isn't forgotten).

## 4. Confidence review

Confidence is a fixed value attached to each pattern in the `_PATTERNS` table, not computed
from surrounding context — so it's deterministic by construction: the same pattern always
produces the same confidence, run to run, file to file. Verified via a regression test
(`test_finding_has_stable_deterministic_id`) that re-running discovery on unchanged input
produces identical finding IDs (which are themselves derived from file/line/category/name,
so any drift would show up there first).

## 5. Attack-surface review

- **Duplicates:** no evidence of double-counting — each `AIFinding` produces exactly one
  `AttackSurfaceItem`.
- **Silent drops — blocking issue found and fixed:** the per-file-pattern cap
  (`MAX_FINDINGS_PER_FILE_PATTERN = 3`) was discarding matches past the cap with zero
  record anywhere. Confirmed on real content: scanning `vibe_explainer/` itself, 5
  (file, category, name) groups hit the cap, silently dropping real matches. Fixed by
  adding `DiscoveryResult.truncated`, which records `{file, category, name,
  additional_matches}` for every group that hit the cap, surfaced in `to_dict()`.
- **Traceability:** fixed in this pass via `finding_id` (see §1).
- **Outputs bucket empty:** confirmed still explicitly documented in
  `attack_surface.py`'s docstring and covered by
  `test_all_buckets_present_in_to_dict_even_when_empty`.

## 6. Test review

Full suite: **29/29 passing** (24 from Phases 1–2, +5 new regression tests added in this
review: 2 for stable/unique IDs, 2 for truncation tracking, 1 for attack-surface
traceability). Coverage includes positive detection, one explicit negative/no-AI baseline,
evidence/line-number/confidence presence, attack-surface bucketing, and the two issues
fixed in this review.

## Recommended Phase 3 starting point

Data-flow can now reference findings by `id` instead of positional identity. Suggested
first data-flow relationships to implement (per the original directive's examples), in
order of how directly the current data supports them:

1. `prompt_surface → ai_usage` (same file, prompt finding on an earlier or nearby line than
   a chat/completions call) — cheapest, uses only file+line already on hand
2. `rag_retrieval → ai_usage` (same file, similar proximity heuristic)
3. `ai_usage → tool_agent` (model call followed by tool-invocation evidence in the same
   file) — weakest signal of the three, flag as `low`/`moderate` confidence only

Cross-file flows (e.g. "database → retrieval → model" across modules) are out of scope for
a first data-flow pass — that needs import-graph resolution, which is a bigger, separate
piece of work than line-proximity heuristics.
