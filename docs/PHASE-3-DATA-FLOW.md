# Phase 3 — Static AI Data-Flow Observation

> **Validity warning:** Relationships remain same-file proximity associations. They
> are not control-flow, def-use, import-graph, or taint-analysis results and require
> manual validation before security decisions.

## 1. Purpose

Connect the AI components `ai_discovery.py` already found into a lightweight graph of
plausible relationships, so a reviewer (or a future report) can see "these pieces of
evidence look connected" rather than a flat, unordered list of findings.

## 2. What constitutes an observation

An observation (`DataFlowObservation`, a graph edge) is created only when two findings:

1. sit in the **same file**,
2. are within `MAX_DATAFLOW_LINE_DISTANCE` (30) lines of each other,
3. belong to a **documented category pair** (see §4), and
4. are the *nearest* qualifying pair for that destination finding (no combinatorial
   fan-out just because several candidates exist).

If any of those four conditions fails, **no edge is produced.** Nothing is invented to
increase coverage.

## 3. OBSERVED vs INFERRED vs UNKNOWN

Three statuses exist in the vocabulary; this module emits exactly one of them:

- **INFERRED** — the only status this phase produces. A same-file, category-paired,
  proximity-supported relationship. It is an inference from static text position, not
  a confirmed runtime data flow.
- **OBSERVED** — reserved for a stronger evidentiary standard (execution tracing,
  instrumented test runs) that static analysis cannot provide. Never emitted here;
  doing so would misrepresent a guess as a fact.
- **UNKNOWN** — reserved for "a relationship is suspected but there's not enough
  evidence to classify it." Also never emitted: per the detection rules, insufficient
  evidence means *no edge at all*, not an UNKNOWN edge. An UNKNOWN edge invented just
  because two components co-exist in a repo is exactly the overclaiming this phase is
  designed to avoid.

## 4. Relationship types (implemented this phase)

| Source category | Destination category | Relationship | Notes |
|---|---|---|---|
| `prompt_surface` | `ai_usage` | `feeds_prompt` | |
| `rag_retrieval` | `ai_usage` | `retrieved_context` | |
| `ai_usage` | `tool_agent` | `invokes_tool` | |
| `ai_usage` | `tool_agent` (shell/eval names only) | `flows_to_output` | Covers directive item #7 (model output → downstream sink) using existing `tool_agent` evidence — no separate "output" detector exists yet, so a shell/eval sink is the closest available signal. |
| `ai_usage` | `external_integration` | `calls_external_service` | |
| `secret_config` | `model_provider` | `reads_storage` | |
| `secret_config` | `ai_usage` | `reads_storage` | |

**Not implemented this phase**, documented rather than silently skipped:

- `user_input → prompt_surface` — no `user_input` discovery category exists in
  `ai_discovery.py`. Building it would be new Phase 1 detector work (e.g. HTTP
  request-body parsing, form input, CLI `input()` calls feeding a prompt variable),
  out of scope for a data-flow phase. Adding this relationship without first adding
  the category would mean inventing evidence.
- `ai_usage → storage-related findings (general)` beyond the credential-specific
  `reads_storage` above — there's no discovery category for actual conversation/data
  storage (databases, session stores) distinct from credentials
  (`secret_config`) or outbound clients (`external_integration`, bucketed as
  Tools). Extending this needs a new "data store" category first.

## 5. Proximity heuristic

`MAX_DATAFLOW_LINE_DISTANCE = 30` (named constant in `dataflow.py`). Findings farther
apart than this in the same file are never connected — this is the line between
"moderate confidence" and "no evidence," not a soft cutoff.

For a destination finding with multiple same-file candidates in the paired source
category, only the **nearest** one is connected (tie-broken deterministically by line
number, then finding id). This prevents combinatorial edge explosion when a file has,
say, three `tool_agent` findings and one `ai_usage` call — each `tool_agent` finding
still gets its own edge (since each is a separate *destination*), but a single
`ai_usage` finding never fans out to every conceivable partner beyond what the nearest
match justifies per destination.

## 6. Confidence rules

Two tiers only:

- **high** — same-file distance ≤ `HIGH_CONFIDENCE_LINE_DISTANCE` (10 lines). Proxy for
  "tight coupling" in the absence of real AST evidence.
- **moderate** — same-file distance between 10 and 30 lines. "Supported primarily by
  proximity," per the directive's own definition.

**"low" is intentionally never emitted.** A proximity-only heuristic beyond the
moderate range has crossed into insufficient-evidence territory — the correct response
there is no observation, not a low-confidence edge produced merely to increase
coverage (the directive's own instruction).

## 7. Current limitations

- Same-file only. No cross-file resolution (see §8).
- Proximity is a distance proxy, not real evidence of a data dependency — two
  unrelated findings that happen to sit near each other in a large function could
  still connect. Mitigated by requiring a documented category pair, but not eliminated.
- No directionality validation — "prompt defined 3 lines *after* the model call it
  supposedly feeds" would still connect, since only absolute distance is checked, not
  code order. Left as a known gap rather than adding heuristic complexity this phase.
- `reads_storage` uses `secret_config` findings as a proxy for "credential material is
  nearby" — it does not confirm the credential is actually the one used to
  authenticate that specific call.

## 8. Cross-file analysis limitation

Explicitly deferred, not attempted. Connecting a prompt defined in `prompts.py` to a
model call in `client.py` needs import-graph resolution (who imports what, under what
alias, is the name actually used at the call site) — a materially different and larger
piece of work than line-proximity matching. Verified via `tests/fixtures/dataflow-cross-file/`:
both findings are correctly discovered, and correctly produce **zero** edges between them.

## 9. Why this is NOT exploitability analysis

An edge here means "two pieces of static evidence are plausibly related by position."
It says nothing about whether the relationship is reachable at runtime, whether input
is actually attacker-controlled, or whether any control mitigates it. That's the job of
later phases (Controls, Risk) and, beyond static analysis entirely, the future Aletheia
AI Red Team. Confusing "I found a plausible same-file relationship" with "this is
exploitable" is precisely the overclaiming this module's design (INFERRED-only status,
two-tier confidence, no-edge-on-insufficient-evidence) is built to prevent.

## 10. Future extension points

- A `user_input` discovery category (Phase 1 addition) would unlock the
  `user_input → prompt_surface` relationship.
- A dedicated "data store" discovery category would allow a real
  `ai_usage → storage (writes conversation/data)` relationship, distinct from the
  credential-proxy `reads_storage` implemented here.
- Cross-file resolution via lightweight import-graph parsing (Python `import`/`from`
  statements, JS/TS `import`/`require`) — a bounded, well-scoped Phase 3.5/4 candidate
  if it turns out to matter for real repos.
- Directionality (source-before-destination in code order) as an additional signal
  feeding into confidence, if false positives from out-of-order proximity turn out to
  be common in practice.
