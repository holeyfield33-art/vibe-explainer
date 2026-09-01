# Phase 5 — AI Security Risk Assessment

> **Calibration warning:** Factor values and severity thresholds are deterministic
> policy constants and have not been calibrated against real incidents or a labeled
> vulnerable/secure repository corpus.

**The risk engine evaluates risk represented by repository evidence. It does not prove
exploitability or establish that a vulnerability can be successfully exploited.**

## 1. Purpose

Turn the evidence chain from Phases 1–4 (findings → attack surface → data flow →
controls) into deterministic, evidence-backed risk *scenarios* — not a single
repository-wide score, and not a claim about what's actually exploitable.

`assess_risks(discovery, attack_surface, dataflow, controls) -> RiskAssessment`
performs **no new repository scan**; it is a pure function over the four upstream
results.

## 2. Risk scenario model

```
RiskAssessment
  ├── ai_surface_detected: bool
  ├── assessment_completeness: COMPLETE | PARTIAL
  ├── summary_note: str
  └── scenarios: list[RiskScenario]
        ├── risk_id, title, category
        ├── exposure, safety_impact, security_exposure, likelihood  (1-5 each)
        ├── score, severity
        ├── confidence
        ├── rationale
        ├── evidence[]  (type: finding | dataflow | control)
        ├── related_finding_ids / related_dataflow_ids / related_control_ids
```

Scenarios are grouped by coherent evidence chain, not generated one-per-finding — e.g.
a `prompt_surface → ai_usage` chain with several findings produces one
`INPUT_SECURITY` scenario, not three.

## 3. Factor definitions

Four factors, 1–5 each, per the source framework:

- **Exposure** — how reachable the AI path is, from repository evidence only. Default
  is conservative (2); bumped to 3 only when a `feeds_prompt` data-flow edge shows the
  path is user-influenced, or (for RAG) a `Webhook` finding suggests external content
  ingestion. **Never inferred from an HTTP library existing alone** — the directive is
  explicit about this, and it's enforced: `EXTERNAL_INTEGRATION` exposure comes from
  the same prompt-chain check, not from `requests`/`httpx` being imported.
- **Safety Impact** — potential impact if the path misbehaves. Fixed per category
  (5 for shell/eval sinks, 4 for data-access/MCP/secret-exposure, 3 for generic
  tool/external-call, 2 for input/output-only paths) — a deliberately coarse,
  documented table rather than a per-repo judgment call.
- **Security Exposure** — sensitivity of the capability, informed by the relevant
  Phase 4 control's status: `DETECTED` lowers it, `NOT_DETECTED` raises it, `PARTIAL`
  sits between. `SECRET_EXPOSURE` is fixed at 5 (a hardcoded key found in source *is*
  the maximum-sensitivity case by definition).
- **Likelihood** — "likelihood of the identified risk condition being relevant," not
  probability of exploitation. Driven by (a) the paired control's status and (b) the
  data-flow edge's own confidence (`high`/`moderate` from Phase 3) — weak same-file
  proximity evidence caps likelihood lower than a tight, high-confidence edge.

## 4. Formula

Unmodified from the source framework:

```
score = ROUND(((exposure + safety_impact + security_exposure) / 3) * likelihood)
```

Implemented with round-half-up (`score_risk()` in `risk.py`), matching the
spreadsheet-style `ROUND()` the framework document itself uses rather than Python's
default banker's rounding.

## 5. Severity thresholds

| Score | Severity |
|---|---|
| 1–7 | LOW |
| 8–14 | MODERATE |
| 15–19 | HIGH |
| 20–25 | CRITICAL |

Boundary-tested directly (`score_risk`/`severity_for` unit tests), not just inferred
from end-to-end fixtures.

## 6. Confidence semantics

Confidence in *the assessment*, not probability of exploitation. Generally the
strongest data-flow edge confidence feeding the scenario (`high`/`moderate`, same
two-tier discipline as Phase 3 — never a manufactured "low"). `SECRET_EXPOSURE` is
fixed at `high` (the hardcoded-key pattern itself is a high-confidence finding).
`DATA_ACCESS` and `MCP_SECURITY` default to `moderate` — there's no data-flow edge
directly linking AI usage to a database client or an MCP server today (that would need
new Phase 3 relationship rules), so confidence is capped below what a direct edge
would justify.

## 7. Control interaction

Controls inform factor **values and rationale** — never a bolt-on multiplier or
subtraction. There is no `score = base_score * control_discount` anywhere in this
module; every factor value is chosen from a small, documented table keyed by the
relevant control's status (see `_security_exposure_from_control` /
`_likelihood_from_control_and_confidence` in `risk.py`). The four-factor formula
itself is never adjusted post-hoc.

Verified directly: the same tool-execution evidence with vs. without a detected
authorization control (C05) produces different `security_exposure`/`likelihood`
values and a different final score — `agent-with-tools` (no auth) scores its
`TOOL_SECURITY` scenario higher than `controls-tool-with-auth` (auth present), and the
rationale explicitly names which control and status drove the difference.

## 8. Evidence requirements

Every generated scenario carries at least one `RiskEvidenceRef`. No scenario is
generated with an empty evidence list. Evidence descriptions reference
`finding`/`dataflow`/`control` IDs rather than copying full objects, so a reader can
always trace back to `file:line:evidence` on the original finding via Phase 1's ID.

## 9. Truncation behavior

`RiskAssessment.assessment_completeness` is `PARTIAL` whenever
`DiscoveryResult.truncated` is non-empty (Phase 2's noise cap was hit somewhere), and
`summary_note` explicitly says *"Assessment may be incomplete because discovery
results were truncated."* This is never silently dropped — verified by a dedicated
test against the `truncation-heavy` fixture.

## 10. Secret redaction

`SECRET_EXPOSURE` evidence descriptions run through `_redact()`, which replaces any
`sk-...`-shaped substring with `[REDACTED]` before it ever reaches a `RiskEvidenceRef`.
Verified directly: the hardcoded-credential fixture's actual key value never appears
anywhere in the generated risk output.

## 11. No-AI behavior

`ai_surface_detected = False` and `scenarios = []` for a repository with zero AI
findings — never a fabricated LOW score "to have a number." `summary_note` states
plainly that no AI components were found, not that the repository is safe.

## 12. Limitations

- Factor values come from small, hand-authored tables keyed by category/control-status/
  edge-confidence — not a continuous or learned model. Two repositories with subtly
  different evidence can land on the same factor values if they fall in the same table
  bucket; this is a deliberate simplicity/defensibility tradeoff, not an oversight.
- `EXTERNAL_INTEGRATION` and `DATA_ACCESS` have no dedicated Phase 4 control mapped
  1:1 the way `TOOL_SECURITY`↔C05 or `RAG_SECURITY`↔C09 do — `EXTERNAL_INTEGRATION`'s
  security exposure instead falls back to "was a credential finding present in the
  same file," a weaker proxy, documented as such in its own rationale text.
- Inherits every upstream limitation: same-file-only data flow (Phase 3), regex/
  keyword-only control evidence (Phase 4), no AST or cross-file resolution anywhere in
  the chain.
- `INPUT_SECURITY`/`OUTPUT_SECURITY` are deliberately only generated for `ai_usage`
  findings *not* already covered by a more specific sink-oriented scenario
  (`TOOL_SECURITY`, `HIGH_IMPACT_ACTION`, `EXTERNAL_INTEGRATION`, `DATA_ACCESS`) — this
  avoids redundant overlapping scenarios for the same evidence chain, per the
  directive's grouping instruction, but means a complex chain's input/output concerns
  are folded into the sink scenario's rationale rather than surfaced as their own line
  item.

## 13. Risk ≠ readiness

A risk score answers "how concerning is this identified evidence scenario." Readiness
(Phase 6, not implemented here) answers "how mature and repeatable is the
organization's AI security testing program." This module never computes a Level 1–4
readiness classification, never infers one from a risk score, and keeps the two
concepts fully independent — a repository can have strong controls and one high-risk
component, or weak controls and only moderate current risk, and this module represents
both correctly rather than collapsing them into one number.

## 14. Risk ≠ exploitability

Every scenario's rationale explicitly avoids exploitability language ("remote code
execution confirmed," "vulnerability present") in favor of evidence language
("repository evidence shows an AI-connected path to X; this assessment does not
establish exploitability"). Nothing in this module executes code, traces a runtime
call, or confirms a path is actually reachable by an attacker — it describes what the
static evidence chain looks like and how concerning that combination is, nothing more.
