# Phase 7 — Report + CLI Product Integration

## 1. Report architecture

```
DiscoveryResult ─┐
AttackSurfaceResult ─┤
DataFlowGraph ─┤─▶ build_report() ─▶ VibeExplainerReport ─┬─▶ render_text()   (human)
ControlAssessment ─┤                                       └─▶ report.to_json() (machine)
RiskAssessment ─┤
ReadinessAssessment ─┘
```

`vibe_explainer/security_report.py` performs **no scanning, scoring, or
classification** — `build_report()` is a pure function over the six already-computed
Phase 1–6 results. The pipeline runs exactly once per CLI invocation
(`cli.py:_run_security_mode`); nothing is re-derived per report section.

## 2. CLI usage

```
vibe-explainer <repo>                    # unchanged: original mental-model report
vibe-explainer <repo> --security         # AI security assessment, human-readable
vibe-explainer <repo> --security --json  # AI security assessment, JSON
vibe-explainer <repo> --security -o FILE # write to a file instead of stdout
```

Backward compatible: the default (no `--security`) mode is byte-for-byte the same
code path as before this phase — `scanner.py` and `report.py` (the original
mental-model renderer) are untouched.

## 3. JSON usage

`--json` (only meaningful with `--security`) serializes the complete
`VibeExplainerReport` via `report.to_json()` — deterministic key order, no ANSI
codes, valid JSON verified by parsing it back in tests. Every ID in the JSON
(`finding_id`, `risk_id`, `control_id`, dataflow edge keys) is traceable to a real
object elsewhere in the same document — no dangling references.

## 4. Exit codes

- `0` — assessment completed, regardless of what it found. **A HIGH or CRITICAL risk
  scenario is a successful assessment result, not a tool failure**, and never changes
  the exit code.
- `1` — the analysis pipeline itself raised (e.g. an unreadable repository) —
  printed as `"Unable to analyze repository:\n<reason>"`, never a raw Python
  traceback.
- `2` — usage error (bad path), same as the pre-existing default-mode behavior.

## 5. Report sections

| Section | Source | Notes |
|---|---|---|
| `metadata` | tool/version/schema/repo path | no timestamps — nothing here affects IDs or ordering |
| `executive_summary` | Phases 1, 5, 6 | AI surface, risk count + highest severity, readiness level, completeness |
| `ai_inventory` | Phase 1 | grouped by discovery category; truncation notice when applicable |
| `attack_surface` | Phase 2 | all six buckets always present, even empty ones |
| `data_flows` | Phase 3 | edges only — no internal graph/index details |
| `controls` | Phase 4 | grouped by status, `NOT_DETECTED` always shown, never hidden |
| `risks` | Phase 5 | severity distribution + deterministically sorted scenario list |
| `readiness` | Phase 6 | all four level assessments + `blocked_from_next_level` |
| `recommendations` | derived, see §7 | deduplicated, prioritized |
| `limitations` | static + conditional | always present, never buried |

## 6. Risk vs readiness

Both appear side by side in `executive_summary` and are never combined into one
number or used to infer each other. Verified directly:
`test_both_present_and_independent_in_report` checks the `agent-with-tools` fixture
reports `highest_risk_severity: "HIGH"` and `readiness_level: 1` simultaneously — the
report never states anything like "because risk is high, readiness is low" or vice
versa; both numbers are simply presented.

## 7. Recommendations

Generated from **existing** evidence only — no new detection. Priority order:

1. `CRITICAL`/`HIGH`/`MODERATE` risk scenarios (already deterministically sorted by
   Phase 5 severity → score → category → risk_id)
2. The single most immediate readiness blocker (the first missing requirement for
   `readiness_level + 1`)
3. Notable `NOT_DETECTED` controls (`C05`, `C08`, `C09`, `C10`, `C12`) **not already
   covered** by a risk-scenario recommendation above

Deduplication: a control referenced by `related_control_ids` on any risk-scenario
recommendation is never also given its own standalone recommendation — verified by
`test_dedup_control_not_double_recommended_with_its_risk` (C05's gap in
`agent-with-tools` is covered by the `TOOL_SECURITY`/`HIGH_IMPACT_ACTION` risk
recommendations, so no separate "C05 not detected" line is added). Priorities are
assigned sequentially (`P0`, `P1`, …) over the final merged, sorted list — not
hardcoded per category.

## 8. No-AI behavior

`executive_summary.ai_surface = "NOT_DETECTED"`, `risk_scenario_count = 0`,
`readiness_level = None`. The statement is exactly *"No AI security assessment was
generated because no AI surface was detected."* — never `LOW RISK`, never
`Level 1`, never "good security posture." Both the JSON and text renderers short-circuit
straight to limitations after this statement.

## 9. Truncation behavior

`ai_inventory.truncation_notice` is set (and `metadata.assessment_completeness` is
`PARTIAL`) whenever `DiscoveryResult.truncated` is non-empty — propagated from Phase 2
through every downstream phase. A dedicated limitation line
(*"Discovery results were truncated for this repository..."*) is appended so it's
visible in the limitations section, not just a buried metadata flag.

## 10. Secret redaction

**Found and fixed during this phase's own testing**: Phase 5's `_redact()` only
covered risk-scenario text. The report's `ai_inventory`, `attack_surface`, and
`controls` sections serialize raw `AIFinding.evidence` text directly — which, for a
`secret_config` finding, *is* the literal source line containing the key. Worse, a
hardcoded key can also get picked up by an unrelated finding on the same line (e.g. a
bare `openai` keyword match), so category-based redaction ("only redact
`secret_config` items") wasn't sufficient either. Fixed by applying `_redact()`
**unconditionally** to every evidence/rationale string that reaches the report,
regardless of category — verified by `TestSecretRedaction` and
`test_no_secret_leakage_via_cli`, which check the actual key value never appears
anywhere in the full serialized report or CLI output.

## 11. Limitations

Always present, never gated behind a debug flag: static/regex-only analysis, same-file
data-flow only, no runtime verification, keyword/path-based control and readiness
evidence, repository-evidence-only scope — plus a truncation-specific line when
applicable, plus Phase 6's own limitations merged in (deduplicated).

## 12. Example output structure

```
VIBE EXPLAINER
AI SECURITY ASSESSMENT
────────────────────────────────────────

AI SURFACE
DETECTED

RISKS
2 scenario(s)
Highest: HIGH

READINESS
Level 1 — BASELINE

────────────────────────────────────────
TOP RISKS

HIGH      AI-connected high-impact action (shell/dynamic-code execution) without
          detected authorization control
          Repository evidence shows an AI-connected path to a high-impact...

────────────────────────────────────────
READINESS

Level 1  BASELINE     ACHIEVED
Level 2  MANAGED      BLOCKED
         └─ no repeatable AI/security test artifact detected...

────────────────────────────────────────
RECOMMENDED ACTIONS

P0  AI-connected high-impact action ... without detected authorization control
P1  AI-connected tool execution without detected authorization control

────────────────────────────────────────
ASSESSMENT LIMITATIONS

- Static, regex/keyword-based analysis only...
```
