# Detailed Evidence Review Report

`consultant_report.py` is the historical module name for the detailed Markdown renderer.
The renderer is a packaging layer over `VibeExplainerReport`; it performs no scanning,
classification, scoring, or validation of its own.

Use the report as an analyst work product:

```bash
vibe-explainer REPO --report
vibe-explainer REPO --report -o review.md
```

`--consultant` remains a deprecated compatibility alias. The report is not automatically
suitable for delivery: an analyst must verify scope, evidence, context, inferred
relationships, secrets, conclusions, and limitations before sharing it.

## Structure

The report contains scope and engine metadata, executive evidence summary, AI inventory,
attack-surface leads, inferred relationships, unscored concern scenarios, control
artifacts, an unscored process-evidence checklist, recommendations, evidence appendix,
and limitations.

Every important row carries a finding, relationship, control, or concern ID that can be
traced to repository evidence. Traceability supports review; it does not convert heuristic
evidence into proof of exploitability or control effectiveness.

## Framework vocabulary

Some categories and four-level labels use vocabulary adapted from HackerOne's
"Security for AI: Readiness and Risk Playbook." Vibe Explainer is not a HackerOne
assessment, endorsed implementation, certification, or validated conformance tool.
Numeric scores, severity bands, and process levels are absent from default reporting.
They are available only through `--experimental-scoring` as uncalibrated research output.

## Sensitive output

Evidence is redacted during construction and again at serialization boundaries. Secret
recognition is necessarily incomplete. Treat every report as potentially sensitive,
retain it according to the client's handling policy, and inspect it before distribution.

## Determinism

The renderer's date is reader-facing metadata and does not alter finding IDs or analytical
ordering. Full reproducibility also requires source commit, dirty state, scan configuration,
exclusions, and catalog hash; those provenance additions are tracked in issue #10.
