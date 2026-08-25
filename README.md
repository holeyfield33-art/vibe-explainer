# Vibe Explainer

**Static AI security readiness assessment for any repository.**

Point it at a codebase and get a structured, evidence-backed assessment of its AI
security posture: what AI components exist, what attack surface they create, how data
and capability flow between them, which security controls are present, what risks that
evidence represents, and how mature the repository's demonstrated security practice is —
scored against a four-level readiness model.

```bash
python -m vibe_explainer /path/to/repo --security             # human-readable summary
python -m vibe_explainer /path/to/repo --security --json      # full machine-readable assessment
python -m vibe_explainer /path/to/repo --security --consultant # consultant-grade Markdown report
```

Everything runs **offline and deterministically** — Python stdlib only, no API keys, no
network, same repo in, same assessment out.

> **What this is, and what it is not.** Vibe Explainer performs *static, evidence-based*
> analysis. It reports what the repository's own code and configuration demonstrate. It
> does **not** execute the application, prove exploitability, or replace adversarial
> testing or a manual security review. Every conclusion it prints traces back to a
> specific finding, data-flow observation, or control — that evidence chain is the point.

---

## The assessment pipeline

Each stage consumes the previous one; nothing is re-scanned or re-scored downstream.

```
Repository
   |  AI discovery          - model providers, prompt surfaces, RAG, tools, MCP, secrets...
   |  Attack surface        - six buckets: inputs, model, retrieval, tools, outputs, storage
   |  Data flow             - same-file, evidence-based relationships between components
   |  Security controls     - 12 controls, DETECTED / PARTIAL / NOT_DETECTED / NOT_APPLICABLE
   |  Risk scenarios        - four-factor scoring (Exposure . Safety . Security . Likelihood)
   |  Readiness             - Level 1 Baseline -> 4 Continuous, independent of risk severity
   |  Report                - executive summary, evidence appendix, prioritized remediations
```

### What each stage promises — and refuses to claim

- **Discovery** finds AI-relevant code by content, tagging every finding with
  `file:line`, the matched evidence, and a confidence level. It never treats a keyword as
  proof.
- **Controls** report *evidence of a control*, never that a control is complete or
  effective. `NOT_DETECTED` means "no supporting evidence was found here" — **not** "this
  control does not exist" (it may live outside the repository).
- **Risk** scores the concern represented by the evidence. It never claims a path is
  exploitable — every scenario rationale says so explicitly.
- **Readiness** measures *demonstrated process maturity*, and is deliberately independent
  of risk severity. A repo can carry a high-severity risk at an early readiness level, or
  vice versa. Running Vibe Explainer on a repo does not itself raise that repo's readiness.

## Context awareness

A real AI repository contains the same strings in production code, test fixtures, demo
payloads, generated manifests, and documentation. Vibe Explainer labels every finding by
**context** — `Production`, `Test`, `Example`, `Documentation`, or `Generated` — so a
genuine production surface is never buried under thirty test-fixture matches of the same
pattern. The executive summary reports how many findings are in production code versus
everything else, and the consultant report lists production surface first.

## Output modes

| Mode | Flag | Use |
|------|------|-----|
| Terminal summary | `--security` | Quick read: surface, top risks, readiness, blockers, recommendations |
| Full JSON | `--security --json` | Machine-readable; complete assessment with every ID for traceability |
| Consultant report | `--security --consultant` | Professional Markdown deliverable with an evidence appendix |

Exit codes are for tool status only: `0` = assessment completed (even with HIGH/CRITICAL
findings — a finding is a result, not a crash), `1` = analysis error, `2` = usage error.

## Honesty guarantees

- **Truncation is loud.** If discovery is truncated on a large repo, the assessment is
  marked `PARTIAL` and the report states plainly that counts are a lower bound — never
  "only N risks."
- **Secrets are redacted.** Any credential-shaped value is replaced with `[REDACTED]`
  everywhere in every output, enforced at the serialization boundary.
- **No manufactured findings.** A repo with no AI surface reports exactly that — not a
  fabricated "LOW risk / Level 1 / looks secure."
- **Every claim is traceable.** Attack-surface rows, risk scenarios, and recommendations
  all reference the finding / data-flow / control IDs they derive from.

## Legacy mode: repository mental model

The original orientation report is still available (default mode, no `--security`): a short
"what is this repo and where do I start" map, optionally grounded in a
[vibe-check](https://github.com/holeyfield33-art/vibe-check) report.

```bash
python -m vibe_explainer /path/to/repo                          # mental-model report
python -m vibe_explainer /path/to/repo --vibe-check-report report.json
```

## Where it sits in the toolchain

Vibe Explainer is one of three composable static-analysis tools, each answering a
different question about a repository:

```
vibe-check       -> Is this code itself trustworthy?   (AI-generated / rushed-code signals)
vibe-explainer   -> Is its AI security posture sound?  (this tool)
Lie Detector     -> Do its README claims hold up?      (executable claim verification)
```

## Development

```bash
python -m unittest discover -s tests        # full suite
python -m vibe_explainer examples/sample-vibe-project --security
```

Architecture and per-stage methodology are documented in `docs/` (`PHASE-1`...`PHASE-7`,
`CONSULTANT-REPORT.md`).

## Design principles

- Offline and deterministic wherever possible
- Report evidence, never assert exploitability or effectiveness
- Distinguish "not detected" from "does not exist" from "not applicable"
- Keep risk (how concerning) and readiness (how mature) strictly separate
- Be loud about limitations, truncation, and what wasn't checked

## License

MIT
