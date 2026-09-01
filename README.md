# Vibe Explainer

**Static AI security readiness assessment for any repository.**

Point it at a codebase and get a structured, evidence-backed assessment of its AI
security posture: what AI components exist, what attack surface they create, how data
and capability flow between them, which security controls are present, what risks that
evidence represents, and how mature the repository's demonstrated security practice is —
scored against a four-level readiness model.

The risk scoring and readiness levels are aligned to the **HackerOne "Security for AI:
Readiness and Risk Playbook"** framework (four-factor risk scoring, four readiness
levels from Baseline to Continuous, and a Preventive / Validation / Governance control
taxonomy), so the output maps to vocabulary security teams already recognize.

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
- **Secrets are redacted (defense-in-depth).** Known credential shapes — provider API
  keys, cloud access keys, JWTs, private-key blocks, `KEY=`/`TOKEN=`/`SECRET=`/`PASSWORD=`
  assignments, and URL-embedded credentials — are replaced with `[REDACTED]` at the
  evidence and serialization boundaries. This reduces exposure but is not a guarantee that
  every possible secret format is caught; treat reports as potentially sensitive and review
  them before sharing.
- **No manufactured findings.** A repo with no AI surface reports exactly that — not a
  fabricated "LOW risk / Level 1 / looks secure."
- **Every claim is traceable.** Attack-surface rows, risk scenarios, and recommendations
  all reference the finding / data-flow / control IDs they derive from.

## Legacy mode: repository mental model

The original orientation report is still available (default mode, no `--security`): a short
"what is this repo and where do I start" map, optionally grounded in an external
code-quality report.

```bash
python -m vibe_explainer /path/to/repo                          # mental-model report
python -m vibe_explainer /path/to/repo --vibe-check-report report.json
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

## Scope and hardening

**Experimental prototype — not production security assurance.** The repository
contains both the original mental-model report and an experimental `--security`
static evidence pipeline. The security pipeline uses regex and proximity heuristics;
it does not prove exploitability, control effectiveness, compliance, or maturity.

Current hardening guarantees:

- local/offline analysis with no target-code execution;
- file symlinks and non-regular files are skipped;
- bounded file reads;
- secret redaction at evidence and report boundaries; and
- a 90% branch-coverage gate (currently 94% across the package).

Reports remain potentially sensitive and should be reviewed before sharing.

See [SPEC.md](SPEC.md) for the full product specification.

## Quick start (development)

```bash
cd vibe-explainer
python -m vibe_explainer examples/sample-vibe-project --offline
python -m vibe_explainer examples/sample-vibe-project --offline --out /tmp/explain.md
python -m vibe_explainer tests/fixtures/basic-chatbot --security --json
python -m unittest discover -s tests
python -m coverage run -m unittest discover -s tests
python -m coverage report
```

The coverage commands require the development-only `coverage` package.

## Security-mode limitations

- Language coverage is uneven; detection is primarily shaped around Python forms.
- Comments, strings, examples, tests, generated code, and production code are not
  yet reliably distinguished.
- Data-flow relationships are same-file line-proximity inferences, not control-flow
  or taint analysis.
- Numeric risk severities and readiness levels are deterministic policy outputs,
  not empirically calibrated predictions.
- A unified coverage ledger and scan-wide resource budgets remain unfinished.

See [SECURITY.md](SECURITY.md), [CHANGELOG.md](CHANGELOG.md), and the open GitHub
issues for the hardening backlog.

## Design principles (inherited from vibe-check)

- Prefer offline / deterministic where possible
- Be honest about limitations and coverage
- Produce something a human actually reads
- Stay small enough that the tool itself is understandable
- Never pretend a zero means more than what was actually checked

## Part of the Aletheia toolchain

```
Aletheia portfolio auditor  → which repos need attention
vibe-check                 → what’s wrong / triage disposition
vibe-explainer             → here’s the map so a human can look productively
Lie Detector               → does the repo do what it claims
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
