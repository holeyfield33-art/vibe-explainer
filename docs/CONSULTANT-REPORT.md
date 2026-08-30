# Consultant Assessment Report (packaging layer)

This is a **packaging** layer, not an engineering expansion. It renders the existing
Phase 0–7 assessment as a consultant-grade Markdown deliverable a security
professional can hand to a client. It makes **no changes to the analysis engine** —
`consultant_report.py` is a pure function over an already-built `VibeExplainerReport`.

> **Pre-release warning:** “Consultant-grade” describes formatting, not analytical
> assurance. The engine remains an experimental regex/proximity evidence reporter.
> Severities and readiness levels are not empirically calibrated, and reports require
> manual validation before client use.

## Why it exists

The valuable asset isn't the regex engine — it's the traceable assessment chain:

```
Repository → AI surface → attack surface → data flow → controls → risk →
readiness → recommendations → evidence-backed report
```

The customer (initially: a security consultant) is buying the professional deliverable,
not the scanner. This layer produces that deliverable.

## Usage

```
vibe-explainer <repo> --security --consultant            # Markdown to stdout
vibe-explainer <repo> --security --consultant -o report.md
```

`--consultant` requires `--security`. It is mutually informative with `--json`
(if both are given, `--json` wins, since JSON is the machine format). The default
mode and plain `--security` terminal output are unchanged.

## Report structure

Repository / date / commit-scope header, then: Executive Summary, AI Attack Surface,
AI Data Flows, Key Risks (with per-scenario factor breakdown and severity), Security
Controls (grouped by status), AI Security Readiness (current level + all four level
assessments + blocker), Top Remediations (prioritized, each traced to its risk/control
IDs), Evidence Appendix (complete finding inventory), and Limitations.

## The one thing that makes it more than an "LLM security report"

**Every important conclusion traces back to evidence.** Attack-surface rows carry the
finding ID they came from; risk scenarios carry related finding/control IDs; the
evidence appendix lists every finding by ID so any claim above can be walked back to
`file:line:evidence`. That traceability is the moat, not the pattern count.

## Determinism and dates

The only injected value is `assessment_date` (defaults to today). It is reader-facing
metadata and never affects any analytical content — deliberately kept out of the
underlying report object so finding IDs and ordering stay deterministic regardless of
when the report is rendered.

## Secret redaction

The renderer reads already-redacted fields from `VibeExplainerReport`, and redaction
is re-applied at the Phase 7 serialization boundary. Covered secret formats are
verified by `TestConsultantReportRedaction` and CLI-level leak checks.

Redaction is also applied when discovery captures evidence and recognizes sensitive
assignments, credential-bearing URLs, private keys, JWTs, and common provider token
formats. This remains defense-in-depth rather than a guarantee that every secret
format is recognizable; reports must still be treated as sensitive.

## Untrusted tree safety

File symlinks and non-regular entries are excluded from content and process-evidence
scans. Reads are bounded and use no-follow semantics where supported. Global file,
byte, depth, and elapsed-time budgets remain future hardening work.

## Explicit non-goals

No SaaS, no dashboard, no GitHub App, no new detection, no engine changes. The next
step after this is **validation with real security professionals**, not more building.
