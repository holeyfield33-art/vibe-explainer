# Aletheia AI Readiness Audit
**Static security posture assessment for AI-integrated systems.**

The Aletheia AI Readiness Audit (formerly Vibe Explainer) provides a structured, evidence-backed assessment of a repository's AI security posture. It maps the attack surface, identifies risks, and scores the project's security maturity against an industry-standard framework.

Instead of subjective "vibes," this tool produces a clinical analysis of what the code *demonstrates* about its security practices.

```bash
python -m vibe_explainer /path/to/repo --security --consultant
```

You receive a professional **Consultant-Grade Report** that maps findings to the **HackerOne "Security for AI: Readiness and Risk Playbook"**, providing a common vocabulary for security teams and executives.

---

## 🛡️ The Assessment Pipeline

The tool performs a multi-stage static analysis to build a complete picture of the AI surface.

**The Workflow:**
`Repository` $\rightarrow$ `AI Discovery` $\rightarrow$ `Attack Surface` $\rightarrow$ `Data Flow` $\rightarrow$ `Security Controls` $\rightarrow$ `Risk Scoring` $\rightarrow$ `Readiness Level` $\rightarrow$ `Final Report`

### Key Analytical Pillars

- **Discovery**: Identifies model providers, prompt surfaces, RAG pipelines, and MCP tools. It distinguishes between `Production` code and `Test/Demo` content to avoid noise.
- **Controls**: Scans for 12 specific security controls (Preventive, Validation, Governance). It reports *evidence of a control*, never assuming effectiveness.
- **Risk**: Scores concerns based on a four-factor formula (Exposure $\cdot$ Safety $\cdot$ Security $\cdot$ Likelihood).
- **Readiness**: Measures demonstrated process maturity on a 4-level scale:
    - **Level 1: Baseline** (AI as a feature, essential safeguards).
    - **Level 2: Managed** (Defined, repeatable testing).
    - **Level 3: Hardened** (Security-first, adversarial signals).
    - **Level 4: Continuous** (Automated AI assurance/SRE for models).

---

## 💎 Professional Guarantees

Designed for high-integrity auditing, the tool adheres to strict honesty principles:

- **Deterministic & Offline**: No API keys, no network. Same repo in, same report out.
- **Evidence-First**: Every risk and recommendation traces back to a specific finding ID and line of code.
- **Truncation is loud.** If discovery is truncated on a large repo, the assessment is
  marked `PARTIAL` and the report states plainly that counts are a lower bound — never
  "only N risks."
- **No Manufactured Findings**: If no AI surface is detected, the tool reports exactly that—it does not fabricate "Low Risk" to fill a report.
- **Secret Redaction (defense-in-depth)**: Known credential shapes — provider API
  keys, cloud access keys, JWTs, private-key blocks, `KEY=`/`TOKEN=`/`SECRET=`/`PASSWORD=`
  assignments, and URL-embedded credentials — are replaced with `[REDACTED]` at the
  evidence and serialization boundaries. This reduces exposure but is not a guarantee that
  every possible secret format is caught; treat reports as potentially sensitive and review
  them before sharing.

## Legacy mode: repository mental model

The original orientation report is still available (default mode, no `--security`): a short
"what is this repo and where do I start" map, optionally grounded in an external
code-quality report.

---

## 🛠️ Quick Start

**Prerequisites:** Python 3.10+

```bash
# Terminal summary (Quick read)
python -m vibe_explainer /path/to/repo --security

# Full machine-readable assessment (for automation)
python -m vibe_explainer /path/to/repo --security --json

# Consultant report (Professional deliverable)
python -m vibe_explainer /path/to/repo --security --consultant
```

---

## 🎯 Use Cases

- **Pre-Acquisition Due Diligence**: Quickly assess the AI security maturity of a target company.
- **Internal Governance**: Baseline the security posture of various internal AI agents.
- **Vendor Assessment**: Verify that an AI vendor's "Security" claims map to actual code evidence.
- **Compliance**: Provide a structured starting point for AI security audits.

---

## 📂 Layout
```
vibe_explainer/
  discovery.py   # AI component identification
  surface.py     # Attack surface categorization
  flow.py        # Data-flow analysis
  controls.py    # Control evidence detection
  risk.py        # Risk scenario scoring
  readiness.py   # Readiness level adjudication
  report.py      # Consultant report generation
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
- a 90% branch-coverage gate (currently ~92% across the package).

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
vibe-check                 → what's wrong / triage disposition
vibe-explainer             → here's the map so a human can look productively
Lie Detector               → does the repo do what it claims
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
