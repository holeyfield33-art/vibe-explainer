# Vibe Explainer

License: Apache-2.0.

Vibe Explainer is an offline static AI repository evidence reviewer. It inventories
AI-related source signals, organizes attack-surface leads, records inferred relationships,
looks for security-control artifacts, and produces traceable JSON, terminal, or Markdown
output for analyst validation.

It is a pre-release evidence tool. It is not a vulnerability scanner, penetration test,
compliance assessment, certification, or proof that a control is effective. Current
Python discovery is gated by AST/token structure, while configuration artifacts use
bounded lexical matching. Other-language matches are retained as non-authoritative leads.
Python relationships require bounded AST def-use or direct-import evidence.
Default reports intentionally contain no numeric concern severity or awarded maturity
level.

## Quick start

Python 3.11 through 3.14 is supported and included in the CI matrix.

```bash
# Install the package and console command
python -m pip install .

# Concise terminal evidence review (default)
vibe-explainer /path/to/repo

# Machine-readable evidence and limitations
vibe-explainer /path/to/repo --json

# Detailed Markdown for analyst review
vibe-explainer /path/to/repo --report -o review.md

# Research compatibility only: include uncalibrated legacy scoring
vibe-explainer /path/to/repo --json --experimental-scoring

# Optional mapping to a local Agent Security Index export
vibe-explainer /path/to/repo --json \
  --asi-catalog /path/to/asi-catalog.json
```

Output files are created atomically and are never replaced implicitly. Use `--force`
only when replacing the named destination is intentional.

`--security` and `--consultant` remain accepted as deprecated compatibility aliases.
The original repository-orientation report is available only through
`--legacy-mental-model`; it is not part of the security evidence product.

## What the review contains

- AI/provider, prompt, retrieval, tool/agent, MCP, integration, and credential leads.
- A six-bucket attack-surface inventory with file, line, confidence, and context.
- Static relationship observations with their resolution method and limitations.
- Evidence for twelve security-control categories, separating artifact presence,
  same-function structural enforcement, uncovered surfaces, and unverified runtime
  effectiveness.
- Unscored concern scenarios with evidence class, evidence strength, static reachability,
  and unresolved assumptions.
- An unscored process-evidence checklist. Offline-unverifiable execution, enforcement,
  and effectiveness remain `UNKNOWN` even when an artifact is observed.
- Assessment completeness, truncation, excluded/unreadable-file accounting, and explicit
  lower-bound language when coverage is partial.
- Minimal bounded evidence excerpts plus defense-in-depth redaction. Reports remain
  sensitive; follow [report handling and retention guidance](docs/REPORT-HANDLING.md).
- Optional ASI taxonomy mapping from a pinned local catalog. Applicability, class-specific
  evidence, individual control-to-mitigation signals, unresolved assumptions, and manual
  review are separate axes; protocol compatibility alone never becomes a control gap.
  Catalog version, draft/review status, and source hash appear in every output mode.

## Evidence boundary

The scanner never executes target code and makes no network or LLM calls. All scan stages
share a deterministic symlink-refusing walker. Reads are bounded; non-regular files are
skipped; file-count, byte, and elapsed-time budgets limit hostile or accidental trees.

Known credential shapes are redacted when evidence is created and again at report
boundaries. Secret recognition cannot be complete, so every output must still be treated
as potentially sensitive and reviewed before sharing.

Context classification distinguishes test, security-test, fixture, example,
documentation, generated, configuration, and production-like paths. A production label
may be a conservative default; defaulted counts are visible in every report and require
analyst confirmation.

## Supported and unsupported analysis

Authoritative source-code discovery currently covers common Python imports, calls,
assignments, and decorators. JSON, YAML, TOML, env, cfg, and ini files are treated as
configuration artifacts. JavaScript/TypeScript, Go, Rust, Java, and Ruby matches are
reported as lexical leads and cannot drive risk, control, readiness, data-flow, or ASI
conclusions.

Current limitations:

- Syntax-aware authoritative discovery is currently Python-only; other code languages
  remain lead-only until a parser-backed analyzer is available.
- Structural relationships remain bounded static inference, not runtime flow proof.
- Import-resolved cross-file relationships show reachability, not proven data flow.
- Control discovery begins with named patterns; Python enforcement relationships use
  same-function AST checks but remain incomplete for dynamic/framework wiring.
- Runtime reachability, exploitability, control enforcement, external security processes,
  and deployed configuration are not verified.
- Precision and recall have not yet been established on an independently labelled corpus.

The legacy formula and four-level policy are available only with
`--experimental-scoring`. They are uncalibrated research outputs and must not be used as
vulnerability severity, maturity, certification, or assurance.

The complete release gate and implementation order are in
[docs/LAUNCH-READINESS-PLAN.md](docs/LAUNCH-READINESS-PLAN.md).

## Development

```bash
python -m pytest
python -m coverage run -m pytest
python -m coverage report --fail-under=90
python -m vibe_explainer.validation --output validation/metrics.json --metrics-gate --check
git diff --exit-code -- validation/metrics.json
```

The validation command reproduces the separate detection-quality artifact. See
[docs/VALIDATION.md](docs/VALIDATION.md) for metric definitions and label-review status.

Architecture and historical implementation notes are under `docs/`. `SECURITY.md`
defines the current scanner boundary and sensitive-report handling expectations.

## License

Apache License 2.0; see [LICENSE](LICENSE).
