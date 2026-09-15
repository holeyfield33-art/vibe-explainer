# Vibe Explainer

Vibe Explainer is an offline static AI repository evidence reviewer. It inventories
AI-related source signals, organizes attack-surface leads, records inferred relationships,
looks for security-control artifacts, and produces traceable JSON, terminal, or Markdown
output for analyst validation.

It is a pre-release evidence tool. It is not a vulnerability scanner, penetration test,
compliance assessment, certification, or proof that a control is effective. Current
discovery is primarily regex-based, relationships include proximity/import heuristics,
and numeric concern scores and process-evidence levels are uncalibrated experimental
policy outputs.

## Quick start

Python 3.11 or 3.12 is currently tested in CI.

```bash
# Concise terminal evidence review (default)
python -m vibe_explainer /path/to/repo

# Machine-readable evidence and limitations
python -m vibe_explainer /path/to/repo --json

# Detailed Markdown for analyst review
python -m vibe_explainer /path/to/repo --report -o review.md

# Optional mapping to a local Agent Security Index export
python -m vibe_explainer /path/to/repo --json \
  --asi-catalog /path/to/asi-catalog.json
```

`--security` and `--consultant` remain accepted as deprecated compatibility aliases.
The original repository-orientation report is available only through
`--legacy-mental-model`; it is not part of the security evidence product.

## What the review contains

- AI/provider, prompt, retrieval, tool/agent, MCP, integration, and credential leads.
- A six-bucket attack-surface inventory with file, line, confidence, and context.
- Static relationship observations with their resolution method and limitations.
- Evidence for twelve security-control categories. `DETECTED` means evidence was found,
  not that enforcement or effectiveness was verified.
- Deterministic concern scenarios and process signals. Their current scores, severities,
  and levels are experimental and not empirically calibrated.
- Assessment completeness, truncation, excluded/unreadable-file accounting, and explicit
  lower-bound language when coverage is partial.
- Optional ASI taxonomy mapping from a pinned local catalog. The mapping does not detect
  attacks or validate ASI mitigations, and the catalog's draft/review status matters.

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

The strongest current detection coverage is for common Python and JavaScript/TypeScript
AI idioms. Other listed extensions receive lexical scanning with uneven coverage.

Current limitations:

- General discovery is not yet syntax-aware across supported languages.
- Same-file relationships may be line-proximity associations rather than def-use flow.
- Import-resolved cross-file relationships show reachability, not proven data flow.
- Control evidence is mainly keyword, path, header, and proximity based.
- Runtime reachability, exploitability, control enforcement, external security processes,
  and deployed configuration are not verified.
- Precision and recall have not yet been established on an independently labelled corpus.

The complete release gate and implementation order are in
[docs/LAUNCH-READINESS-PLAN.md](docs/LAUNCH-READINESS-PLAN.md).

## Development

```bash
python -m pytest
python -m coverage run -m pytest
python -m coverage report --fail-under=90
```

Architecture and historical implementation notes are under `docs/`. `SECURITY.md`
defines the current scanner boundary and sensitive-report handling expectations.

## License

Apache License 2.0; see [LICENSE](LICENSE).
