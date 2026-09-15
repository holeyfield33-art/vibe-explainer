# Changelog

All notable changes to Vibe Explainer are recorded here. The project currently
uses pre-release versioning while its security evidence model is being hardened.

## Unreleased

### Security

- Replace the ASI mapper's single precedence status with independent applicability,
  class-evidence, per-control mitigation, unresolved-assumption, and manual-review axes.
  Protocol compatibility can no longer manufacture `CONTROL_GAP`, and conflicting
  mapped controls remain visible instead of being collapsed to a best status.
- Add ASI schema 2.0 catalog provenance: version, draft status, independent-review state,
  and SHA-256 source identity. Detailed Markdown now contains all row mappings, while
  terminal and JSON output prominently disclose the catalog review state.
- Pin a reduced 40-class ASI test export and cover positive/negative applicability for
  Native, MCP, RAG, A2A, ANP, and Skills.
- Remove numeric scores, severity bands, and awarded readiness levels from default
  terminal, JSON, Markdown, and ASI output. Default concerns now expose evidence class,
  evidence strength, static reachability, and unresolved assumptions; process artifacts
  are an unscored checklist with enforcement fixed to `UNKNOWN` for offline review.
- Retain the legacy formula and four-level policy only behind
  `--experimental-scoring`, with explicit uncalibrated-research warnings.
- Require nontrivial executable assertions for security-test process evidence; require CI
  commands to reference existing test paths without obvious failure suppression; reject
  empty evidence files; and exclude generated reports and the active output destination.
- Consolidate the product identity on **Vibe Explainer**, make the static AI repository
  evidence review the default CLI behavior, move the deprecated orientation report behind
  `--legacy-mental-model`, and remove the dead `--offline` flag.
- Replace client-ready/assurance language in README, SPEC, CLI help, and detailed Markdown
  with explicit analyst-validation, heuristic-evidence, and non-certification boundaries.
- Add `--report` as the primary detailed Markdown flag; retain `--security` and
  `--consultant` only as deprecated compatibility aliases during the pre-release line.
- Exclude planted `tests/` and `examples/` evidence during self-scan readiness
  evaluation, label self-scans explicitly, and prevent self-assessment from being
  cited as meaningful readiness evidence.
- Distinguish production context inferred by conservative default from positively
  classified context in findings, JSON, the executive summary, and consultant output.
- Add test-framework import signals for test files whose paths do not identify them
  as tests.
- Refuse file symlinks and non-regular filesystem entries during content and
  readiness scans, preventing out-of-repository reads and FIFO/device blocking.
- Refuse **directory** symlinks too: every walker-touching stage (discovery,
  controls, readiness, the structural scanner, the coverage crawl) now shares
  one centralized, symlink-safe walker (`exclusion_policy.walk_pruned`) instead
  of five independently-maintained `os.walk` loops, one of which had drifted to
  miss several excluded directories.
- Fix a directory-name exclusion bug where a `.git`-prefix check also silently
  hid `.github` from every scan; exclusion is now exact-name only.
- Use bounded, no-follow file opens where the host platform supports them.
- Stream readiness paths instead of retaining the full repository path list.
- Redact sensitive assignments, credential-bearing URLs, private keys, JWTs,
  and common provider token formats before evidence reaches report layers.
- Retain defense-in-depth redaction at JSON, text, and consultant-report boundaries.
- Redact control and data-flow evidence at the point each is constructed, not
  only at the final report boundary — a control pattern matching a line that
  also contains a live secret no longer carries that secret into intermediate
  evidence objects.
- Enforce global scan budgets (file count, total bytes, and elapsed time)
  during discovery, so a hostile or accidental tree of many small files can no
  longer exhaust memory or time on the scan host. Hitting a budget stops the
  walk and is reported, rather than silently truncating.
- Track *why* a candidate file was never examined (too large vs. unreadable)
  and force `assessment_completeness = PARTIAL` — with explicit lower-bound
  language in every report surface — whenever a real coverage gap occurred,
  distinct from the "everything counted, just summarized" AGGREGATED case.

### Tests

- Make symlink safety tests skip cleanly on Windows hosts that do not grant symlink
  creation privileges, while retaining the safety assertions on capable hosts.
- Add adversarial coverage for external file symlinks, FIFOs, readiness-evidence
  manipulation through symlinks, unknown-format secret assignments, URLs, and
  common credential formats.
- Add regression coverage for directory-symlink pruning and `.git`/`.github`
  exclusion, secret redaction on control-matching lines and in data-flow
  evidence, and scan-budget enforcement (oversized files, unreadable files,
  file-count budget exhaustion).
- Enforce at least 90% branch coverage for the package. Current measured package
  coverage is 94% with 208 tests.

### Known limitations

- Static discovery remains primarily regex-based; file context is heuristic and
  conservative-default production classifications require analyst review.
- Data-flow edges remain same-file proximity inferences.
- Risk severity and readiness levels have not been empirically calibrated.
