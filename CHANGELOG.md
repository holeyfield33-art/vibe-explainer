# Changelog

All notable changes to Vibe Explainer are recorded here. The project currently
uses pre-release versioning while its security evidence model is being hardened.

## Unreleased

### Security

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

- Static discovery remains regex-based and context-blind.
- Data-flow edges remain same-file proximity inferences.
- Risk severity and readiness levels have not been empirically calibrated.
