# Changelog

All notable changes to Vibe Explainer are recorded here. The project currently
uses pre-release versioning while its security evidence model is being hardened.

## Unreleased

### Security

- Refuse file symlinks and non-regular filesystem entries during content and
  readiness scans, preventing out-of-repository reads and FIFO/device blocking.
- Use bounded, no-follow file opens where the host platform supports them.
- Stream readiness paths instead of retaining the full repository path list.
- Redact sensitive assignments, credential-bearing URLs, private keys, JWTs,
  and common provider token formats before evidence reaches report layers.
- Retain defense-in-depth redaction at JSON, text, and consultant-report boundaries.

### Tests

- Add adversarial coverage for external file symlinks, FIFOs, readiness-evidence
  manipulation through symlinks, unknown-format secret assignments, URLs, and
  common credential formats.
- Enforce at least 90% branch coverage for the package. Current measured package
  coverage is 94% with 208 tests.

### Known limitations

- Static discovery remains regex-based and context-blind.
- Data-flow edges remain same-file proximity inferences.
- Risk severity and readiness levels have not been empirically calibrated.
- Scan-wide file, byte, depth, and elapsed-time budgets are not implemented yet.
