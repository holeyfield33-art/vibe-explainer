# Security Policy

Vibe Explainer scans repositories that may be untrusted. Report security problems
privately through GitHub's security-advisory interface when disclosure could expose
users or credentials.

## Supported versions

The project is pre-release. Only the current `main` branch receives security fixes
until a packaged release line is established.

## Current scanner boundary

- Analysis is local; the analyzer makes no network or LLM calls.
- File and directory symlinks and non-regular files are skipped. Every scan
  stage traverses through one shared walker, so this holds uniformly rather
  than only on the stages that happened to implement it.
- Size and type checks use `lstat` and an explicit regular-file test, so a
  symlink's metadata is never resolved by following it.
- Candidate files are read through a bounded no-follow reader.
- Discovery enforces global file-count, total-byte, and elapsed-time budgets,
  so a large or adversarial tree cannot exhaust the scanning host.
- Evidence is redacted where it is constructed and again before serialization,
  but secret detection is necessarily incomplete. Reports must still be handled
  as potentially sensitive artifacts.
- The target application is never executed.

## Residual gaps

These are known and not yet closed. They affect assessment accuracy, not the
integrity of the scanning host:

- File-context classification is largely path-based and defaults unknown code
  to `PRODUCTION`. Mixed trees (monorepos, `app/test_utils/`, examples that are
  the real entrypoint) can be mis-labeled. Reports distinguish path-confirmed
  contexts from defaulted ones so this is visible rather than implied.
- Scanning this repository with itself is not a meaningful readiness signal:
  the tool's own test fixtures contain the very CI/security-test/doc patterns
  the readiness scan looks for. Self-scan readiness levels are excluded from
  process-signal evidence and must not be cited as a readiness proof.

This is an experimental static evidence reporter, not a vulnerability scanner,
penetration test, compliance certification, or assurance that a repository is secure.
