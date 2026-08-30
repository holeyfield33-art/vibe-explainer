# Security Policy

Vibe Explainer scans repositories that may be untrusted. Report security problems
privately through GitHub's security-advisory interface when disclosure could expose
users or credentials.

## Supported versions

The project is pre-release. Only the current `main` branch receives security fixes
until a packaged release line is established.

## Current scanner boundary

- Analysis is local; the analyzer makes no network or LLM calls.
- File symlinks and non-regular files are skipped.
- Candidate files are read through a bounded no-follow reader.
- Evidence is redacted before serialization, but secret detection is necessarily
  incomplete. Reports must still be handled as potentially sensitive artifacts.
- The target application is never executed.

This is an experimental static evidence reporter, not a vulnerability scanner,
penetration test, compliance certification, or assurance that a repository is secure.
