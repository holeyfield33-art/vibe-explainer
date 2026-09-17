# Beta release baseline

Recorded before implementation, 2026-09-17.

- Remote: https://github.com/holeyfield33-art/vibe-explainer.git
- Branch: main; clean tracked/untracked status.
- HEAD and freshly fetched origin/main: `4eeee896e65252399645b7ec5c71dd43dfc575c0`.
- Windows, Python 3.14.6, package 0.2.0a1; pytest 9.1.1,
  coverage 7.16.1, build 1.6.1, setuptools 84.0.0.
- Initial full suite: 386 passed, 1 failed, 6 skipped, 50 subtests passed.
  Failure: TestBuiltArtifacts.test_wheel_and_sdist_metadata_and_contents,
  build subprocess exit 1 while qualification was building in the same checkout.
  No code changed: standalone sdist/wheel build succeeded; isolated test retry
  passed (1 passed). Qualification's full suite and coverage suite also passed.
  Treat the initial failure as build contention, not a demonstrated product defect.
  Subsequent builds/tests must be serialized.
- Product-boundary check: pass.
- Corpus metric and exact-label gates: pass; known obfuscated-import false negative.
  27 cases: TP 16, FP 0, FN 1, TN 10; precision 1.0, recall 0.9412.
- Sample Markdown generation: pass, temporary `vibe-baseline-report.md`.
- Release qualification: 28/29 passed, exit 1. Only blocker:
  independent corpus-label review is PENDING_INDEPENDENT_REVIEW.
- Clean build/install, installed CLI, JSON/Markdown, redaction and >=90% branch
  coverage gates passed in that qualification. No missing developer tooling.

Known limitations: labels prepared alongside implementation; golden analyst
approval not recorded; discovery budgets do not cover later repository scans;
no demonstrated self-terminated large-repository artifacts. Python structural
evidence and lexical configuration are supported; other languages are leads.
No evidence establishes exploitability, control effectiveness or compliance.

Commands: `python -m pytest -q`, `python scripts/check_product_boundary.py`,
`python scripts/qualify_release.py`,
`python -m vibe_explainer.validation --output <temp>/metrics.json --metrics-gate --check`,
`python -m vibe_explainer examples/analyst-review-fixture --report --out <temp>/report.md`.
