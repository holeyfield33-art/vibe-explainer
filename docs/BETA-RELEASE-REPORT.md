# Beta release report

Verdict: **NO-GO** for Analyst-Assisted Beta.

The technical candidate adds shared scan budgets, usable partial artifacts,
real-repository qualification, frozen review inputs and reproducible packaging.
Version remains **0.2.0a1**. No release tag, publication, push or merge is authorized
or performed. This is an offline deterministic evidence-review engine, not an
autonomous auditor, vulnerability scanner or assurance/certification tool.

## Mandatory blockers

1. Independent detection-quality review is not complete. Frozen labels and metrics
   are implementation-authored; a reviewer independent of detector implementation
   must review and record acceptance, identity, date and exact version/commit.
2. The golden client-facing candidate has no named analyst signoff. Automated
   regression and boundary checks do not approve buyer-facing usefulness or wording.

## Technical results

- Baseline: main at `4eeee896e65252399645b7ec5c71dd43dfc575c0`, clean and matching
  origin/main; details in BETA-RELEASE-BASELINE.md.
- Expanded full suite under coverage: **402 passed, 0 failed, 7 skipped,
  50 subtests passed**; branch-inclusive coverage **91%**.
- Product-boundary check: pass. Existing safety/redaction/ASI tests retained.
- Time/file/byte partial JSON and Markdown tests: pass; controlled time advances
  verify retained evidence and PARTIAL status. Atomic publication failure preserves
  the previous valid artifact; no-overwrite and exit semantics are tested.
- All three real targets emitted JSON/Markdown and self-terminated under configured
  time budgets: **3/3 repository qualifications passed, 6/6 scan processes exited 0**.
  See LARGE-REPO-QUALIFICATION.md for SHAs, counts, times and artifacts.
- Frozen original corpus: **TP 16, FP 0, FN 1, TN 10; precision 1.0000,
  recall 0.9412**. Supplemental per-signal metrics and error analysis are in
  DETECTION-QUALITY-REVIEW.md. Small samples do not support statistical claims.
- Complete golden candidate compares exactly; analyst approval remains pending.
- Clean-environment qualification: final run result will be appended after the
  committed candidate is exercised. Packaging is not declared qualified on the
  strength of source-checkout tests alone.

## Residual limitations and scope

Known misses: obfuscated imports and standalone/developer-role prompt constructions.
Other languages are non-authoritative lexical leads. No runtime control effectiveness,
exploitability or compliance is established. Time budgets are cooperative rather
than hard preemption; sorted traversal is deterministic but time-limited scope depends
on machine load. Scope counters are lower bounds, not numeric assurance scores.
Targets must remain immutable. Symlink-privilege/platform skips and a single tested
Python/Windows environment do not replace required multi-version CI/CodeQL checks.
No known Critical/High target-execution or product-boundary defect was identified
in the performed checks; that is not a comprehensive security assurance claim.

No version bump is proposed for this NO-GO. Conditional next version after all gates
and CI pass: `0.2.0b1`, maximum posture **Analyst-Assisted Beta**.

Exact commands and the proposed, **unexecuted** tag/push sequence are in
RELEASING.md. Use `scripts/qualify_clean_environment.py` on the exact committed
candidate to independently reproduce tests, package builds/install, installed CLI,
corpus, boundary, golden comparison and large-repository checks.
