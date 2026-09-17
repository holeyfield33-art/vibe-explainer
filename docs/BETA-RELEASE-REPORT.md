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
- Expanded full suite, both normal and under coverage: **403 passed, 0 failed, 7 skipped,
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
- Clean-environment qualification of implementation commit
  `79a25f13313c0b5bf44196ebdf096a1fa9706b95`: **33/35 gates passed**, exit 1 solely
  for golden analyst signoff and independent corpus-label review. A subsequent
  documentation-only commit records these results; no engine/test/build changes.
- Fresh checkout, new virtualenv, pinned developer-tool installation: pass.
  Source distribution and wheel built; wheel built from the source distribution.
  Package metadata/content inspection: pass (269 archived paths inspected).
  Clean wheel install without dependencies/index: pass. Isolated installed-module
  import, CLI version/help, terminal, JSON and Markdown smoke checks: pass.
- Full tests: 403 passed / 0 failed / 7 skipped / 50 subtests passed in 48.63s;
  coverage run: identical counts in 46.98s. Seven skips: one POSIX-only FIFO test,
  six tests requiring symlink creation privileges unavailable on this Windows host.
- Complete logs and machine results remain in
  `dist/beta-qualification-verified/{qualification.log,result.json}`;
  real-target JSON/Markdown and run record are under its `large-repos/` directory.
  These generated artifacts are intentionally not versioned.

The first clean-checkout run exposed two line-ending portability issues: raw-byte
golden scope counts, and the existing ASI catalog fixture's pinned byte hash.
Golden operational byte counts are now normalized only for regression comparison,
with an LF/CRLF test. `.gitattributes` preserves that ASI fixture's exact LF bytes;
catalog hash semantics are unchanged. Both failures are resolved in the final run.

## Independent reproduction and files

Branch: `main`. Final HEAD is obtained with `git rev-parse HEAD`; the last commit
only records results. [Complete changed-file list](BETA-CHANGED-FILES.md) identifies
all 63 changed/added files relative to baseline.

From this local checkout, after the three external clones exist:

```powershell
python -u scripts/qualify_clean_environment.py --revision HEAD --large-targets "$env:TEMP/vibe-beta-targets" --output dist/independent-beta-qualification
```

Expected overall exit is **1** until the two review gates are legitimately closed;
inspect per-gate results rather than mistaking that exit for a packaging defect.
To reproduce the exact measured implementation, use
`--revision 79a25f13313c0b5bf44196ebdf096a1fa9706b95`.
Full setup, pinned upstream instructions, individual commands and the conditional
release/tag command sequence are in [RELEASING.md](RELEASING.md).

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
