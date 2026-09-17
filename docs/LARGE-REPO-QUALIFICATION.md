# Large repository qualification

This evaluates **Vibe Explainer's termination and artifacts**, not the security
posture of these projects. No finding count is a claim that a project is insecure.

Initial successful Windows/Python 3.14.6 run, 2026-09-17, with `--max-seconds 2`.
JSON and Markdown are separate scans and may stop at different checkpoints.
All six processes exited 0 without watchdog intervention and produced parseable
JSON or structured Markdown. Numbers below describe the JSON scans only.

| Repository | Upstream SHA | Discovered | Inspected | Analysis / process seconds | State | Budget reason | AI items | Surface leads | Control observations | Artifact prefix | Errors/warnings |
|---|---|---:|---:|---|---|---|---:|---:|---:|---|---|
| openai/openai-python | b77076d23b6f3e34453b0fadd8cd2a001627e365 | 125 | 69 | 2.085326 / 4.177 | PARTIAL | time budget (2.0s) reached | 187 | 187 | 13 | `%TEMP%/vibe-beta-large/openai-python` | No errors; oversized OpenAPI file skipped |
| langchain-ai/langgraph | 230927fb3a9ac9b2893a30322b4dfea7cdea9a8f | 100 | 42 | 2.013947 / 3.289 | PARTIAL | time budget (2.0s) reached | 9 | 9 | 0 | `%TEMP%/vibe-beta-large/langgraph` | No errors; partial scope |
| BerriAI/litellm | 4b368bf0669cfd3268b780eea6c69497b9a51850 | 50 | 15 | 2.020839 / 4.612 | PARTIAL | time budget (2.0s) reached | 22 | 22 | 0 | `%TEMP%/vibe-beta-large/litellm` | No errors; partial scope |

Each prefix has `.json` and `.md` files. The full machine-readable run record is
`%TEMP%/vibe-beta-large/qualification.json`. Clean-environment reruns preserve
their artifacts and exact counts under the requested output directory's
`large-repos/`; timing-dependent scope is not expected to equal this table.

```powershell
python scripts/qualify_large_repos.py --targets "$env:TEMP/vibe-beta-targets" --output "$env:TEMP/vibe-beta-large" --max-seconds 2
```

The harness accepts existing clones; it does not execute setup files, install
target dependencies or import target modules. A child Python audit hook refuses
execution of code whose filename resolves inside the target and permits only
hardened Git provenance subprocesses. Git filesystem-monitor hooks are disabled.
The worker runs in isolated Python mode with only the trusted engine source added.
The scanner's centralized walker prunes excluded trees and directory symlinks;
regular-file reads reject symlinks/outside-root paths. Evidence locations must be
relative without parent traversal. Existing adversarial tests and the new marker
test cover non-execution; symlink tests are skipped where Windows lacks privileges.

Report assertions check provenance SHA, completeness, budget reason, discovered /
inspected / skipped / byte counts, relative paths and redaction idempotence for
recognized secret patterns. Planted-secret regression tests independently test
redaction. These checks do not guarantee recognition of every possible secret
format. Output must be handled as sensitive repository-derived material.

The first harness attempt failed because Windows supplies the subprocess audit
argument as a command-line string; the guard originally expected a list. The
cross-platform guard was corrected before the successful run. No target execution
occurred and this was not a scanner failure.

Limitations: cooperative time checks cannot preempt a single filesystem/AST/regex
operation; assembly and provenance take extra wall time. A 30-second extra watchdog
is a **failure guard**, never an accepted partial result. Discovered counts cover
visited directories only, and inspected means content read, not all stages done.
Trees must remain immutable during review; no race-proof filesystem isolation is
claimed. Analysts must not interpret omitted evidence as absence.
