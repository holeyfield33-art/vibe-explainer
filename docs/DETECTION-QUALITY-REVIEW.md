# Detection quality review

Status: **PENDING_INDEPENDENT_REVIEW**. The implementation team cannot close this
gate on its own. Neither this document nor automated metrics constitute independent
review or evidence of security/control effectiveness.

`validation/beta-freeze.json` pins the unchanged 27-case corpus by canonical SHA-256,
partitions it into positives, negatives and ambiguous cases, and holds five additional
review fixtures with explicit per-signal labels. Reviewable copies live under
`validation/frozen/{positives,negatives,ambiguous}`. Freeze version:
`2026.09.17-beta-1`. No detection rule was tuned after freezing these labels.

Run `python scripts/review_detection.py` to reproduce
`validation/beta-review-metrics.json`. Existing corpus checks remain separately
available via `python -m vibe_explainer.validation --metrics-gate --check`.

The original corpus contains direct/aliased providers, abstraction wrappers,
tool decorators with and without provenance, MCP, retrieval, configuration,
negative/comment examples, incomplete syntax and bounded relationships. Additional
fixtures cover database access, environment credentials, outbound model calls,
tool authorization, human approval, logging, isolation and standalone/developer
prompts. Ambiguous examples remain analyst-review-required; they are not positives
for authoritative conclusions. Supplemental control labels measure observed
artifacts, not enforcement or effectiveness.

## Descriptive results

Original corpus: 27 cases, TP 16, FP 0, FN 1, TN 10; precision **1.0000**,
recall **0.9412**. Python subset: TP 15, FP 0, FN 1, precision 1.0000,
recall 0.9375. Per-construct and per-language metrics are in the machine artifact.

| Supplemental signal | TP | FP | FN | Precision | Recall |
|---|---:|---:|---:|---:|---:|
| Providers | 2 | 0 | 0 | 1.0 | 1.0 |
| Model usage | 2 | 0 | 0 | 1.0 | 1.0 |
| Retrieval | 1 | 0 | 0 | 1.0 | 1.0 |
| Prompts | 1 | 0 | 1 | 1.0 | 0.5 |
| Credentials | 1 | 0 | 0 | 1.0 | 1.0 |
| Tools | 1 | 0 | 0 | 1.0 | 1.0 |
| MCP | 1 | 0 | 0 | 1.0 | 1.0 |
| Database integration | 1 | 0 | 0 | 1.0 | 1.0 |
| C05 authorization artifact | 1 | 0 | 0 | 1.0 | 1.0 |
| C06 approval artifact | 1 | 0 | 0 | 1.0 | 1.0 |
| C07 logging artifact | 1 | 0 | 0 | 1.0 | 1.0 |
| C12 isolation/action artifact | 1 | 0 | 0 | 1.0 | 1.0 |

Each supplemental signal also has one labelled true negative. Unlabelled signals
are not treated as negatives. These samples are far too small and too closely
related to existing regression cases for statistical/generalization claims.
There is no statistical confidence estimate or combined security accuracy score.

## Error analysis

| Fixture | Expected | Observed | Error/root cause | Disposition | Fixed | Residual limitation |
|---|---|---|---|---|---|---|
| py_obfuscated_import | Authoritative provider evidence | No finding | FN: dynamic import string construction outside supported patterns | Published known miss; independent reviewer must accept/reject | No | Dynamic/obfuscated providers may be missed |
| prompt_file_and_developer_role | Prompt evidence | No authoritative prompt finding | FN: text prompt files and quoted developer-role dictionaries are outside current patterns | Retain frozen positive; document, do not tune on evaluation | No | Analysts must inspect standalone/developer prompts manually |
| misleading_name | No authoritative signals | No authoritative signals | No false trigger | Retain negative | N/A | One negative cannot establish broad precision |
| Ambiguous partition | Non-authoritative lead/unresolved | Matches labels | No mandatory mismatch | Analyst review required | N/A | Unsupported language/structure cannot support conclusions |

## Independent review handoff

An independent reviewer who did not implement the detector must inspect frozen
sources and labels without using detector output as ground truth; record stable
identity, date, reviewed version/commit and disputes. Resolve label disputes in a
new version without silently replacing this evaluation. Review the two known
misses and sample adequacy, then record acceptance/rejection. Do not flip the
existing corpus's label-review status until that review actually occurs.

Detector accuracy concerns whether observable evidence was classified correctly.
Control effectiveness requires runtime/operational validation unavailable here.
Vibe Explainer does not establish that a vulnerability exists, that a control is
effective, or that a system is compliant.
