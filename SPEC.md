# Vibe Explainer Product Specification

## Product boundary

Vibe Explainer is an offline static AI repository evidence reviewer. Its product output
is a traceable set of evidence leads and explicit limitations for a human analyst. The
legacy repository-orientation report is deprecated and available only through
`--legacy-mental-model`.

Vibe Explainer does not claim vulnerability discovery, exploitability, runtime
reachability, control effectiveness, compliance, certification, or organizational
security maturity.

## Users and jobs

- A security analyst needs a bounded first pass over an AI-integrated repository.
- An engineering team needs an inventory of AI-related code and unresolved review areas.
- A governance team needs machine-readable evidence references without treating absence
  of repository evidence as proof that a control does not exist.

## Inputs

- A local repository path.
- Optional local Agent Security Index catalog export.
- Output selection: terminal summary, JSON, or detailed Markdown.

The reviewer does not fetch catalogs, call an LLM, or execute target code.

## Outputs

Every output exposes the applicable subset of:

1. Engine and schema identity.
2. Repository identity and assessment completeness.
3. AI evidence inventory with file, line, category, confidence, context, and stable ID.
4. Attack-surface leads derived from inventory evidence.
5. Static relationship observations with resolution method.
6. Security-control artifact evidence and explicit status semantics.
7. Concern scenarios and their underlying assumptions.
8. An unscored process-evidence checklist separating observed artifacts from unknown
   enforcement and effectiveness.
9. Recommendations linked to evidence IDs.
10. Limitations, coverage gaps, aggregation counts, and unsupported analysis.
11. Optional ASI mapping with catalog provenance and mapping limitations.

All advertised JSON fields must be serialized. Human-readable output may summarize but
must preserve references to the complete machine-readable evidence.

## Required honesty semantics

- `DETECTED` or `EVIDENCE_FOUND` means repository evidence was observed; it never means a
  control was proven effective.
- `NOT_DETECTED` means no supporting evidence was found within assessed coverage; it never
  means a control does not exist.
- `NOT_APPLICABLE` requires absence of the relevant supported surface, not merely weak
  confidence.
- `UNKNOWN` is used when coverage or offline verification cannot support a conclusion.
- `PARTIAL` completeness makes every count a lower bound.
- `AGGREGATED` means all matches were counted but repetitive evidence was summarized.
- Production context reached through fallback must be distinguished from positively
  classified context.
- Unsupported-language lexical leads cannot drive authoritative conclusions.

Numeric scores, severity bands, and four-level process classifications are absent from
default output. They remain available only through `--experimental-scoring` for research
compatibility until independently reviewed calibration exists.

## Untrusted-repository boundary

- One shared walker owns directory exclusions, symlink refusal, and deterministic order.
- Final-component reads refuse symlinks and non-regular files.
- Per-file, file-count, total-byte, and elapsed-time budgets are enforced.
- Skips, unreadable files, and budget exhaustion affect completeness explicitly.
- Target code is never imported or executed.
- Evidence is minimized and redacted at construction and serialization boundaries.
- Reports remain potentially sensitive even after redaction.

## CLI contract

```text
vibe-explainer REPO                         terminal evidence review
vibe-explainer REPO --json                  complete machine-readable review
vibe-explainer REPO --report -o FILE        detailed analyst-review Markdown
vibe-explainer REPO --asi-catalog PATH      add local ASI mapping
vibe-explainer REPO --experimental-scoring  opt into uncalibrated legacy policy output
vibe-explainer REPO --legacy-mental-model   deprecated orientation report
```

`--security` and `--consultant` are deprecated compatibility aliases during the
pre-release line. `--offline` is removed because all supported review behavior is offline.

## Release criteria

The authoritative implementation sequence and GO/NO-GO gates are maintained in
`docs/LAUNCH-READINESS-PLAN.md`. Until those gates pass, detailed reports require analyst
validation and the product must not be sold as an automated audit or certification.
