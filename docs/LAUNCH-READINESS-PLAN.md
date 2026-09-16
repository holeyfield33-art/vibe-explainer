# Launch Readiness Plan

Status: **NO-GO for an unreviewed automated security audit.** The current product may
be offered only as an analyst-reviewed beta static repository evidence review until
the launch gates at the end of this document pass.

## Execution checklist

- [x] **1. Establish one honest product boundary**
  Issue refs: `#12`
  What to build: Choose one product name, separate or remove legacy mental-model mode,
  and replace certification-like, consultant-grade, standards-aligned, and maturity
  claims with evidence-review language.
  Acceptance: README, SPEC, CLI help, JSON, terminal output, and Markdown describe the
  same supported capabilities and non-capabilities.
  Verify: `rg -n "consultant-grade|industry-standard|certif|prove|guarantee|maturity" README.md SPEC.md vibe_explainer docs`

- [x] **2. Suspend uncalibrated scores and readiness awards by default**
  Issue refs: `#6`, `#8`
  What to build: Make the default report an unscored concern and process-evidence
  checklist. Retain legacy scoring only behind an explicit experimental flag, if at all.
  Parse CI structure, reject inert tests/workflows, and exclude generated/active output.
  Acceptance: Default output contains no numeric severity or awarded maturity level;
  inert artifacts cannot improve process evidence.
  Verify: adversarial readiness fixtures plus CLI golden-output tests.

- [x] **3. Redesign the ASI mapping as separate evidence axes**
  Issue refs: `#32`; related to `#6`, `#7`, `#8`
  What to build: Report applicability basis, class-specific evidence, mitigation evidence,
  unresolved assumptions, and manual-review status separately. Remove best-control
  aggregation and never emit `CONTROL_GAP` from protocol compatibility alone. Surface
  catalog draft/review status and include row-level mapping in the consultant report.
  Acceptance: A basic chatbot does not acquire unrelated filesystem, sandbox, rogue-agent,
  or prompt-extraction gaps without class-specific evidence. Conflicting mapped controls
  remain visible and cannot mask one another.
  Verify: golden tests against the pinned 40-class ASI export and negative fixtures for
  Native, MCP, RAG, A2A, ANP, and Skills applicability.

- [ ] **4. Build syntax-aware discovery**
  Issue refs: `#4`
  What to build: Use Python AST/tokenize for imports, calls, assignments, aliases,
  comments, and strings. Keep unsupported-language lexical leads separate from
  structurally established findings and publish coverage boundaries.
  Acceptance: Commented/string calls do not become executable findings; aliased imports
  and common wrappers are covered; unsupported leads cannot drive conclusions.
  Verify: labelled corpus metrics meet at least 90% precision for high-confidence Python
  findings, with recall and unresolved rates published.

- [x] **5. Replace proximity with bounded structural relationships**
  Issue refs: `#5`
  What to build: Add Python intra-procedural def-use and direct local import/re-export
  resolution. Rename legacy edges to proximity associations and prevent them from driving
  concern severity.
  Acceptance: Relationships require shared value/symbol evidence and preserve explicit
  unresolved reasons; nearby unrelated calls never form a flow.
  Verify: positive and negative prompt-to-model, retrieval-to-model, model-to-tool, sink,
  and two-file import fixtures.

- [x] **6. Make control evidence structural**
  Issue refs: `#7`
  What to build: Separate artifact presence, structural enforcement, and effectiveness
  not verified. Require same-function or resolved-call relationships and consumption of
  guard results before protected operations.
  Acceptance: Dead code, unused/late/unconditional guards, environment variables, and
  documentation headers cannot establish enforcement.
  Verify: adversarial negative cases for all twelve controls.

- [x] **7. Minimize and govern captured evidence**
  Issue refs: `#13`
  What to build: Store minimal sanitized match excerpts, maintain positive/benign secret
  corpora, unify report/error redaction boundaries, and document retention and handling.
  Acceptance: No serialization path bypasses the shared redactor; traceability survives
  excerpt minimization; reports remain explicitly classified as potentially sensitive.
  Verify: credential corpus, exception-path tests, and snapshot scans for planted secrets.

- [ ] **8. Publish detection-quality metrics**
  Issue refs: `#11`
  What to build: Create independently reviewed labelled positive/negative cases, including
  pinned license-compatible real-world samples. Separate regression coverage from detector
  quality.
  Acceptance: Per-language and per-construct precision, recall, unsupported, and unresolved
  rates reproduce offline and appear in release notes.
  Verify: one documented metrics command reproduces the checked-in release artifact.

- [x] **9. Add packaging, provenance, and safe output**
  Issue refs: `#10`
  What to build: Add PEP 621 packaging and console entry point, one version source, schema
  compatibility policy, atomic non-overwriting writes, output exclusion, and stable evidence
  identity. Record repository commit, dirty state, branch, scan configuration, exclusions,
  and ASI catalog hash/status in reports.
  Acceptance: Clean build/install/CLI/uninstall passes; existing files are not silently
  overwritten; reports are reproducible from recorded provenance.
  Verify: package smoke workflow across every documented Python version.

- [ ] **10. Run the release qualification gate**
  Issue refs: `#33` and all remaining launch-blocking issues
  What to build: Generate reviewed golden JSON and Markdown reports for no-AI, chatbot,
  RAG, tool-agent, MCP, mixed-context monorepo, incomplete scan, and hostile filesystem
  cases. Remove synthetic client-looking artifacts from release inputs.
  Acceptance: All gates below pass and an analyst signs off every golden report conclusion.
  Verify: release workflow plus documented manual review record.

## Launch gates

Launch is **GO** only when all of the following are true:

- All high- and medium-severity honesty/security issues are closed with regression tests.
- CI and CodeQL are green on the release commit; no job is skipped due to account/billing.
- Package build, clean install, CLI smoke, and uninstall pass on every supported Python version.
- Published corpus metrics meet the documented high-confidence precision target and disclose recall.
- No default report presents uncalibrated numeric severity, awarded maturity, or protocol-only ASI gaps.
- ASI draft and independent-review status are prominent wherever ASI mapping appears.
- Every report records source commit, dirty state, configuration, exclusions, completeness,
  engine/schema version, and catalog hash/version.
- Golden reports pass manual evidence-to-conclusion review and secret-leak review.
- The release contains no synthetic report that could be mistaken for a real client assessment.
