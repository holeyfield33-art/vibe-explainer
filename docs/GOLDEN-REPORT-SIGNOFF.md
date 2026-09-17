# Golden analyst report signoff

Status: PENDING_ANALYST_APPROVAL

Candidate: [beta-golden.md](../examples/sample-assessment/beta-golden.md).
Fixture: `examples/analyst-review-fixture`; its canonical content SHA-256 is
printed in the candidate. `python scripts/golden_report.py` compares the entire
Markdown output, with only elapsed time, raw byte count (line-ending dependent), local path, date and Git identity
normalized. Fixture content identity is retained; unavailable Git identity is
explicit, never fabricated. Runtime reports contain actual revision metadata.

- [x] Executive summary, scope, provenance and completeness present.
- [x] AI inventory: providers, prompts, retrieval, tools, agents, MCP and credentials.
- [x] Inferred relationships, surface leads, controls and concern scenarios present.
- [x] Evidence paths/locations and references visible.
- [x] Limitations and analyst actions present; scope limitation appears near the top.
- [x] Factual consistency mechanically checked against assembled evidence.
- [x] Complete rendered regression comparison passes.
- [x] Redaction and default absence of severity/numeric process awards tested.
- [x] No assertion of exploitability, runtime effectiveness or compliance.
- [ ] Independent analyst checks every evidence reference and factual statement.
- [ ] Technical-buyer language accepted by the analyst.
- [ ] Analyst confirms usefulness for a client engagement.
- [ ] Analyst accepts visible limitations and residual unsupported constructs.
- [ ] Named analyst signs the exact output hash and fixture hash.

Reviewer: pending
Review date: pending
Approved output SHA-256: pending

No analyst signature has been supplied; implementation authors do not self-sign
this gate. The frozen candidate is a regression artifact, **not an approved client
deliverable**. Approval requires a named reviewer, date, exact hashes and completed
checklist. Changes to the fixture, renderer or analytical content invalidate it.

Deliberate update after reviewing the diff:
`python scripts/golden_report.py --write`; rerun tests and obtain new signoff.
