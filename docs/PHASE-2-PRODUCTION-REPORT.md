# Phase 2 production report contract

Status: implementation candidate. This milestone creates a verifiable **analyst review packet**, not an approved customer assessment or a product release. The historical `PHASE-2-REVIEW.md` describes an earlier data-model phase and is separate from this production work.

## Packet workflow

Run one bounded scan and create an unsigned ZIP in an approved customer workspace:

```powershell
vibe-explainer PATH_TO_CUSTOMER_REPO --review-packet PATH_TO_PRIVATE_WORKSPACE/review-candidate.zip
python scripts/verify_review_packet.py PATH_TO_PRIVATE_WORKSPACE/review-candidate.zip
```

The ZIP contains `evidence.json`, `review.md`, `manifest.json`, and `analyst-checklist.md`. JSON and Markdown come from the **same in-memory assessment**. The manifest records their byte counts and SHA-256 hashes, engine/schema version, repository revision and dirty state, scan settings, completeness, scope, evidence counts, and ASI catalog identity if supplied. Verification checks the exact member set, file hashes, review status, and agreement between the manifest and JSON assessment identity. Existing output is preserved unless `--force` is explicitly given. Review packets reject experimental scoring and cannot be combined with single-output or legacy modes.
The packet JSON omits the analyst workstation's absolute repository path; repository name, source revision and scope remain recorded.

The Markdown begins with **UNREVIEWED CANDIDATE**. The manifest always records `PENDING_ANALYST_REVIEW` and `customer_delivery_approved: false`. The checklist is a template, not a signature. Verification proves only packet integrity and internal consistency; it cannot validate the scanned source, detection accuracy, analyst identity, customer authorization, or security effectiveness.

Before any customer delivery, a named analyst must independently check source scope and commit, dirty state, exclusions, completeness, finding and relationship references, control evidence, unresolved assumptions, ASI catalog status, report wording, and sensitive excerpts. Record reviewer identity, date, decisions, exact evidence/Markdown hashes, and the approved customer scope in a separate signed review record. A changed packet requires a new review. Independent detection-quality review, golden-report signoff, CI/CodeQL, packaging, and the other gates in `LAUNCH-READINESS-PLAN.md` remain open; this packet does not close them.

Generated packets are potentially sensitive. Keep them in an approved private workspace, apply the customer's retention policy, and do not attach them to public issues or PRs.
