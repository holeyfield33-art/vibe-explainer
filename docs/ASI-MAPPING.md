# Agent Security Index Mapping

## Stable offline compatibility seam

Report schema `2.0` and ASI schema `2.0` remain separate. Consumers use the
assessment manifest (engine version, repository revision, scan configuration,
completeness), occurrence-based finding IDs, relative paths/lines, evidence basis,
context and `supports_conclusions`. Control artifact/enforcement/effectiveness
axes must remain independent. Partial reports retain IDs but carry reduced scope.

Future adapters may attach optional local taxonomy references keyed by evidence ID:
taxonomy name/version, identifier (ASI class, CWE, CAPEC, OWASP, CVE/incident or
mitigation), mapping rationale, evidence references and analyst-review state.
This is an adapter contract, not a second emitted mapping schema in this release.
Reuse the existing local ASI mapper for ASI classes. A CVE/incident reference means
context for analyst review, never a claim that the target is affected.
Absent mappings are valid; unavailable catalogs must not block ordinary reports.
No network, remote taxonomy, automatic ASI call or dependency on another Aletheia
repository is introduced. Existing pinned-catalog and independent-axis tests remain
the compatibility validation; consumers must reject unknown schema majors.

Vibe Explainer can map an evidence review to a local Agent Security Index catalog with
`--asi-catalog`. The bridge is offline and deterministic. It does not detect attacks,
validate mitigations, or establish conformance with ASI.

## Independent evidence axes

Each ASI class reports five separate dimensions:

1. **Applicability** — whether supported repository evidence identifies a protocol listed
   by the class, plus the exact findings that form that basis.
2. **Class evidence** — only concern scenarios connected through an explicit
   Vibe-to-class bridge. Protocol compatibility is not class evidence.
3. **Mitigation evidence** — every mapped Vibe control is shown independently with its
   repository status. No best-status aggregation is performed.
4. **Unresolved assumptions** — runtime exposure, external configuration, enforcement,
   and other facts that static repository inspection cannot establish.
5. **Manual review** — whether the row requires analyst disposition or is deferred because
   applicability was not established.

An `APPLICABLE` row may still have `class_evidence.status = NOT_OBSERVED`. That means the
protocol family appears in the repository but Vibe did not observe class-specific evidence.
It is not a control gap and is not a claim that the attack exists.

## Catalog provenance

Every matrix includes the catalog version, lifecycle status, independent-review metadata,
source location, and SHA-256 identifier. The terminal and detailed Markdown outputs display
draft and pending-review status prominently. JSON contains the complete provenance and
row-level structure.

Directory loading prefers `asi-catalog.json`. Split `attack-classes*.json` exports are
accepted only when their row count matches `catalog-meta.json.classCount`, if declared.
This prevents partial exports from silently becoming customer matrices.

## Supported applicability observations

The bridge currently records explicit repository observations for Native model/tool use,
MCP, RAG/retrieval, A2A/Agent Cards, ANP, and agent Skills. These observations establish
technical applicability only. Deployed services, external control planes, and operational
configuration outside the repository remain unresolved.
