# Agent Security Index Mapping

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
