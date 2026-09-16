# Phase 3 — Bounded Structural Relationships

Vibe Explainer reports static relationships only when supported by a shared Python
value or symbol. It does not claim runtime data flow, reachability, or taint propagation.

## Supported relationships

- prompt construction → model invocation (`feeds_prompt`)
- retrieval result → model invocation (`retrieved_context`)
- model result/configuration → tool or high-risk action (`invokes_tool`, `flows_to_output`)
- model result → external integration (`calls_external_service`)
- credential reference → provider/model use (`reads_storage`)

## Evidence methods

`PYTHON_DEF_USE` requires same-scope directional assignment/call-argument evidence. The
analyzer follows bounded local assignment dependencies, so `result → context → prompt`
can connect to a model call. Module constants referenced by a function are supported.

`PYTHON_IMPORT_SYMBOL` requires a directly imported symbol that originates at the source
finding and is consumed by the destination call. `PYTHON_IMPORT_CALL` requires a source
value to be passed into a directly imported function containing the destination finding.
Import edges are confidence-capped at moderate.

Nearby category-compatible findings with no shared def-use evidence are retained under
`unresolved_relationships` with reasons such as `NO_SHARED_VALUE_OR_SYMBOL`,
`DIFFERENT_FUNCTION_SCOPE`, or `NO_SHARED_IMPORTED_SYMBOL`. They are not emitted as
edges and cannot drive concern scenarios or experimental severity.

## Boundaries

The implementation is intentionally bounded: Python AST only, intraprocedural local
assignments, direct imports, and direct imported calls. It does not resolve dynamic
dispatch, reflection, framework injection, arbitrary interprocedural flows, containers,
or runtime aliases. Unsupported and ambiguous paths remain unresolved for analyst review.

Every emitted edge records source/destination finding IDs, files and lines, relationship,
resolution method, confidence, structural basis, and `STRUCTURALLY_INFERRED` status.
