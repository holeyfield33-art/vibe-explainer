# Phase 4 — AI Security Control Evidence

> **Validity warning:** This is static repository evidence, not a security verdict.

## Purpose

`assess_controls(discovery, attack_surface, dataflow)` reports evidence for twelve
control categories. It never claims that an application is secure or that a control
works at runtime.

Every result separates three questions:

| Axis | Values | Meaning |
|---|---|---|
| Artifact | `EVIDENCE_FOUND`, `NOT_FOUND`, `NOT_APPLICABLE` | Was a relevant repository artifact observed? |
| Structural enforcement | `STRUCTURALLY_CONNECTED`, `PARTIALLY_CONNECTED`, `NOT_ESTABLISHED`, `NOT_APPLICABLE` | Is evidence connected to each protected operation in the same function through a consumed guard, decorator, transform, or logging side effect? |
| Effectiveness | `UNVERIFIED` | An offline scan does not test runtime behavior, configuration, bypass resistance, or operational effectiveness. |

The compatibility names `STATUS_DETECTED` and `STATUS_NOT_DETECTED` remain importable,
but serialize as `EVIDENCE_FOUND` and `NOT_FOUND`. New integrations should use the new
vocabulary.

## Aggregate status

- **EVIDENCE_FOUND** — qualifying artifact evidence exists and, for executable
  controls, covers every discovered protected surface structurally.
- **PARTIAL** — artifact evidence exists but structural coverage is absent or
  incomplete. Every uncovered surface is listed individually.
- **NOT_FOUND** — an applicable surface was found, but no qualifying control artifact
  was found. This does not prove the control is absent from external systems.
- **UNKNOWN** — reserved for indeterminate cases.
- **NOT_APPLICABLE** — the protected surface was not discovered.

## Control catalog

| ID | Control | Applicability |
|---|---|---|
| C01 | AI Inventory | any AI signal |
| C02 | AI Threat Model | any AI signal |
| C03 | Input Handling | AI usage or prompt construction |
| C04 | Output Handling | AI usage |
| C05 | Tool Authorization | tool or MCP surface |
| C06 | Human Approval | tool or MCP surface |
| C07 | Logging / Auditability | AI usage or tool surface |
| C08 | Secret Management | provider or AI usage |
| C09 | RAG / Retrieval Security | retrieval surface |
| C10 | MCP / Tool Governance | MCP surface |
| C11 | AI Data Access | AI usage and database/data-store client |
| C12 | High-Risk Action Controls | shell or dynamic-code execution |

## Structural rules

Python evidence is parsed with `ast` and related to discovered operations by function
scope and order. A guard must influence control flow, be consumed by an assignment or
return, or be an applied authorization decorator. A bare checker call is not
enforcement. Guards after a sink do not cover it. Evidence in another/dead function
does not cover a live surface. Audit logging is treated as a side effect, but still
must share the operation's function. Output validation may follow model invocation;
other guards must precede the protected operation.

Documentation headings (C01/C02) and environment-variable access (C08) are artifact
evidence only. In particular, an environment variable does not establish a vault,
rotation, access policy, or runtime secret-management enforcement.

The analyzer is conservative: unsupported languages, indirect framework wiring,
dynamic dispatch, and cross-function/cross-file call paths remain `NOT_ESTABLISHED`.
They require manual review rather than optimistic credit.

## Traceability

Each result includes evidence references, related finding/data-flow IDs, and
`uncovered_surfaces`. Evidence lines are redacted before storage. Adversarial tests
cover all twelve controls, including unused checks, checks after sinks, dead code,
unconsumed allowlists, documentation-only evidence, and environment-only secrets.
