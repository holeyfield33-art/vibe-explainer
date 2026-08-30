# Phase 4 — AI Security Control Assessment

> **Validity warning:** Statuses describe lexical repository evidence only. They do
> not prove that a guard executes, precedes a protected action, consumes an
> authorization result, or resists bypass.

**Control assessment identifies repository evidence of security controls. It does not
prove that a control is complete, effective, or resistant to bypass.**

## 1. Purpose

Answer: *"What evidence of security controls exists in this repository?"*

Never answer: *"Is this application secure?"*

This is the evidence layer between static discovery (Phases 1–3) and any future scoring
(Phases 5–6). Getting the discipline right here — evidence found vs. evidence not found
vs. not applicable — is what makes a later risk number mean something instead of being
an arbitrary guess dressed up as math.

## 2. Control model

```
AIFinding ──▶ Attack Surface ──▶ Data Flow ──▶ Control Assessor ──▶ SecurityControl
```

`assess_controls(discovery, attack_surface, dataflow) -> ControlAssessment` — a pure
function over the outputs of Phases 1–3. It does not re-scan the repository for AI
components (that's `ai_discovery.py`'s job); it runs its own narrow evidence scan
(auth checks, validation calls, audit-specific logging, doc headers) and combines that
with the already-discovered findings and data-flow edges.

`ControlAssessment` holds exactly 12 `SecurityControl` results, always present,
always in `C01`–`C12` order regardless of internal processing order.

## 3. Status semantics

- **DETECTED** — meaningful repository evidence of the control was found. Does not
  mean the control is correct, complete, or unbypassable.
- **PARTIAL** — either (a) evidence covers some but not all of the relevant surface
  (e.g. one tool call is authorized, another isn't), or (b) only moderate-specificity
  evidence exists for a control that doesn't have a "coverage" concept.
- **NOT_DETECTED** — the relevant AI surface is clearly present and was searched, but
  no supporting evidence was found. **This is not a claim that the control doesn't
  exist anywhere** — it may live in an external service, a private wiki, a repo this
  tool wasn't pointed at. Every `NOT_DETECTED` rationale says this explicitly.
- **UNKNOWN** — reserved in the status vocabulary for genuinely indeterminate cases.
  This implementation doesn't currently emit it: every control here resolves to
  DETECTED/PARTIAL/NOT_DETECTED/NOT_APPLICABLE based on the evidence scan, because the
  applicability check (§4) already absorbs the "we can't reasonably judge this" case
  into NOT_APPLICABLE. Left in the vocabulary for a future control whose evidence
  really is ambiguous rather than simply absent.

## 4. NOT_APPLICABLE semantics

Used whenever the attack surface a control protects doesn't exist in this repository —
preferred over NOT_DETECTED, which would overclaim ("missing") for a feature that was
never there. E.g. no RAG discovered → C09 is `NOT_APPLICABLE`, not `NOT_DETECTED`.

Applicability gates, one per control:

| Control | Applicable when |
|---|---|
| C01, C02 | any AI component was discovered at all |
| C03 | `ai_usage` or `prompt_surface` findings exist |
| C04 | `ai_usage` findings exist |
| C05, C06 | `tool_agent` or `mcp` findings exist |
| C07 | `ai_usage` or tool-like findings exist |
| C08 | `model_provider` or `ai_usage` findings exist |
| C09 | `rag_retrieval` findings exist |
| C10 | `mcp` findings exist |
| C11 | `ai_usage` **and** a DB/data-store client (`SQL database client`/`Redis client`) both exist |
| C12 | `tool_agent` findings named "Shell execution" or "Dynamic code execution" exist |

## 5. Evidence rules

Every `DETECTED`/`PARTIAL` result carries at least one `EvidenceRef`
(`type`, `id`, `description`). Every `NOT_APPLICABLE` and most `NOT_DETECTED` results
carry an **empty** evidence list — no evidence object is manufactured to fill the
field. The exception: `NOT_DETECTED` for C04/C05/C12 may carry `dataflow`-typed
evidence describing what *was* found (e.g. "model invocation is data-flow-connected to
tool execution") even though no control evidence was found — this is the evidence for
*why the control was searched*, not evidence for the control itself, matching the
directive's own worked example.

## 6. Confidence rules

Confidence describes confidence in **the assessment**, not confidence that the
underlying AI component exists (that's `ai_discovery.py`'s confidence, a separate
field on `AIFinding`). Two tiers for control-evidence patterns, same discipline as
Phase 3's data-flow confidence: no "low" tier — a signal too weak to be "moderate"
produces no evidence at all rather than a manufactured low-confidence hit.

- A control's confidence is **high** if any matched evidence pattern is tagged high.
- Otherwise **moderate** if any pattern matched at all.
- `DETECTED` requires high confidence; evidence that only reaches moderate confidence
  yields `PARTIAL` instead — a deliberate choice so "detected" isn't claimed on weak
  evidence alone.
- C08 (Secret Management) is hand-tuned rather than pattern-tier-based: env-var-only
  evidence is `DETECTED` but pinned at `moderate` confidence forever, because knowing a
  credential comes from an env var doesn't confirm a real secret manager/vault sits
  behind it — see the false-positive tests.

## 7. Traceability

```
SecurityControl
  ├── related_finding_ids   → AIFinding.id (Phase 1)
  ├── related_dataflow_ids  → "source_id->dest_id:relationship" (Phase 3)
  └── evidence[] → EvidenceRef(type: finding | dataflow | pattern, id, description)
```

Controls never copy a full `AIFinding` or `DataFlowObservation` into themselves — only
IDs and a short description, so a report layer can always walk back to
`file:line:evidence` on the original finding.

## 8. Control definitions (C01–C12)

| ID | Name | Category | Applicability gate |
|---|---|---|---|
| C01 | AI Inventory | AI_INVENTORY | any AI signal |
| C02 | AI Threat Model | THREAT_MODELING | any AI signal |
| C03 | Input Handling | INPUT_HANDLING | ai_usage/prompt_surface |
| C04 | Output Handling | OUTPUT_HANDLING | ai_usage |
| C05 | Tool Authorization | TOOL_AUTHORIZATION | tool_agent/mcp |
| C06 | Human Approval | HUMAN_APPROVAL | tool_agent/mcp |
| C07 | Logging / Auditability | LOGGING | ai_usage/tool-like |
| C08 | Secret Management | SECRET_MANAGEMENT | model_provider/ai_usage |
| C09 | RAG / Retrieval Security | RAG_SECURITY | rag_retrieval |
| C10 | MCP / Tool Governance | MCP_GOVERNANCE | mcp |
| C11 | AI Data Access | DATA_ACCESS | ai_usage + DB client |
| C12 | High-Risk Action Controls | HIGH_RISK_ACTIONS | shell/eval findings |

C01/C02 evidence comes from documentation (`.md`/`.rst`/`.txt` section headers or
recognizable filenames like `THREAT-MODEL.md`) — the repository must document the
thing; generating an attack-surface report (this tool's own output) does not satisfy
either control. C05 and C12 use per-finding coverage (§9) rather than a single
repo-wide yes/no; the rest use a simpler "was any qualifying evidence found at all."

## 9. Coverage-based PARTIAL (C05, C12)

For Tool Authorization and High-Risk Action Controls specifically, evidence is checked
per discovered finding (same-file, within `dataflow.MAX_DATAFLOW_LINE_DISTANCE`, reused
so "nearby" means the same thing everywhere in the assessment chain):

- evidence covers **every** relevant finding → `DETECTED`
- evidence covers **some but not all** → `PARTIAL`, naming how many of how many
- evidence covers **none** → `NOT_DETECTED`

This directly implements the directive's own example: "some tool calls are authorized,
but another discovered tool path has no corresponding authorization evidence" → PARTIAL.

## 10. Limitations

- Regex/keyword evidence, not AST analysis — a function literally named
  `check_permission` is evidence; a differently-named function doing the identical
  check is invisible to this scanner. False negatives are expected and are the safer
  failure mode here (NOT_DETECTED, not a false DETECTED).
- Proximity-based coverage (C05/C12) inherits Phase 3's same limitation: it's a
  distance proxy, not confirmed code-path evidence that the check actually gates that
  specific action.
- C01/C02 only scan `.md`/`.rst`/`.txt` — a threat model written directly in code
  comments, a wiki, or a ticket tracker is invisible here.
- No cross-file resolution (inherited from Phase 3) — an authorization decorator
  defined in `auth.py` and applied via a decorator import in `tools.py` is only
  detected if the decorator *usage* itself matches a pattern in the same file as the
  tool; a wrapper applied at a framework/router level elsewhere won't be seen.
- 12 controls is a deliberately small, directly-supported set — not exhaustive
  coverage of the source framework's full Level 1 control list (e.g. no dedicated
  "risk register" control; that's closer to Phase 5/6 territory).

## 11. Examples

**DETECTED** — `controls-well-controlled/app.py`, C04 Output Handling: a
`response_format=` argument on the `.chat.completions.create(` call is high-confidence,
directly-matched evidence of structured output handling.

**PARTIAL** — `controls-tool-with-auth` variants where authorization evidence exists
near some but not all discovered tool findings; also any control whose only matching
pattern is moderate-confidence (e.g. a bare `BaseModel` reference for C03, with no
stronger `.model_validate(` call alongside it).

**NOT_DETECTED** — `agent-with-tools`, C05 Tool Authorization: tool execution (a
`@tool`-decorated function, `tool_choice=`, and a `subprocess.run(`) is clearly
present and data-flow-connected to the model call, but no `check_permission`/
`is_authorized`/allowlist evidence was found anywhere nearby.

**NOT_APPLICABLE** — `examples/sample-vibe-project` (no AI at all): all 12 controls
report `NOT_APPLICABLE`, none report `NOT_DETECTED` — there is no AI surface to have
found evidence for or against.
