"""AI security control assessment — evidence only, never a verdict on security.

Answers: "what evidence of security controls exists in this repository?"
Never answers: "is this application secure?"

Every status is a claim about EVIDENCE, not about effectiveness:

  DETECTED       - meaningful repository evidence of the control was found.
                   Does NOT mean the control is correct, complete, or
                   unbypassable — only that evidence of it exists.
  PARTIAL        - some evidence exists but coverage is incomplete or the
                   evidence itself is only moderately specific.
  NOT_DETECTED   - the relevant AI surface is clearly present and could
                   reasonably be searched, but no supporting evidence was
                   found. This is NOT a claim that the control doesn't
                   exist anywhere (it could live in an external service,
                   a private repo, etc.) — only that this repository
                   doesn't demonstrate it.
  UNKNOWN        - not enough information in the repository to make any
                   reasonable judgment either way.
  NOT_APPLICABLE - the attack surface this control protects doesn't exist
                   in this repository at all (e.g. no RAG => no RAG
                   security control to assess). Preferred over NOT_DETECTED
                   or UNKNOWN whenever the surface genuinely isn't present —
                   labeling an absent feature "missing" overclaims.

No risk scoring, no readiness classification here — see docs/PHASE-4-CONTROLS.md.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .ai_discovery import AIFinding, DiscoveryResult, MAX_FILE_BYTES, _iter_candidate_files, _read_text
from .attack_surface import AttackSurfaceResult
from .dataflow import MAX_DATAFLOW_LINE_DISTANCE, DataFlowGraph, DataFlowObservation
from .scanner import SKIP_DIRS

STATUS_DETECTED = "DETECTED"
STATUS_PARTIAL = "PARTIAL"
STATUS_NOT_DETECTED = "NOT_DETECTED"
STATUS_UNKNOWN = "UNKNOWN"
STATUS_NOT_APPLICABLE = "NOT_APPLICABLE"

TOOL_LIKE_CATEGORIES = {"tool_agent", "mcp"}
HIGH_RISK_TOOL_NAMES = {"Shell execution", "Dynamic code execution"}
DB_EXTERNAL_NAMES = {"SQL database client", "Redis client"}
HARDCODED_SECRET_NAME = "Possible hardcoded API key"
ENV_SECRET_NAMES = {"Model API key env var", "Generic API key reference"}

DOC_EXTS = {".md", ".rst", ".txt"}


@dataclass
class EvidenceRef:
    type: str  # "finding" | "dataflow" | "pattern"
    id: str
    description: str

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "id": self.id, "description": self.description}


@dataclass
class SecurityControl:
    control_id: str
    name: str
    category: str
    status: str
    confidence: str
    evidence: list[EvidenceRef]
    related_finding_ids: list[str]
    related_dataflow_ids: list[str]
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "name": self.name,
            "category": self.category,
            "status": self.status,
            "confidence": self.confidence,
            "evidence": [e.to_dict() for e in self.evidence],
            "related_finding_ids": list(self.related_finding_ids),
            "related_dataflow_ids": list(self.related_dataflow_ids),
            "rationale": self.rationale,
        }


@dataclass
class ControlAssessment:
    root: str
    controls: list[SecurityControl] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "controls": [c.to_dict() for c in self.controls],
            "summary": {c.control_id: c.status for c in self.controls},
        }


# ---------------------------------------------------------------------------
# Code-level control-evidence patterns.
#
# These are deliberately NOT a superset of ai_discovery.py's patterns — they
# look for evidence that a control exists (auth checks, validation, allowlists,
# audit-specific logging), not evidence that an AI component exists. Kept to
# "high"/"moderate" confidence only, same discipline as dataflow.py: a
# proximity/keyword-only signal too weak to be "moderate" is not manufactured
# just to produce a DETECTED.
# ---------------------------------------------------------------------------
_CODE_EVIDENCE_PATTERNS: list[tuple[str, str, re.Pattern[str], str]] = [
    # C03 — INPUT_HANDLING
    ("C03", "Pydantic input model", re.compile(r"\bBaseModel\b"), "moderate"),
    ("C03", "Schema validation call", re.compile(r"jsonschema\.validate\(|\.model_validate\("), "high"),
    ("C03", "Explicit input sanitizer/validator", re.compile(r"\b(?:sanitize_input|validate_input)\s*\("), "moderate"),
    # C04 — OUTPUT_HANDLING
    ("C04", "Structured output response format", re.compile(r"\bresponse_format\s*="), "high"),
    ("C04", "Output parsed via schema", re.compile(r"\.model_validate\(|\.parse_obj\("), "moderate"),
    ("C04", "Explicit output sanitizer/validator", re.compile(r"\b(?:sanitize_output|validate_output)\s*\("), "moderate"),
    # C05 — TOOL_AUTHORIZATION
    ("C05", "Auth/permission decorator", re.compile(r"@(?:require_auth|requires_permission|login_required|requires_scope)\b"), "high"),
    ("C05", "Explicit permission/authorization check", re.compile(r"\b(?:check_permission|is_authorized|authorize_tool)\s*\("), "high"),
    ("C05", "Tool allowlist", re.compile(r"\b(?:ALLOWED_TOOLS|allowed_tools)\b\s*[:=]"), "moderate"),
    # C06 — HUMAN_APPROVAL
    ("C06", "Explicit approval gate", re.compile(r"\b(?:require_approval|human_approval|approve_action)\s*\("), "high"),
    ("C06", "Confirmation call", re.compile(r"\bconfirm\s*\("), "moderate"),
    # C07 — LOGGING / AUDITABILITY (deliberately excludes generic logger.*() —
    # see false-positive tests: a bare logger call is not AI-auditability evidence)
    ("C07", "Audit-specific log call", re.compile(r"\b(?:audit_log|log_tool_call|log_ai_action)\s*\("), "high"),
    ("C07", "Audit logger class", re.compile(r"\bAuditLogger\b"), "moderate"),
    # C09 — RAG_SECURITY
    ("C09", "Source allowlist", re.compile(r"\b(?:allowed_domains|trusted_sources)\b\s*[:=]"), "moderate"),
    ("C09", "Source/content filter function", re.compile(r"\b(?:filter_sources|verify_source|content_filter)\s*\("), "high"),
    # C10 — MCP_GOVERNANCE
    ("C10", "Default-deny / explicit tool allowlist", re.compile(r"\bdefault_deny\b|\ballowed_tools\b\s*[:=]"), "high"),
    ("C10", "Scoped permission on tool/resource", re.compile(r"\b(?:scope\s*=|requires_scope)\b"), "moderate"),
    # C11 — AI_DATA_ACCESS
    ("C11", "Explicit access-control function", re.compile(r"\bcheck_access\s*\(|\brow_level_security\b"), "high"),
    ("C11", "Tenant/user-scoped query", re.compile(r"\b(?:tenant_id|user_id)\s*=\s*[A-Za-z_]"), "moderate"),
    # C12 — HIGH_RISK_ACTION_CONTROLS
    ("C12", "Sandbox/dry-run guard", re.compile(r"\bsandbox\s*\(|\bdry_run\b"), "high"),
    ("C12", "Explicit action allowlist", re.compile(r"\ballowed_actions\b\s*[:=]"), "moderate"),
    ("C12", "Confirmation before action", re.compile(r"\bconfirm\s*\("), "moderate"),
    ("C12", "Auth/permission check before action", re.compile(r"@(?:require_auth|requires_permission|login_required|requires_scope)\b|\b(?:check_permission|is_authorized|authorize_tool)\s*\("), "high"),
]

# Doc-level patterns for C01/C02 — these require the repository to actually
# document the thing, not just have Vibe Explainer infer it.
_DOC_EVIDENCE_PATTERNS: list[tuple[str, str, re.Pattern[str], str]] = [
    ("C01", "AI/model inventory section header", re.compile(r"(?im)^#+\s*(?:ai component|model inventory|ai inventory)s?\b"), "high"),
    ("C02", "Threat model / security architecture section header", re.compile(r"(?im)^#+\s*(?:(?:ai )?threat model|security architecture)\b"), "high"),
]

_DOC_FILENAME_HINTS: list[tuple[str, re.Pattern[str], str]] = [
    ("C01", re.compile(r"(?i)^(ai[-_]?inventory|models)\.(md|txt)$"), "moderate"),
    ("C02", re.compile(r"(?i)^(threat[-_]?model)\.(md|txt)$"), "moderate"),
]


@dataclass
class _EvidenceMatch:
    file: str
    line: int
    tag: str
    confidence: str
    text: str


def _evidence_id(file: str, line: int, tag: str) -> str:
    digest = hashlib.sha1(f"{file}:{line}:{tag}".encode("utf-8")).hexdigest()
    return digest[:12]


def _should_skip_dir(name: str) -> bool:
    return name in SKIP_DIRS or name.startswith(".")


def _iter_doc_files(root_path: Path):
    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [d for d in dirnames if not _should_skip_dir(d)]
        for name in filenames:
            full = Path(dirpath) / name
            if full.suffix.lower() in DOC_EXTS:
                yield full


def _line_evidence_text(text: str, start: int) -> str:
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", start)
    if line_end == -1:
        line_end = len(text)
    evidence = text[line_start:line_end].strip()
    if len(evidence) > 160:
        evidence = evidence[:157] + "..."
    return evidence


def _scan_code_evidence(root_path: Path) -> dict[str, list[_EvidenceMatch]]:
    by_control: dict[str, list[_EvidenceMatch]] = {}
    for file_path in _iter_candidate_files(root_path):
        text = _read_text(file_path)
        if text is None:
            continue
        rel = str(file_path.relative_to(root_path)).replace("\\", "/")
        for control_id, tag, pattern, confidence in _CODE_EVIDENCE_PATTERNS:
            for match in pattern.finditer(text):
                line_no = text.count("\n", 0, match.start()) + 1
                evidence_text = _line_evidence_text(text, match.start())
                by_control.setdefault(control_id, []).append(
                    _EvidenceMatch(file=rel, line=line_no, tag=tag, confidence=confidence, text=evidence_text)
                )
    return by_control


def _scan_doc_evidence(root_path: Path) -> dict[str, list[_EvidenceMatch]]:
    by_control: dict[str, list[_EvidenceMatch]] = {}
    for file_path in _iter_doc_files(root_path):
        try:
            if file_path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        text = _read_text(file_path)
        if text is None:
            continue
        rel = str(file_path.relative_to(root_path)).replace("\\", "/")

        for control_id, tag, pattern, confidence in _DOC_EVIDENCE_PATTERNS:
            for match in pattern.finditer(text):
                line_no = text.count("\n", 0, match.start()) + 1
                evidence_text = _line_evidence_text(text, match.start())
                by_control.setdefault(control_id, []).append(
                    _EvidenceMatch(file=rel, line=line_no, tag=tag, confidence=confidence, text=evidence_text)
                )

        for control_id, name_pattern, confidence in _DOC_FILENAME_HINTS:
            if name_pattern.match(file_path.name):
                by_control.setdefault(control_id, []).append(
                    _EvidenceMatch(file=rel, line=1, tag="Filename suggests this document exists", confidence=confidence, text=file_path.name)
                )

    return by_control


def _findings_covered(matches: list[_EvidenceMatch], findings: list[AIFinding]) -> set[str]:
    """Finding ids that have at least one evidence match in the same file within
    the shared same-file proximity threshold (reusing dataflow.py's constant so
    'nearby' means the same thing across the whole assessment chain)."""
    covered: set[str] = set()
    for finding in findings:
        for m in matches:
            if m.file == finding.file and abs(m.line - finding.line) <= MAX_DATAFLOW_LINE_DISTANCE:
                covered.add(finding.id)
                break
    return covered


def _best_confidence(matches: list[_EvidenceMatch]) -> str:
    return "high" if any(m.confidence == "high" for m in matches) else "moderate"


def _pattern_evidence_refs(matches: list[_EvidenceMatch], limit: int = 5) -> list[EvidenceRef]:
    ordered = sorted(matches, key=lambda m: (m.file, m.line, m.tag))[:limit]
    return [
        EvidenceRef(
            type="pattern",
            id=_evidence_id(m.file, m.line, m.tag),
            description=f"{m.tag} at {m.file}:{m.line} — \"{m.text}\"",
        )
        for m in ordered
    ]


def _finding_evidence_refs(findings: list[AIFinding], description_prefix: str) -> list[EvidenceRef]:
    ordered = sorted(findings, key=lambda f: f.id)
    return [
        EvidenceRef(
            type="finding",
            id=f.id,
            description=f"{description_prefix}: {f.category}/{f.name} at {f.file}:{f.line}",
        )
        for f in ordered
    ]


def _dataflow_evidence_refs(edges: list[DataFlowObservation], description: str) -> list[EvidenceRef]:
    def edge_id(e: DataFlowObservation) -> str:
        return f"{e.source_finding_id}->{e.destination_finding_id}:{e.relationship}"

    ordered = sorted(edges, key=edge_id)
    return [EvidenceRef(type="dataflow", id=edge_id(e), description=description) for e in ordered]


def assess_controls(
    discovery: DiscoveryResult,
    attack_surface: AttackSurfaceResult,
    dataflow: DataFlowGraph,
) -> ControlAssessment:
    """Evidence-only AI security control assessment.

    Does not calculate risk or readiness (Phases 5/6). Does not claim a
    control is effective — only that repository evidence of it was found,
    partially found, or not found, and clearly distinguishes "not found"
    from "not applicable" from "unknown".
    """
    root_path = Path(discovery.root)
    code_evidence = _scan_code_evidence(root_path)
    doc_evidence = _scan_doc_evidence(root_path)

    findings = discovery.findings
    by_category: dict[str, list[AIFinding]] = {}
    for f in findings:
        by_category.setdefault(f.category, []).append(f)

    ai_usage = by_category.get("ai_usage", [])
    model_provider = by_category.get("model_provider", [])
    prompt_surface = by_category.get("prompt_surface", [])
    rag_retrieval = by_category.get("rag_retrieval", [])
    tool_agent = by_category.get("tool_agent", [])
    mcp = by_category.get("mcp", [])
    external_integration = by_category.get("external_integration", [])
    secret_config = by_category.get("secret_config", [])

    tool_like = [f for f in tool_agent + mcp]
    high_risk_tools = [f for f in tool_agent if f.name in HIGH_RISK_TOOL_NAMES]
    db_integrations = [f for f in external_integration if f.name in DB_EXTERNAL_NAMES]

    controls: list[SecurityControl] = []

    def not_applicable(control_id: str, name: str, category: str, reason: str) -> SecurityControl:
        return SecurityControl(
            control_id=control_id,
            name=name,
            category=category,
            status=STATUS_NOT_APPLICABLE,
            confidence="moderate",
            evidence=[],
            related_finding_ids=[],
            related_dataflow_ids=[],
            rationale=reason,
        )

    def not_detected(
        control_id: str,
        name: str,
        category: str,
        reason: str,
        related_findings: list[AIFinding] | None = None,
    ) -> SecurityControl:
        related = related_findings or []
        return SecurityControl(
            control_id=control_id,
            name=name,
            category=category,
            status=STATUS_NOT_DETECTED,
            confidence="moderate",
            evidence=[],
            related_finding_ids=sorted({f.id for f in related}),
            related_dataflow_ids=[],
            rationale=reason,
        )

    def detected_or_partial_from_matches(
        control_id: str,
        name: str,
        category: str,
        matches: list[_EvidenceMatch],
        related_findings: list[AIFinding],
        surface_description: str,
    ) -> SecurityControl:
        confidence = _best_confidence(matches)
        status = STATUS_DETECTED if confidence == "high" else STATUS_PARTIAL
        rationale = (
            f"{surface_description} evidence of the control was found in the repository "
            f"({len(matches)} matching pattern(s))."
            if status == STATUS_DETECTED
            else (
                f"{surface_description} was found, but only moderate-specificity evidence "
                f"exists — treated as partial rather than fully detected."
            )
        )
        return SecurityControl(
            control_id=control_id,
            name=name,
            category=category,
            status=status,
            confidence=confidence,
            evidence=_pattern_evidence_refs(matches),
            related_finding_ids=sorted({f.id for f in related_findings}),
            related_dataflow_ids=[],
            rationale=rationale,
        )

    # ---- C01 — AI INVENTORY -------------------------------------------
    if not discovery.has_ai_signal():
        controls.append(not_applicable("C01", "AI Inventory", "AI_INVENTORY", "No AI components were discovered in this repository — there is nothing to inventory."))
    else:
        matches = doc_evidence.get("C01", [])
        if matches:
            controls.append(
                detected_or_partial_from_matches(
                    "C01", "AI Inventory", "AI_INVENTORY", matches, [],
                    "AI/model inventory documentation",
                )
            )
        else:
            controls.append(
                not_detected(
                    "C01", "AI Inventory", "AI_INVENTORY",
                    "AI components were discovered, but no inventory/architecture documentation "
                    "(README/docs section or dedicated file) was found describing them. This does "
                    "not mean no inventory exists — it may live outside scanned doc file types or "
                    "in an external system.",
                )
            )

    # ---- C02 — AI THREAT MODEL -----------------------------------------
    if not discovery.has_ai_signal():
        controls.append(not_applicable("C02", "AI Threat Model", "THREAT_MODELING", "No AI components were discovered in this repository — there is no AI surface to threat-model."))
    else:
        matches = doc_evidence.get("C02", [])
        if matches:
            controls.append(
                detected_or_partial_from_matches(
                    "C02", "AI Threat Model", "THREAT_MODELING", matches, [],
                    "AI threat-model documentation",
                )
            )
        else:
            controls.append(
                not_detected(
                    "C02", "AI Threat Model", "THREAT_MODELING",
                    "AI components were discovered, but no threat-model or AI security architecture "
                    "documentation was found. Generating an attack-surface report (this tool's own "
                    "output) does not itself satisfy this control — the repository must document its "
                    "own threat model.",
                )
            )

    # ---- C03 — INPUT HANDLING ------------------------------------------
    if not ai_usage and not prompt_surface:
        controls.append(not_applicable("C03", "Input Handling", "INPUT_HANDLING", "No AI usage or prompt-construction surface was discovered — there is no AI input to handle."))
    else:
        matches = code_evidence.get("C03", [])
        related = ai_usage + prompt_surface
        if matches:
            controls.append(detected_or_partial_from_matches("C03", "Input Handling", "INPUT_HANDLING", matches, related, "Input-validation"))
        else:
            controls.append(not_detected("C03", "Input Handling", "INPUT_HANDLING", "AI input surfaces (prompt construction / model invocation) were found, but no schema validation, sanitization, or explicit input-handling evidence was found.", related))

    # ---- C04 — OUTPUT HANDLING ------------------------------------------
    if not ai_usage:
        controls.append(not_applicable("C04", "Output Handling", "OUTPUT_HANDLING", "No AI usage was discovered — there is no model output to handle."))
    else:
        matches = code_evidence.get("C04", [])
        if matches:
            controls.append(detected_or_partial_from_matches("C04", "Output Handling", "OUTPUT_HANDLING", matches, ai_usage, "Output-validation"))
        else:
            downstream = [e for e in dataflow.edges if e.relationship in {"invokes_tool", "flows_to_output", "calls_external_service"}]
            extra = ""
            related_edges: list[DataFlowObservation] = []
            if downstream:
                extra = (
                    " Model output was also observed (via Phase 3 data-flow) to reach a tool, "
                    "shell, or external call, with no validation evidence in between."
                )
                related_edges = downstream
            control = not_detected("C04", "Output Handling", "OUTPUT_HANDLING", "AI usage was found, but no output validation/sanitization evidence was found." + extra, ai_usage)
            if related_edges:
                control.related_dataflow_ids = sorted({f"{e.source_finding_id}->{e.destination_finding_id}:{e.relationship}" for e in related_edges})
            controls.append(control)

    # ---- C05 — TOOL AUTHORIZATION ---------------------------------------
    if not tool_like:
        controls.append(not_applicable("C05", "Tool Authorization", "TOOL_AUTHORIZATION", "No tool-invocation or MCP surface was discovered — there is nothing to authorize."))
    else:
        matches = code_evidence.get("C05", [])
        covered = _findings_covered(matches, tool_like)
        related_edges = [e for e in dataflow.edges if e.relationship in {"invokes_tool", "flows_to_output"}]
        if not matches:
            control = not_detected("C05", "Tool Authorization", "TOOL_AUTHORIZATION", "Tool execution was detected, but no authorization or permission-check evidence was identified near any of it.", tool_like)
            if related_edges:
                control.related_dataflow_ids = sorted({f"{e.source_finding_id}->{e.destination_finding_id}:{e.relationship}" for e in related_edges})
                control.evidence = _dataflow_evidence_refs(related_edges, "Model invocation is data-flow-connected to tool execution with no authorization evidence nearby.")
            controls.append(control)
        elif covered >= {f.id for f in tool_like}:
            confidence = _best_confidence(matches)
            controls.append(
                SecurityControl(
                    control_id="C05", name="Tool Authorization", category="TOOL_AUTHORIZATION",
                    status=STATUS_DETECTED, confidence=confidence,
                    evidence=_pattern_evidence_refs(matches),
                    related_finding_ids=sorted({f.id for f in tool_like}),
                    related_dataflow_ids=sorted({f"{e.source_finding_id}->{e.destination_finding_id}:{e.relationship}" for e in related_edges}),
                    rationale="Authorization evidence was found near every discovered tool-invocation surface.",
                )
            )
        else:
            controls.append(
                SecurityControl(
                    control_id="C05", name="Tool Authorization", category="TOOL_AUTHORIZATION",
                    status=STATUS_PARTIAL, confidence="moderate",
                    evidence=_pattern_evidence_refs(matches),
                    related_finding_ids=sorted({f.id for f in tool_like}),
                    related_dataflow_ids=sorted({f"{e.source_finding_id}->{e.destination_finding_id}:{e.relationship}" for e in related_edges}),
                    rationale=(
                        f"Authorization evidence covers {len(covered)} of {len(tool_like)} discovered "
                        f"tool-invocation surfaces — at least one tool path has no corresponding "
                        f"authorization evidence nearby."
                    ),
                )
            )

    # ---- C06 — HUMAN APPROVAL --------------------------------------------
    if not tool_like:
        controls.append(not_applicable("C06", "Human Approval", "HUMAN_APPROVAL", "No tool-invocation or MCP surface was discovered — there is no high-impact AI action requiring approval."))
    else:
        matches = code_evidence.get("C06", [])
        if matches:
            controls.append(detected_or_partial_from_matches("C06", "Human Approval", "HUMAN_APPROVAL", matches, tool_like, "Approval/confirmation-gate"))
        else:
            controls.append(not_detected("C06", "Human Approval", "HUMAN_APPROVAL", "Tool-invocation surfaces were found, but no approval, confirmation-gate, or human-in-the-loop evidence was found. A UI existing elsewhere in the application is not, by itself, evidence of an approval gate.", tool_like))

    # ---- C07 — LOGGING / AUDITABILITY ------------------------------------
    if not ai_usage and not tool_like:
        controls.append(not_applicable("C07", "Logging / Auditability", "LOGGING", "No AI usage or tool-invocation surface was discovered — there is no AI action to audit."))
    else:
        matches = code_evidence.get("C07", [])
        related = ai_usage + tool_like
        if matches:
            controls.append(detected_or_partial_from_matches("C07", "Logging / Auditability", "LOGGING", matches, related, "AI/security-relevant audit logging"))
        else:
            controls.append(not_detected("C07", "Logging / Auditability", "LOGGING", "AI usage and/or tool invocation were found, but no AI/security-specific audit-logging evidence was found. Generic application logging elsewhere does not, by itself, count as evidence for this control.", related))

    # ---- C08 — SECRET MANAGEMENT -----------------------------------------
    if not model_provider and not ai_usage:
        controls.append(not_applicable("C08", "Secret Management", "SECRET_MANAGEMENT", "No model provider or AI usage was discovered — there is no AI credential to manage."))
    else:
        hardcoded = [f for f in secret_config if f.name == HARDCODED_SECRET_NAME]
        env_based = [f for f in secret_config if f.name in ENV_SECRET_NAMES]
        if hardcoded and env_based:
            controls.append(
                SecurityControl(
                    control_id="C08", name="Secret Management", category="SECRET_MANAGEMENT",
                    status=STATUS_PARTIAL, confidence="moderate",
                    evidence=_finding_evidence_refs(hardcoded + env_based, "Mixed secret-handling evidence"),
                    related_finding_ids=sorted({f.id for f in hardcoded + env_based}),
                    related_dataflow_ids=[],
                    rationale="Both environment-variable-based and apparently hardcoded credential evidence were found — mixed practice, not a consistently applied control.",
                )
            )
        elif hardcoded:
            controls.append(
                SecurityControl(
                    control_id="C08", name="Secret Management", category="SECRET_MANAGEMENT",
                    status=STATUS_NOT_DETECTED, confidence="high",
                    evidence=_finding_evidence_refs(hardcoded, "Apparent hardcoded credential"),
                    related_finding_ids=sorted({f.id for f in hardcoded}),
                    related_dataflow_ids=[],
                    rationale="An apparent hardcoded API key was found in source; this contradicts secure secret management regardless of any other evidence.",
                )
            )
        elif env_based:
            controls.append(
                SecurityControl(
                    control_id="C08", name="Secret Management", category="SECRET_MANAGEMENT",
                    status=STATUS_DETECTED, confidence="moderate",
                    evidence=_finding_evidence_refs(env_based, "Environment-variable-based credential reference"),
                    related_finding_ids=sorted({f.id for f in env_based}),
                    related_dataflow_ids=[],
                    rationale="AI credentials are referenced via environment variables rather than hardcoded — reasonable evidence, though this alone doesn't confirm a dedicated secret manager/vault is in use.",
                )
            )
        else:
            controls.append(not_detected("C08", "Secret Management", "SECRET_MANAGEMENT", "A model provider or AI usage was found, but no evidence of how its credential is supplied (no env-var reference or hardcoded key detected) was found.", model_provider + ai_usage))

    # ---- C09 — RAG / RETRIEVAL SECURITY ----------------------------------
    if not rag_retrieval:
        controls.append(not_applicable("C09", "RAG / Retrieval Security", "RAG_SECURITY", "No retrieval/RAG surface was discovered — there is no retrieved content to secure."))
    else:
        matches = code_evidence.get("C09", [])
        if matches:
            controls.append(detected_or_partial_from_matches("C09", "RAG / Retrieval Security", "RAG_SECURITY", matches, rag_retrieval, "Source/content-filtering"))
        else:
            controls.append(not_detected("C09", "RAG / Retrieval Security", "RAG_SECURITY", "Retrieval/RAG usage was found, but no source allowlisting, content filtering, or provenance-check evidence was found.", rag_retrieval))

    # ---- C10 — MCP / TOOL GOVERNANCE -------------------------------------
    if not mcp:
        controls.append(not_applicable("C10", "MCP / Tool Governance", "MCP_GOVERNANCE", "No MCP surface was discovered — there is no MCP tool/server to govern."))
    else:
        matches = code_evidence.get("C10", [])
        if matches:
            controls.append(detected_or_partial_from_matches("C10", "MCP / Tool Governance", "MCP_GOVERNANCE", matches, mcp, "Scoped-permission / default-deny"))
        else:
            controls.append(not_detected("C10", "MCP / Tool Governance", "MCP_GOVERNANCE", "MCP configuration was found, but no scoped-permission, allowlist, or default-deny evidence was found. MCP configuration existing is not, by itself, evidence of governance.", mcp))

    # ---- C11 — AI DATA ACCESS --------------------------------------------
    if not (ai_usage and db_integrations):
        controls.append(not_applicable("C11", "AI Data Access", "DATA_ACCESS", "No combination of AI usage and a database/data-store client was discovered — there is no AI-adjacent data access to constrain."))
    else:
        matches = code_evidence.get("C11", [])
        related = ai_usage + db_integrations
        if matches:
            controls.append(detected_or_partial_from_matches("C11", "AI Data Access", "DATA_ACCESS", matches, related, "Scoped-access"))
        else:
            controls.append(not_detected("C11", "AI Data Access", "DATA_ACCESS", "AI usage alongside a database/data-store client was found, but no row/tenant-scoping or explicit access-control evidence was found.", related))

    # ---- C12 — HIGH-RISK ACTION CONTROLS ---------------------------------
    if not high_risk_tools:
        controls.append(not_applicable("C12", "High-Risk Action Controls", "HIGH_RISK_ACTIONS", "No shell-execution or dynamic-code-execution surface was discovered — there is no high-risk action to constrain."))
    else:
        matches = code_evidence.get("C12", [])
        covered = _findings_covered(matches, high_risk_tools)
        related_edges = [e for e in dataflow.edges if e.relationship == "flows_to_output"]
        if not matches:
            control = not_detected("C12", "High-Risk Action Controls", "HIGH_RISK_ACTIONS", "Shell/dynamic-code-execution was detected, but no sandboxing, allowlist, or confirmation evidence was found nearby.", high_risk_tools)
            if related_edges:
                control.related_dataflow_ids = sorted({f"{e.source_finding_id}->{e.destination_finding_id}:{e.relationship}" for e in related_edges})
            controls.append(control)
        elif covered >= {f.id for f in high_risk_tools}:
            confidence = _best_confidence(matches)
            controls.append(
                SecurityControl(
                    control_id="C12", name="High-Risk Action Controls", category="HIGH_RISK_ACTIONS",
                    status=STATUS_DETECTED, confidence=confidence,
                    evidence=_pattern_evidence_refs(matches),
                    related_finding_ids=sorted({f.id for f in high_risk_tools}),
                    related_dataflow_ids=sorted({f"{e.source_finding_id}->{e.destination_finding_id}:{e.relationship}" for e in related_edges}),
                    rationale="Sandboxing/allowlist/confirmation evidence was found near every discovered high-risk action.",
                )
            )
        else:
            controls.append(
                SecurityControl(
                    control_id="C12", name="High-Risk Action Controls", category="HIGH_RISK_ACTIONS",
                    status=STATUS_PARTIAL, confidence="moderate",
                    evidence=_pattern_evidence_refs(matches),
                    related_finding_ids=sorted({f.id for f in high_risk_tools}),
                    related_dataflow_ids=sorted({f"{e.source_finding_id}->{e.destination_finding_id}:{e.relationship}" for e in related_edges}),
                    rationale=f"Control evidence covers {len(covered)} of {len(high_risk_tools)} discovered high-risk action surfaces.",
                )
            )

    controls.sort(key=lambda c: c.control_id)
    return ControlAssessment(root=discovery.root, controls=controls)
