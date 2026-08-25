"""AI security risk assessment — deterministic four-factor scoring over evidence
already produced by Phases 1-4. Performs NO independent repository scan.

"The risk engine evaluates risk represented by repository evidence. It does not prove
exploitability or establish that a vulnerability can be successfully exploited."

RISK != READINESS: a risk score answers "how concerning is this identified evidence
scenario", not "how mature is the org's AI security program". Readiness is Phase 6 and
is explicitly out of scope here — this module never computes a maturity level.

RISK != EXPLOITABILITY: nothing here executes code, traces runtime behavior, or proves
a path is reachable/abusable. A HIGH or CRITICAL score means "repository evidence
describes a concerning combination of exposure/impact/sensitivity/likelihood factors",
not "this is a confirmed vulnerability".

NO RISK != SAFE: if no scenarios are generated, that means no risk-worthy evidence
combination was found by this scanner — never state or imply the repository is secure.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

from .ai_discovery import AIFinding, DiscoveryResult
from .attack_surface import AttackSurfaceResult
from .controls import (
    HARDCODED_SECRET_NAME,
    HIGH_RISK_TOOL_NAMES,
    STATUS_DETECTED,
    STATUS_NOT_DETECTED,
    STATUS_PARTIAL,
    ControlAssessment,
    SecurityControl,
)
from .dataflow import DataFlowGraph, DataFlowObservation

SEVERITY_LOW = "LOW"
SEVERITY_MODERATE = "MODERATE"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"

COMPLETENESS_COMPLETE = "COMPLETE"
COMPLETENESS_PARTIAL = "PARTIAL"

_SECRET_PATTERN = re.compile(r"sk-[A-Za-z0-9_-]{20,}")


def _redact(text: str) -> str:
    return _SECRET_PATTERN.sub("[REDACTED]", text)


def score_risk(exposure: int, safety_impact: int, security_exposure: int, likelihood: int) -> int:
    """The source framework's formula, unmodified: ROUND(((E+S+Sec)/3) * L).

    Uses round-half-up (not Python's banker's rounding) to match the conventional
    spreadsheet ROUND() the framework document itself uses.
    """
    raw = ((exposure + safety_impact + security_exposure) / 3) * likelihood
    return int(raw + 0.5) if raw >= 0 else -int(-raw + 0.5)


def severity_for(score: int) -> str:
    if score <= 7:
        return SEVERITY_LOW
    if score <= 14:
        return SEVERITY_MODERATE
    if score <= 19:
        return SEVERITY_HIGH
    return SEVERITY_CRITICAL


@dataclass
class RiskEvidenceRef:
    type: str  # "finding" | "dataflow" | "control"
    id: str
    description: str

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "id": self.id, "description": self.description}


@dataclass
class RiskScenario:
    risk_id: str
    title: str
    category: str
    score: int
    severity: str
    exposure: int
    safety_impact: int
    security_exposure: int
    likelihood: int
    confidence: str
    rationale: str
    evidence: list[RiskEvidenceRef]
    related_finding_ids: list[str]
    related_dataflow_ids: list[str]
    related_control_ids: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "risk_id": self.risk_id,
            "title": self.title,
            "category": self.category,
            "score": self.score,
            "severity": self.severity,
            "exposure": self.exposure,
            "safety_impact": self.safety_impact,
            "security_exposure": self.security_exposure,
            "likelihood": self.likelihood,
            "confidence": self.confidence,
            "rationale": self.rationale,
            "evidence": [e.to_dict() for e in self.evidence],
            "related_finding_ids": list(self.related_finding_ids),
            "related_dataflow_ids": list(self.related_dataflow_ids),
            "related_control_ids": list(self.related_control_ids),
        }


@dataclass
class RiskAssessment:
    root: str
    ai_surface_detected: bool
    assessment_completeness: str
    scenarios: list[RiskScenario] = field(default_factory=list)
    summary_note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "ai_surface_detected": self.ai_surface_detected,
            "assessment_completeness": self.assessment_completeness,
            "scenarios": [s.to_dict() for s in self.scenarios],
            "summary_note": self.summary_note,
            "summary": {
                "scenario_count": len(self.scenarios),
                "by_severity": {
                    sev: len([s for s in self.scenarios if s.severity == sev])
                    for sev in (SEVERITY_LOW, SEVERITY_MODERATE, SEVERITY_HIGH, SEVERITY_CRITICAL)
                },
            },
        }


def _risk_id(category: str, related_finding_ids: list[str]) -> str:
    digest = hashlib.sha1(f"{category}:{','.join(sorted(related_finding_ids))}".encode("utf-8")).hexdigest()
    return f"R-{category}-{digest[:8]}"


def _edge_key(e: DataFlowObservation) -> str:
    return f"{e.source_finding_id}->{e.destination_finding_id}:{e.relationship}"


def _best_edge_confidence(edges: list[DataFlowObservation]) -> str:
    return "high" if any(e.confidence == "high" for e in edges) else "moderate"


def _has_upstream_prompt_chain(ai_usage_id: str, dataflow: DataFlowGraph) -> bool:
    return any(e.relationship == "feeds_prompt" and e.destination_finding_id == ai_usage_id for e in dataflow.edges)


def _control_by_id(controls: ControlAssessment, control_id: str) -> SecurityControl | None:
    for c in controls.controls:
        if c.control_id == control_id:
            return c
    return None


def _security_exposure_from_control(control: SecurityControl | None, detected: int, partial: int, not_detected: int) -> int:
    if control is None:
        return not_detected
    if control.status == STATUS_DETECTED:
        return detected
    if control.status == STATUS_PARTIAL:
        return partial
    if control.status == STATUS_NOT_DETECTED:
        return not_detected
    return partial  # UNKNOWN/other — treat as an unresolved middle ground, not the worst case


def _likelihood_from_control_and_confidence(control: SecurityControl | None, edge_confidence: str, detected: int, partial: int, not_detected_high: int, not_detected_moderate: int) -> int:
    status = control.status if control else STATUS_NOT_DETECTED
    if status == STATUS_DETECTED:
        return detected
    if status == STATUS_PARTIAL:
        return partial
    # NOT_DETECTED (or unresolved) — likelihood still capped by how direct the evidence is
    return not_detected_high if edge_confidence == "high" else not_detected_moderate


def _control_evidence_ref(control: SecurityControl | None) -> list[RiskEvidenceRef]:
    if control is None:
        return []
    return [
        RiskEvidenceRef(
            type="control",
            id=control.control_id,
            description=_redact(f"{control.control_id} {control.name}: {control.status} — {control.rationale}"),
        )
    ]


def _finding_evidence_ref(f: AIFinding, note: str) -> RiskEvidenceRef:
    text = _redact(f"{note}: {f.category}/{f.name} at {f.file}:{f.line} — \"{f.evidence}\"")
    return RiskEvidenceRef(type="finding", id=f.id, description=text)


def _dataflow_evidence_ref(e: DataFlowObservation, note: str) -> RiskEvidenceRef:
    # Defense-in-depth: DataFlowObservation.evidence is a synthesized category/line
    # description today, not a literal source-line reproduction, so it can't
    # currently carry a raw secret — but the redaction boundary must hold
    # regardless of what any given evidence string happens to contain, not rely on
    # today's field semantics staying that way.
    text = _redact(f"{note}: {e.relationship} ({e.confidence} confidence), {e.evidence}")
    return RiskEvidenceRef(type="dataflow", id=_edge_key(e), description=text)


def assess_risks(
    discovery: DiscoveryResult,
    attack_surface: AttackSurfaceResult,
    dataflow: DataFlowGraph,
    controls: ControlAssessment,
) -> RiskAssessment:
    """Deterministic, evidence-backed risk scenario generation.

    Consumes discovery/attack-surface/data-flow/control results — performs no new
    repository scan. Generates zero or more RiskScenario objects grouped by coherent
    evidence chains (never one scenario per individual finding), each scored with the
    framework's unmodified four-factor formula.
    """
    root = discovery.root
    completeness = COMPLETENESS_PARTIAL if discovery.truncated else COMPLETENESS_COMPLETE

    if not discovery.has_ai_signal():
        return RiskAssessment(
            root=root,
            ai_surface_detected=False,
            assessment_completeness=completeness,
            scenarios=[],
            summary_note="No AI components were discovered in this repository — no AI security risk scenarios were generated.",
        )

    by_category: dict[str, list[AIFinding]] = {}
    for f in discovery.findings:
        by_category.setdefault(f.category, []).append(f)

    ai_usage = by_category.get("ai_usage", [])
    tool_agent = by_category.get("tool_agent", [])
    mcp = by_category.get("mcp", [])
    rag_retrieval = by_category.get("rag_retrieval", [])
    external_integration = by_category.get("external_integration", [])
    secret_config = by_category.get("secret_config", [])

    from .controls import DB_EXTERNAL_NAMES  # local import: avoid a module-level cycle risk

    db_integrations = [f for f in external_integration if f.name in DB_EXTERNAL_NAMES]

    c03 = _control_by_id(controls, "C03")
    c04 = _control_by_id(controls, "C04")
    c05 = _control_by_id(controls, "C05")
    c09 = _control_by_id(controls, "C09")
    c10 = _control_by_id(controls, "C10")
    c11 = _control_by_id(controls, "C11")
    c12 = _control_by_id(controls, "C12")

    scenarios: list[RiskScenario] = []
    consumed_ai_usage_ids: set[str] = set()

    # ---- TOOL_SECURITY / HIGH_IMPACT_ACTION: ai_usage -> tool_agent -------
    tool_edges = [e for e in dataflow.edges if e.relationship in {"invokes_tool", "flows_to_output"}]
    high_impact_edges = [e for e in tool_edges if e.relationship == "flows_to_output"]
    generic_tool_edges = [e for e in tool_edges if e.relationship == "invokes_tool"]

    if high_impact_edges:
        consumed_ai_usage_ids.update(e.source_finding_id for e in high_impact_edges)
        edge_conf = _best_edge_confidence(high_impact_edges)
        exposure = 3 if any(_has_upstream_prompt_chain(e.source_finding_id, dataflow) for e in high_impact_edges) else 2
        security_exposure = _security_exposure_from_control(c12, detected=2, partial=3, not_detected=5)
        likelihood = _likelihood_from_control_and_confidence(c12, edge_conf, detected=2, partial=3, not_detected_high=4, not_detected_moderate=3)
        safety_impact = 5
        score = score_risk(exposure, safety_impact, security_exposure, likelihood)
        related_findings = {e.source_finding_id for e in high_impact_edges} | {e.destination_finding_id for e in high_impact_edges}
        scenarios.append(
            RiskScenario(
                risk_id=_risk_id("HIGH_IMPACT_ACTION", sorted(related_findings)),
                title="AI-connected high-impact action (shell/dynamic-code execution) "
                + ("without detected authorization control" if not c12 or c12.status != STATUS_DETECTED else "with recognized authorization control"),
                category="HIGH_IMPACT_ACTION",
                score=score, severity=severity_for(score),
                exposure=exposure, safety_impact=safety_impact, security_exposure=security_exposure, likelihood=likelihood,
                confidence=edge_conf,
                rationale=(
                    "Repository evidence shows an AI-connected path to a high-impact "
                    "shell/dynamic-code-execution capability (Phase 3 data-flow evidence). "
                    f"C12 High-Risk Action Controls status: {c12.status if c12 else 'UNKNOWN'}. "
                    "This assessment does not establish exploitability."
                ),
                evidence=[_dataflow_evidence_ref(e, "Model-to-sink data flow") for e in high_impact_edges] + _control_evidence_ref(c12),
                related_finding_ids=sorted(related_findings),
                related_dataflow_ids=sorted({_edge_key(e) for e in high_impact_edges}),
                related_control_ids=["C12"] if c12 else [],
            )
        )

    if generic_tool_edges:
        consumed_ai_usage_ids.update(e.source_finding_id for e in generic_tool_edges)
        edge_conf = _best_edge_confidence(generic_tool_edges)
        exposure = 3 if any(_has_upstream_prompt_chain(e.source_finding_id, dataflow) for e in generic_tool_edges) else 2
        security_exposure = _security_exposure_from_control(c05, detected=2, partial=3, not_detected=4)
        likelihood = _likelihood_from_control_and_confidence(c05, edge_conf, detected=2, partial=3, not_detected_high=3, not_detected_moderate=2)
        safety_impact = 3
        score = score_risk(exposure, safety_impact, security_exposure, likelihood)
        related_findings = {e.source_finding_id for e in generic_tool_edges} | {e.destination_finding_id for e in generic_tool_edges}
        scenarios.append(
            RiskScenario(
                risk_id=_risk_id("TOOL_SECURITY", sorted(related_findings)),
                title="AI-connected tool execution "
                + ("without detected authorization control" if not c05 or c05.status != STATUS_DETECTED else "with recognized authorization control"),
                category="TOOL_SECURITY",
                score=score, severity=severity_for(score),
                exposure=exposure, safety_impact=safety_impact, security_exposure=security_exposure, likelihood=likelihood,
                confidence=edge_conf,
                rationale=(
                    "Repository evidence shows a model invocation data-flow-connected to tool "
                    f"execution. C05 Tool Authorization status: {c05.status if c05 else 'UNKNOWN'}. "
                    "This assessment does not establish exploitability."
                ),
                evidence=[_dataflow_evidence_ref(e, "Model-to-tool data flow") for e in generic_tool_edges] + _control_evidence_ref(c05),
                related_finding_ids=sorted(related_findings),
                related_dataflow_ids=sorted({_edge_key(e) for e in generic_tool_edges}),
                related_control_ids=["C05"] if c05 else [],
            )
        )

    # ---- EXTERNAL_INTEGRATION: ai_usage -> external_integration (non-DB) --
    ext_edges = [
        e for e in dataflow.edges
        if e.relationship == "calls_external_service"
        and e.destination_finding_id not in {f.id for f in db_integrations}
    ]
    if ext_edges:
        consumed_ai_usage_ids.update(e.source_finding_id for e in ext_edges)
        edge_conf = _best_edge_confidence(ext_edges)
        has_secret_nearby = bool(secret_config)
        exposure = 3 if any(_has_upstream_prompt_chain(e.source_finding_id, dataflow) for e in ext_edges) else 2
        security_exposure = 4 if has_secret_nearby else 3
        likelihood = 3 if edge_conf == "high" else 2
        safety_impact = 3
        score = score_risk(exposure, safety_impact, security_exposure, likelihood)
        related_findings = {e.source_finding_id for e in ext_edges} | {e.destination_finding_id for e in ext_edges}
        scenarios.append(
            RiskScenario(
                risk_id=_risk_id("EXTERNAL_INTEGRATION", sorted(related_findings)),
                title="AI-connected outbound external service call",
                category="EXTERNAL_INTEGRATION",
                score=score, severity=severity_for(score),
                exposure=exposure, safety_impact=safety_impact, security_exposure=security_exposure, likelihood=likelihood,
                confidence=edge_conf,
                rationale=(
                    "Repository evidence shows a model invocation data-flow-connected to an "
                    "outbound external service call. No dedicated control was defined for this "
                    "category in Phase 4; security exposure reflects whether credential evidence "
                    "was also found in the same file. This assessment does not establish "
                    "exploitability or confirm data actually leaves the trust boundary."
                ),
                evidence=[_dataflow_evidence_ref(e, "Model-to-external-call data flow") for e in ext_edges],
                related_finding_ids=sorted(related_findings),
                related_dataflow_ids=sorted({_edge_key(e) for e in ext_edges}),
                related_control_ids=[],
            )
        )

    # ---- DATA_ACCESS: ai_usage + DB/data-store client ----------------------
    if ai_usage and db_integrations:
        related_findings = {f.id for f in ai_usage} | {f.id for f in db_integrations}
        exposure = 3 if any(_has_upstream_prompt_chain(f.id, dataflow) for f in ai_usage) else 2
        security_exposure = _security_exposure_from_control(c11, detected=2, partial=3, not_detected=4)
        likelihood = 3 if (not c11 or c11.status == STATUS_NOT_DETECTED) else 2
        safety_impact = 4
        score = score_risk(exposure, safety_impact, security_exposure, likelihood)
        scenarios.append(
            RiskScenario(
                risk_id=_risk_id("DATA_ACCESS", sorted(related_findings)),
                title="AI access to a database/data-store without detected access-control evidence"
                if not c11 or c11.status != STATUS_DETECTED else "AI access to a database/data-store with recognized access-control evidence",
                category="DATA_ACCESS",
                score=score, severity=severity_for(score),
                exposure=exposure, safety_impact=safety_impact, security_exposure=security_exposure, likelihood=likelihood,
                confidence="moderate",
                rationale=(
                    "Repository evidence shows AI usage alongside a database/data-store client "
                    f"in the same repository. C11 AI Data Access status: {c11.status if c11 else 'UNKNOWN'}. "
                    "This assessment does not confirm the AI path and the data access are the "
                    "same code path, only that both exist in the repository's AI surface."
                ),
                evidence=[_finding_evidence_ref(f, "Database/data-store client") for f in db_integrations] + _control_evidence_ref(c11),
                related_finding_ids=sorted(related_findings),
                related_dataflow_ids=[],
                related_control_ids=["C11"] if c11 else [],
            )
        )

    # ---- RAG_SECURITY: rag_retrieval -> ai_usage ---------------------------
    rag_edges = [e for e in dataflow.edges if e.relationship == "retrieved_context"]
    if rag_edges:
        edge_conf = _best_edge_confidence(rag_edges)
        also_feeds_tool = any(e.source_finding_id in {ge.source_finding_id for ge in tool_edges} for e in rag_edges) or any(
            e.destination_finding_id in {ge.source_finding_id for ge in tool_edges} for e in rag_edges
        )
        exposure = 3 if any(f.name == "Webhook" for f in external_integration) else 2
        safety_impact = 3 if also_feeds_tool else 2
        security_exposure = _security_exposure_from_control(c09, detected=2, partial=3, not_detected=4)
        likelihood = _likelihood_from_control_and_confidence(c09, edge_conf, detected=2, partial=2, not_detected_high=3, not_detected_moderate=2)
        score = score_risk(exposure, safety_impact, security_exposure, likelihood)
        related_findings = {e.source_finding_id for e in rag_edges} | {e.destination_finding_id for e in rag_edges}
        scenarios.append(
            RiskScenario(
                risk_id=_risk_id("RAG_SECURITY", sorted(related_findings)),
                title="Retrieved content feeds model context without detected retrieval-security control"
                if not c09 or c09.status != STATUS_DETECTED else "Retrieved content feeds model context with recognized retrieval-security control",
                category="RAG_SECURITY",
                score=score, severity=severity_for(score),
                exposure=exposure, safety_impact=safety_impact, security_exposure=security_exposure, likelihood=likelihood,
                confidence=edge_conf,
                rationale=(
                    "Repository evidence shows retrieved content flowing into model context. "
                    f"C09 RAG/Retrieval Security status: {c09.status if c09 else 'UNKNOWN'}. "
                    "This assessment does not confirm retrieval poisoning is possible, only that "
                    "the retrieval-to-model relationship exists without demonstrated filtering."
                ),
                evidence=[_dataflow_evidence_ref(e, "Retrieval-to-model data flow") for e in rag_edges] + _control_evidence_ref(c09),
                related_finding_ids=sorted(related_findings),
                related_dataflow_ids=sorted({_edge_key(e) for e in rag_edges}),
                related_control_ids=["C09"] if c09 else [],
            )
        )

    # ---- MCP_SECURITY: mcp findings ----------------------------------------
    if mcp:
        exposure = 2  # no evidence basis to claim external reachability without more signal
        safety_impact = 4  # MCP tool surfaces are typically capability-rich
        security_exposure = _security_exposure_from_control(c10, detected=2, partial=3, not_detected=4)
        likelihood = 3 if (not c10 or c10.status == STATUS_NOT_DETECTED) else 2
        score = score_risk(exposure, safety_impact, security_exposure, likelihood)
        related_findings = {f.id for f in mcp}
        scenarios.append(
            RiskScenario(
                risk_id=_risk_id("MCP_SECURITY", sorted(related_findings)),
                title="MCP tool/server surface without detected governance control"
                if not c10 or c10.status != STATUS_DETECTED else "MCP tool/server surface with recognized governance control",
                category="MCP_SECURITY",
                score=score, severity=severity_for(score),
                exposure=exposure, safety_impact=safety_impact, security_exposure=security_exposure, likelihood=likelihood,
                confidence="moderate",
                rationale=(
                    "Repository evidence shows MCP tool/server configuration. "
                    f"C10 MCP/Tool Governance status: {c10.status if c10 else 'UNKNOWN'}. "
                    "MCP configuration existing is not, by itself, evidence of exploitability — "
                    "this reflects capability presence without demonstrated scoping."
                ),
                evidence=[_finding_evidence_ref(f, "MCP surface") for f in mcp] + _control_evidence_ref(c10),
                related_finding_ids=sorted(related_findings),
                related_dataflow_ids=[],
                related_control_ids=["C10"] if c10 else [],
            )
        )

    # ---- SECRET_EXPOSURE: hardcoded credential -----------------------------
    hardcoded = [f for f in secret_config if f.name == HARDCODED_SECRET_NAME]
    if hardcoded:
        exposure = 2
        safety_impact = 4
        security_exposure = 5
        likelihood = 4
        score = score_risk(exposure, safety_impact, security_exposure, likelihood)
        related_findings = {f.id for f in hardcoded}
        scenarios.append(
            RiskScenario(
                risk_id=_risk_id("SECRET_EXPOSURE", sorted(related_findings)),
                title="Hardcoded AI credential in source",
                category="SECRET_EXPOSURE",
                score=score, severity=severity_for(score),
                exposure=exposure, safety_impact=safety_impact, security_exposure=security_exposure, likelihood=likelihood,
                confidence="high",
                rationale=(
                    "A pattern matching a hardcoded API key was found directly in source. "
                    "The credential value itself is redacted from this assessment. This finding "
                    "is direct evidence of the credential's presence in the repository, not proof "
                    "that the credential is still valid or has been misused."
                ),
                evidence=[_finding_evidence_ref(f, "Hardcoded credential") for f in hardcoded],
                related_finding_ids=sorted(related_findings),
                related_dataflow_ids=[],
                related_control_ids=["C08"],
            )
        )

    # ---- INPUT_SECURITY / OUTPUT_SECURITY: no-sink ai_usage ----------------
    unconsumed_ai_usage = [f for f in ai_usage if f.id not in consumed_ai_usage_ids]
    prompt_fed_unconsumed = [f for f in unconsumed_ai_usage if _has_upstream_prompt_chain(f.id, dataflow)]

    if prompt_fed_unconsumed:
        edges = [e for e in dataflow.edges if e.relationship == "feeds_prompt" and e.destination_finding_id in {f.id for f in prompt_fed_unconsumed}]
        edge_conf = _best_edge_confidence(edges)
        security_exposure = _security_exposure_from_control(c03, detected=1, partial=2, not_detected=3)
        likelihood = _likelihood_from_control_and_confidence(c03, edge_conf, detected=1, partial=2, not_detected_high=3, not_detected_moderate=2)
        exposure = 2
        safety_impact = 2
        score = score_risk(exposure, safety_impact, security_exposure, likelihood)
        related_findings = {f.id for f in prompt_fed_unconsumed} | {e.source_finding_id for e in edges}
        scenarios.append(
            RiskScenario(
                risk_id=_risk_id("INPUT_SECURITY", sorted(related_findings)),
                title="User-influenced prompt path without detected input-handling control"
                if not c03 or c03.status != STATUS_DETECTED else "User-influenced prompt path with recognized input-handling control",
                category="INPUT_SECURITY",
                score=score, severity=severity_for(score),
                exposure=exposure, safety_impact=safety_impact, security_exposure=security_exposure, likelihood=likelihood,
                confidence=edge_conf,
                rationale=(
                    "Repository evidence shows a prompt-construction path feeding a model call "
                    f"with no downstream tool/external/data sink detected. C03 Input Handling "
                    f"status: {c03.status if c03 else 'UNKNOWN'}. This assessment does not confirm "
                    "prompt injection is possible."
                ),
                evidence=[_dataflow_evidence_ref(e, "Prompt-to-model data flow") for e in edges] + _control_evidence_ref(c03),
                related_finding_ids=sorted(related_findings),
                related_dataflow_ids=sorted({_edge_key(e) for e in edges}),
                related_control_ids=["C03"] if c03 else [],
            )
        )

    output_candidates = [f for f in unconsumed_ai_usage if c04 is not None and c04.status != STATUS_DETECTED]
    if output_candidates and (not c04 or c04.status != STATUS_DETECTED):
        security_exposure = _security_exposure_from_control(c04, detected=1, partial=2, not_detected=3)
        likelihood = 2 if (not c04 or c04.status == STATUS_NOT_DETECTED) else 1
        exposure = 2
        safety_impact = 2
        score = score_risk(exposure, safety_impact, security_exposure, likelihood)
        related_findings = {f.id for f in output_candidates}
        scenarios.append(
            RiskScenario(
                risk_id=_risk_id("OUTPUT_SECURITY", sorted(related_findings)),
                title="Model output without detected output-handling control",
                category="OUTPUT_SECURITY",
                score=score, severity=severity_for(score),
                exposure=exposure, safety_impact=safety_impact, security_exposure=security_exposure, likelihood=likelihood,
                confidence="moderate",
                rationale=(
                    "Repository evidence shows model invocation with no downstream tool/external/"
                    "data sink and no detected output-validation evidence. "
                    f"C04 Output Handling status: {c04.status if c04 else 'UNKNOWN'}. This assessment "
                    "does not confirm the output is used unsafely."
                ),
                evidence=[
                    _finding_evidence_ref(f, "Model invocation without downstream sink") for f in output_candidates
                ] + _control_evidence_ref(c04),
                related_finding_ids=sorted(related_findings),
                related_dataflow_ids=[],
                related_control_ids=["C04"] if c04 else [],
            )
        )

    scenarios.sort(key=lambda s: s.risk_id)

    summary_note = (
        f"{len(scenarios)} AI security risk scenario(s) generated from available repository evidence."
        if scenarios
        else "No AI security risk scenarios were generated from the available repository evidence. "
        "This does not mean the repository is secure — only that this scanner's evidence-based "
        "criteria did not identify a risk-worthy combination."
    )
    if completeness == COMPLETENESS_PARTIAL:
        summary_note += " Assessment may be incomplete because discovery results were truncated."

    return RiskAssessment(
        root=root,
        ai_surface_detected=True,
        assessment_completeness=completeness,
        scenarios=scenarios,
        summary_note=summary_note,
    )
