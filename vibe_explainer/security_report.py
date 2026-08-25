"""Integrated AI security report — Phase 7 product layer.

Consumes the outputs of Phases 1-6 (discovery, attack surface, data flow, controls,
risk, readiness) and assembles them into one report object plus a human-readable and
a JSON rendering. Performs NO scanning, scoring, or classification of its own — every
number here traces back to an earlier phase.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

from . import __version__
from .ai_discovery import DiscoveryResult
from .attack_surface import BUCKETS, AttackSurfaceResult
from .controls import ControlAssessment
from .dataflow import DataFlowGraph
from .readiness import NO_AI_SURFACE, ReadinessAssessment
from .risk import RiskAssessment

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "LOW": 3}
_LEVEL_ORDER = (1, 2, 3, 4)

# Controls whose absence is worth a standalone recommendation when the relevant
# surface exists and no risk scenario already covers it via related_control_ids.
_NOTABLE_CONTROLS = {"C05", "C08", "C09", "C10", "C12"}

_STANDARD_LIMITATIONS = [
    "Static, regex/keyword-based analysis only — no AST parsing, no control-flow "
    "graph, no import-graph resolution.",
    "Data-flow relationships are same-file only; cross-file flows are not "
    "established even when clearly implied by imports.",
    "No runtime verification of any kind — nothing in this pipeline executes the "
    "target application or confirms a path is actually reachable.",
    "Control and readiness evidence is keyword/path/header-based; a differently "
    "named function performing an identical check is invisible to this scanner.",
    "This report reflects repository evidence only — practices, controls, or "
    "processes that live outside the scanned repository are not visible here.",
]


def _redact_check(text: str) -> str:
    """Defense-in-depth: Phase 5 already redacts secret values in risk evidence; this
    re-applies the same pattern to any report-level string as a second guard."""
    from .risk import _redact

    return _redact(text)


@dataclass
class VibeExplainerReport:
    metadata: dict[str, Any]
    executive_summary: dict[str, Any]
    ai_inventory: dict[str, Any]
    attack_surface: dict[str, Any]
    data_flows: list[dict[str, Any]]
    controls: dict[str, Any]
    risks: dict[str, Any]
    readiness: dict[str, Any]
    recommendations: list[dict[str, Any]]
    limitations: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "metadata": self.metadata,
            "executive_summary": self.executive_summary,
            "ai_inventory": self.ai_inventory,
            "attack_surface": self.attack_surface,
            "data_flows": self.data_flows,
            "controls": self.controls,
            "risks": self.risks,
            "readiness": self.readiness,
            "recommendations": self.recommendations,
            "limitations": self.limitations,
        }

    def to_json(self) -> str:
        """Deterministic, ANSI-free JSON serialization of the complete report."""
        return json.dumps(self.to_dict(), indent=2, sort_keys=False, ensure_ascii=False)


def build_report(
    discovery: DiscoveryResult,
    attack_surface: AttackSurfaceResult,
    dataflow: DataFlowGraph,
    controls: ControlAssessment,
    risks: RiskAssessment,
    readiness: ReadinessAssessment,
) -> VibeExplainerReport:
    """Assemble the full report from already-computed Phase 1-6 results. No new
    scanning, scoring, or classification happens here."""

    metadata = {
        "tool": "vibe-explainer",
        "version": __version__,
        "schema_version": "1.0",
        "repository": discovery.root,
        "assessment_completeness": readiness.assessment_completeness,
    }

    ai_surface_detected = discovery.has_ai_signal()
    highest_severity = None
    if risks.scenarios:
        highest_severity = min(risks.scenarios, key=lambda s: _SEVERITY_ORDER.get(s.severity, 99)).severity

    if not ai_surface_detected:
        statement = "No AI security assessment was generated because no AI surface was detected."
    else:
        statement = (
            f"{len(risks.scenarios)} AI security risk scenario(s) identified. "
            f"AI security readiness assessed as {readiness.readiness_name}."
        )

    executive_summary = {
        "ai_surface": "DETECTED" if ai_surface_detected else "NOT_DETECTED",
        "risk_scenario_count": len(risks.scenarios),
        "highest_risk_severity": highest_severity,
        "readiness_level": readiness.readiness_level,
        "readiness_name": readiness.readiness_name,
        "assessment_completeness": readiness.assessment_completeness,
        "statement": statement,
    }

    # ---- AI inventory: grouped by discovery category -----------------------
    by_category: dict[str, list[dict[str, Any]]] = {}
    for f in discovery.findings:
        by_category.setdefault(f.category, []).append(
            {
                "id": f.id,
                "file": f.file,
                "line": f.line,
                "name": f.name,
                "evidence": _redact_check(f.evidence),
                "confidence": f.confidence,
            }
        )
    for items in by_category.values():
        items.sort(key=lambda i: (i["file"], i["line"], i["id"]))
    ai_inventory = {
        "categories": dict(sorted(by_category.items())),
        "truncated": [t.to_dict() for t in discovery.truncated],
        "truncation_notice": "Discovery results were truncated; inventory may be incomplete." if discovery.truncated else None,
    }

    # ---- Attack surface: all six buckets, always present -------------------
    by_bucket = attack_surface.by_bucket()
    attack_surface_out = {
        b: [
            {
                "component": f"{i.category}/{i.name}",
                "file": i.file,
                "line": i.line,
                "evidence": _redact_check(i.evidence),
                "confidence": i.confidence,
                "finding_id": i.finding_id,
                "security_relevance": i.security_relevance,
            }
            for i in sorted(by_bucket[b], key=lambda i: (i.file, i.line, i.finding_id))
        ]
        for b in BUCKETS
    }

    # ---- Data flows: meaningful edges only ----------------------------------
    data_flows_out = [
        {
            "source": e.source_type,
            "relationship": e.relationship,
            "destination": e.destination_type,
            "confidence": e.confidence,
            "status": e.status,
            "file": e.file,
            "source_line": e.source_line,
            "destination_line": e.destination_line,
            "evidence": _redact_check(e.evidence),
        }
        for e in dataflow.edges
    ]

    # ---- Controls: grouped by status -----------------------------------------
    controls_by_status: dict[str, list[dict[str, Any]]] = {"DETECTED": [], "PARTIAL": [], "NOT_DETECTED": [], "NOT_APPLICABLE": [], "UNKNOWN": []}
    for c in controls.controls:
        controls_by_status.setdefault(c.status, []).append(
            {
                "control_id": c.control_id,
                "name": c.name,
                "category": c.category,
                "confidence": c.confidence,
                "rationale": _redact_check(c.rationale),
                "evidence": [{**e.to_dict(), "description": _redact_check(e.description)} for e in c.evidence],
                "related_finding_ids": c.related_finding_ids,
                "related_dataflow_ids": c.related_dataflow_ids,
            }
        )
    controls_out = {"by_status": controls_by_status, "note": "NOT_DETECTED means no supporting evidence was found in this repository — not that the control definitely does not exist."}

    # ---- Risks: severity distribution + deterministically sorted list -------
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MODERATE": 0, "LOW": 0}
    for s in risks.scenarios:
        severity_counts[s.severity] = severity_counts.get(s.severity, 0) + 1
    sorted_scenarios = sorted(
        risks.scenarios,
        key=lambda s: (_SEVERITY_ORDER.get(s.severity, 99), -s.score, s.category, s.risk_id),
    )
    risks_out = {
        "total": len(risks.scenarios),
        "by_severity": severity_counts,
        "ai_surface_detected": risks.ai_surface_detected,
        "summary_note": risks.summary_note,
        "scenarios": [
            {
                "risk_id": s.risk_id,
                "title": s.title,
                "category": s.category,
                "score": s.score,
                "severity": s.severity,
                "confidence": s.confidence,
                "rationale": _redact_check(s.rationale),
                "evidence": [{**e.to_dict(), "description": _redact_check(e.description)} for e in s.evidence],
                "related_finding_ids": s.related_finding_ids,
                "related_dataflow_ids": s.related_dataflow_ids,
                "related_control_ids": s.related_control_ids,
            }
            for s in sorted_scenarios
        ],
    }

    # ---- Readiness: pass through with blocker text --------------------------
    next_level_blocked_reason = None
    if readiness.readiness_level is not None and readiness.readiness_level < 4:
        next_la = next((la for la in readiness.level_assessments if la.level == readiness.readiness_level + 1), None)
        if next_la and next_la.missing_requirements:
            next_level_blocked_reason = next_la.missing_requirements[0]
    readiness_out = readiness.to_dict()
    readiness_out["blocked_from_next_level"] = next_level_blocked_reason

    # ---- Recommendations: derived from existing evidence, deduplicated ------
    recommendations: list[dict[str, Any]] = []
    covered_control_ids: set[str] = set()

    for s in sorted_scenarios:
        if s.severity not in ("CRITICAL", "HIGH", "MODERATE"):
            continue
        covered_control_ids.update(s.related_control_ids)
        recommendations.append(
            {
                "title": s.title,
                "why_it_matters": _redact_check(s.rationale),
                "evidence_summary": f"{len(s.evidence)} evidence item(s) — see risk {s.risk_id} for detail.",
                "suggested_action": _suggested_action_for(s.category),
                "related_risk_ids": [s.risk_id],
                "related_control_ids": s.related_control_ids,
                "_sort_key": (0, _SEVERITY_ORDER.get(s.severity, 99), -s.score),
            }
        )

    if next_level_blocked_reason:
        recommendations.append(
            {
                "title": f"Reach AI security readiness Level {min((readiness.readiness_level or 0) + 1, 4)}",
                "why_it_matters": next_level_blocked_reason,
                "evidence_summary": "See readiness level assessments for detail.",
                "suggested_action": "Address the listed missing requirement to progress readiness.",
                "related_risk_ids": [],
                "related_control_ids": [],
                "_sort_key": (1, 0, 0),
            }
        )

    for c in controls.controls:
        if c.status != "NOT_DETECTED":
            continue
        if c.control_id not in _NOTABLE_CONTROLS:
            continue
        if c.control_id in covered_control_ids:
            continue  # already represented by a risk-scenario recommendation above
        recommendations.append(
            {
                "title": f"{c.control_id} {c.name}: no supporting evidence detected",
                "why_it_matters": c.rationale,
                "evidence_summary": f"{len(c.related_finding_ids)} related finding(s).",
                "suggested_action": _suggested_action_for_control(c.control_id),
                "related_risk_ids": [],
                "related_control_ids": [c.control_id],
                "_sort_key": (2, 0, c.control_id),
            }
        )

    recommendations.sort(key=lambda r: r["_sort_key"])
    for idx, rec in enumerate(recommendations):
        rec["priority"] = f"P{idx}"
        del rec["_sort_key"]

    # ---- Limitations -----------------------------------------------------
    limitations = list(_STANDARD_LIMITATIONS)
    if discovery.truncated:
        limitations.append("Discovery results were truncated for this repository; findings, controls, risks, and readiness evidence may all be incomplete as a result.")
    for lim in readiness.limitations:
        if lim not in limitations:
            limitations.append(lim)

    return VibeExplainerReport(
        metadata=metadata,
        executive_summary=executive_summary,
        ai_inventory=ai_inventory,
        attack_surface=attack_surface_out,
        data_flows=data_flows_out,
        controls=controls_out,
        risks=risks_out,
        readiness=readiness_out,
        recommendations=recommendations,
        limitations=limitations,
    )


def _suggested_action_for(category: str) -> str:
    return {
        "HIGH_IMPACT_ACTION": "Require explicit authorization before invoking the high-impact tool and add a regression test covering unauthorized invocation.",
        "TOOL_SECURITY": "Add an authorization or permission check in front of the tool-invocation path and cover it with a test.",
        "EXTERNAL_INTEGRATION": "Review what data the outbound call sends and confirm the credential used is appropriately scoped.",
        "DATA_ACCESS": "Add row/tenant-scoped access control around the AI-adjacent database query.",
        "RAG_SECURITY": "Add source allowlisting or content filtering before retrieved content enters the model prompt.",
        "MCP_SECURITY": "Scope MCP tool permissions explicitly and default-deny unlisted tools.",
        "SECRET_EXPOSURE": "Move the credential to an environment variable or secret manager and rotate the exposed key.",
        "INPUT_SECURITY": "Add schema validation or sanitization on the user-influenced prompt path.",
        "OUTPUT_SECURITY": "Add schema validation or sanitization on model output before it's used downstream.",
    }.get(category, "Review the referenced evidence and add an appropriate control.")


def _suggested_action_for_control(control_id: str) -> str:
    return {
        "C05": "Add authorization checks in front of tool-invocation paths.",
        "C08": "Move AI credentials to environment variables or a secret manager.",
        "C09": "Add source/content filtering to the retrieval pipeline.",
        "C10": "Add scoped permissions and default-deny to MCP tool configuration.",
        "C12": "Add sandboxing, confirmation, or an explicit allowlist around high-risk actions.",
    }.get(control_id, "Review the referenced control gap and add appropriate evidence.")


_LEVEL_DISPLAY = {1: "BASELINE", 2: "MANAGED", 3: "HARDENED", 4: "CONTINUOUS"}


def render_text(report: VibeExplainerReport) -> str:
    """Human-readable terminal rendering of the full report. Deterministic — same
    report object always produces the same text."""
    lines: list[str] = []
    add = lines.append
    sep = "─" * 40

    add("VIBE EXPLAINER")
    add("AI SECURITY ASSESSMENT")
    add(sep)
    add("")

    es = report.executive_summary
    add(f"AI SURFACE\n{es['ai_surface']}")
    add("")
    if es["ai_surface"] == "NOT_DETECTED":
        add(es["statement"])
        add("")
        add(sep)
        _render_limitations(add, report)
        return "\n".join(lines)

    add(f"RISKS\n{es['risk_scenario_count']} scenario(s)")
    add(f"Highest: {es['highest_risk_severity'] or 'none'}")
    add("")
    level = es["readiness_level"]
    level_display = f"Level {level} — {_LEVEL_DISPLAY.get(level, es['readiness_name'])}" if level else es["readiness_name"]
    add(f"READINESS\n{level_display}")
    if es["assessment_completeness"] == "PARTIAL":
        add("(assessment PARTIAL — discovery results were truncated)")
    add("")
    add(sep)

    if report.risks["scenarios"]:
        add("TOP RISKS")
        add("")
        for s in report.risks["scenarios"][:5]:
            add(f"{s['severity']:<9} {s['title']}")
            add(f"{'':<9} {s['rationale'][:100]}{'...' if len(s['rationale']) > 100 else ''}")
            add("")
        add(sep)

    add("READINESS")
    add("")
    for la in report.readiness["level_assessments"]:
        status_display = "ACHIEVED" if la["status"] == "ACHIEVED" else ("BLOCKED" if la["status"] == "NOT_ACHIEVED" else la["status"])
        add(f"Level {la['level']}  {_LEVEL_DISPLAY[la['level']]:<12} {status_display}")
        if la["status"] != "ACHIEVED" and la["missing_requirements"]:
            add(f"         └─ {la['missing_requirements'][0]}")
    add("")
    add(sep)

    if report.recommendations:
        add("RECOMMENDED ACTIONS")
        add("")
        for rec in report.recommendations[:10]:
            add(f"{rec['priority']}  {rec['title']}")
        add("")
        add(sep)

    _render_limitations(add, report)
    return "\n".join(lines)


def _render_limitations(add, report: VibeExplainerReport) -> None:
    add("ASSESSMENT LIMITATIONS")
    add("")
    for lim in report.limitations:
        add(f"- {lim}")
