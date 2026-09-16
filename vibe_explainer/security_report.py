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
from .context_classifier import CONTEXT_PRODUCTION, classify_path

# Fine-grained contexts (Phase 8) that count as production-relevant in the report.
_PRODUCTION_RELEVANT_REPORT_CONTEXTS = frozenset({"PRODUCTION", "CONFIGURATION", "UNKNOWN"})
from .controls import ControlAssessment
from .dataflow import DataFlowGraph
from .readiness import NO_AI_SURFACE, ReadinessAssessment
from .risk import RiskAssessment
from .security_utils import redact_secrets, redact_structure

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "LOW": 3}
_LEVEL_ORDER = (1, 2, 3, 4)

# Controls whose absence is worth a standalone recommendation when the relevant
# surface exists and no risk scenario already covers it via related_control_ids.
_NOTABLE_CONTROLS = {"C05", "C08", "C09", "C10", "C12"}

_STANDARD_LIMITATIONS = [
    "Static analysis only — general discovery is primarily lexical, with targeted syntax "
    "inspection for Python imports and security-test assertions; there is no control-flow graph.",
    "Relationship observations use bounded same-file and import-resolution heuristics; they "
    "do not establish runtime data flow.",
    "No runtime verification of any kind — nothing in this pipeline executes the "
    "target application or confirms a path is actually reachable.",
    "Control discovery begins with named patterns and uses conservative Python AST relationships; "
    "differently named or dynamically wired controls may remain invisible.",
    "This report reflects repository evidence only — practices, controls, or "
    "processes that live outside the scanned repository are not visible here.",
    "Redaction is defense-in-depth, not a guarantee. Treat generated reports as sensitive, "
    "restrict access, define a retention period, and securely delete them when no longer needed.",
]


def _redact_check(text: str) -> str:
    """Defense-in-depth: Phase 5 already redacts secret values in risk evidence; this
    re-applies the same pattern to any report-level string as a second guard."""
    return redact_secrets(text)


def _repo_name(root: str) -> str:
    """Extract a display name (the project's directory name) from a repository root
    path, handling both POSIX and Windows separators and trailing slashes. Falls back
    to the raw string if no basename can be derived. This keeps an assessor's local
    filesystem layout out of the deliverable header."""
    if not root:
        return "repository"
    normalized = root.replace("\\", "/").rstrip("/")
    # Drop a Windows drive prefix like "C:" if that's somehow all that's left.
    name = normalized.rsplit("/", 1)[-1]
    if not name or name.endswith(":"):
        return normalized or "repository"
    return name


@dataclass
class VibeExplainerReport:
    metadata: dict[str, Any]
    executive_summary: dict[str, Any]
    ai_inventory: dict[str, Any]
    attack_surface: dict[str, Any]
    data_flows: list[dict[str, Any]]
    unresolved_relationships: list[dict[str, Any]]
    controls: dict[str, Any]
    risks: dict[str, Any]
    readiness: dict[str, Any]
    recommendations: list[dict[str, Any]]
    limitations: list[str]

    def to_dict(self) -> dict[str, Any]:
        return redact_structure({
            "metadata": self.metadata,
            "executive_summary": self.executive_summary,
            "ai_inventory": self.ai_inventory,
            "attack_surface": self.attack_surface,
            "data_flows": self.data_flows,
            "unresolved_relationships": self.unresolved_relationships,
            "controls": self.controls,
            "risks": self.risks,
            "readiness": self.readiness,
            "recommendations": self.recommendations,
            "limitations": self.limitations,
        })

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
    *,
    include_experimental_scoring: bool = False,
) -> VibeExplainerReport:
    """Assemble the full report from already-computed Phase 1-6 results. No new
    scanning, scoring, or classification happens here."""

    # Repository identity: the project name (basename) is what belongs in a
    # deliverable. The full local path is retained separately for traceability but
    # is not what a report header should expose — the first real-world run leaked
    # an assessor's local path (C:\Users\...\aletheia-core) into the report header.
    repo_name = _repo_name(discovery.root)

    metadata = {
        "tool": "vibe-explainer",
        "version": __version__,
        "schema_version": "2.0",
        "repository": repo_name,
        "repository_path": discovery.root,
        "assessment_completeness": readiness.assessment_completeness,
        "experimental_scoring_enabled": include_experimental_scoring,
    }

    ai_surface_detected = discovery.has_ai_signal()
    # Context breakdown: how much of the discovered surface is production code vs
    # test/example/doc/generated content. This is the key signal the first
    # real-world run (aletheia-core) showed was missing — a production webhook and
    # a test-fixture string were indistinguishable in the report.
    context_counts: dict[str, int] = {}
    production_findings = 0
    defaulted_production_findings = 0
    for f in discovery.findings:
        ctx = getattr(f, "context", None) or classify_path(f.file)
        context_counts[ctx] = context_counts.get(ctx, 0) + 1
        if ctx in _PRODUCTION_RELEVANT_REPORT_CONTEXTS:
            production_findings += 1
        if ctx == CONTEXT_PRODUCTION and getattr(f, "context_defaulted", False):
            defaulted_production_findings += 1

    if not ai_surface_detected:
        statement = "No AI evidence review sections were generated because no supported AI-related signal was detected."
    else:
        if include_experimental_scoring:
            statement = (
                f"{len(risks.scenarios)} static concern scenario(s) generated from repository evidence. "
                "Uncalibrated experimental scoring and process classification were explicitly enabled."
            )
        else:
            statement = (
                f"{len(risks.scenarios)} static concern scenario(s) generated from repository evidence. "
                "Concern scenarios are unscored and process evidence is reported as a checklist."
            )

    executive_summary = {
        "ai_surface": "DETECTED" if ai_surface_detected else "NOT_DETECTED",
        "risk_scenario_count": len(risks.scenarios),
        "assessment_completeness": readiness.assessment_completeness,
        "total_findings": len(discovery.findings),
        "production_findings": production_findings,
        "defaulted_production_findings": defaulted_production_findings,
        "findings_by_context": dict(sorted(context_counts.items())),
        "statement": statement,
    }
    if include_experimental_scoring:
        highest_severity = None
        if risks.scenarios:
            highest_severity = min(
                risks.scenarios, key=lambda s: _SEVERITY_ORDER.get(s.severity, 99)
            ).severity
        executive_summary.update(
            {
                "highest_risk_severity": highest_severity,
                "readiness_level": readiness.readiness_level,
                "readiness_name": readiness.readiness_name,
            }
        )

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
                "context": getattr(f, "context", None) or classify_path(f.file),
                "context_confidence": getattr(f, "context_confidence", "moderate"),
                "context_defaulted": getattr(f, "context_defaulted", False),
            }
        )
    for items in by_category.values():
        items.sort(key=lambda i: (i["file"], i["line"], i["id"]))
    ai_inventory = {
        "categories": dict(sorted(by_category.items())),
        "truncated": [t.to_dict() for t in discovery.truncated],
        "truncation_notice": (
            "Some files contained many repeated matches of the same pattern; these were "
            "summarized with exact counts (see per-group totals). All matches were counted — "
            "nothing was left unassessed."
        ) if discovery.truncated else None,
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
                "context": getattr(i, "context", None) or classify_path(i.file),
                "context_defaulted": getattr(i, "context_defaulted", False),
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
            "resolution_method": getattr(e, "resolution_method", "PYTHON_DEF_USE"),
            "source_file": getattr(e, "source_file", "") or e.file,
            "destination_file": getattr(e, "destination_file", "") or e.file,
            "evidence": _redact_check(e.evidence),
        }
        for e in dataflow.edges
    ]

    # ---- Controls: grouped by status -----------------------------------------
    controls_by_status: dict[str, list[dict[str, Any]]] = {"EVIDENCE_FOUND": [], "PARTIAL": [], "NOT_FOUND": [], "NOT_APPLICABLE": [], "UNKNOWN": []}
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
                "artifact_status": c.artifact_status,
                "enforcement_status": c.enforcement_status,
                "effectiveness_status": c.effectiveness_status,
                "uncovered_surfaces": c.uncovered_surfaces,
            }
        )
    controls_out = {"by_status": controls_by_status, "note": "Artifact presence, structural enforcement, and runtime effectiveness are independent. NOT_FOUND does not prove absence outside this repository."}

    # ---- Concerns: unscored by default; legacy formula is explicit opt-in ----
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MODERATE": 0, "LOW": 0}
    for s in risks.scenarios:
        severity_counts[s.severity] = severity_counts.get(s.severity, 0) + 1
    sorted_scenarios = sorted(risks.scenarios, key=lambda s: (s.category, s.risk_id))
    if include_experimental_scoring:
        sorted_scenarios = sorted(
            risks.scenarios,
            key=lambda s: (_SEVERITY_ORDER.get(s.severity, 99), -s.score, s.category, s.risk_id),
        )
    scenario_rows = []
    for s in sorted_scenarios:
        evidence_classes = sorted({e.type.upper() for e in s.evidence})
        reachability = "STATICALLY_INFERRED" if s.related_dataflow_ids else "NOT_ESTABLISHED"
        assumptions = ["Runtime reachability and exploitability were not tested."]
        if not s.related_dataflow_ids:
            assumptions.append("No supported structural relationship establishes a path to this concern.")
        assumptions.append("Repository control evidence does not establish runtime enforcement or effectiveness.")
        row = {
            "risk_id": s.risk_id,
            "title": s.title,
            "category": s.category,
            "evidence_strength": s.confidence.upper(),
            "evidence_class": evidence_classes,
            "reachability_status": reachability,
            "unresolved_assumptions": assumptions,
            "rationale": _redact_check(s.rationale),
            "evidence": [{**e.to_dict(), "description": _redact_check(e.description)} for e in s.evidence],
            "related_finding_ids": s.related_finding_ids,
            "related_dataflow_ids": s.related_dataflow_ids,
            "related_control_ids": s.related_control_ids,
            "primary_context": s.primary_context,
        }
        if include_experimental_scoring:
            row.update(
                {
                    "score": s.score,
                    "severity": s.severity,
                    "exposure": s.exposure,
                    "safety_impact": s.safety_impact,
                    "security_exposure": s.security_exposure,
                    "likelihood": s.likelihood,
                    "confidence": s.confidence,
                    "context_adjusted": s.context_adjusted,
                }
            )
        scenario_rows.append(row)

    by_category: dict[str, int] = {}
    for scenario in scenario_rows:
        category = scenario["category"]
        by_category[category] = by_category.get(category, 0) + 1
    risks_out = {
        "total": len(risks.scenarios),
        "methodology": "EXPERIMENTAL_SCORED" if include_experimental_scoring else "UNSCORED_EVIDENCE_REVIEW",
        "by_category": dict(sorted(by_category.items())),
        "ai_surface_detected": risks.ai_surface_detected,
        "summary_note": risks.summary_note,
        "scenarios": scenario_rows,
    }
    if include_experimental_scoring:
        risks_out["by_severity"] = severity_counts

    # ---- Process evidence: unscored checklist by default --------------------
    next_level_blocked_reason = None
    if readiness.readiness_level is not None and readiness.readiness_level < 4:
        next_la = next((la for la in readiness.level_assessments if la.level == readiness.readiness_level + 1), None)
        if next_la and next_la.missing_requirements:
            next_level_blocked_reason = next_la.missing_requirements[0]
    if include_experimental_scoring:
        readiness_out = readiness.to_dict()
        readiness_out["blocked_from_next_level"] = next_level_blocked_reason
    else:
        check_names = {
            1: "AI inventory and threat-model scope",
            2: "Repeatable AI security testing",
            3: "CI-integrated security evaluation",
            4: "Scheduled evaluation and retained evidence",
        }
        checks = []
        prerequisite_labels = {
            "Level 2 not sufficiently achieved": (
                "repeatable AI security testing evidence prerequisite not established"
            ),
            "Level 3 not sufficiently achieved": (
                "CI-integrated security evaluation evidence prerequisite not established"
            ),
        }
        for assessment in readiness.level_assessments:
            if readiness.assessment_completeness == "PARTIAL":
                artifact_status = "UNKNOWN"
            elif assessment.evidence:
                artifact_status = "EVIDENCE_OBSERVED"
            else:
                artifact_status = "NOT_OBSERVED"
            checks.append(
                {
                    "check_id": f"PROCESS-{assessment.level}",
                    "name": check_names[assessment.level],
                    "artifact_status": artifact_status,
                    "enforcement_status": "UNKNOWN",
                    "evidence": [e.to_dict() for e in assessment.evidence],
                    "missing_evidence": [
                        prerequisite_labels.get(item, item)
                        for item in assessment.missing_requirements
                    ],
                    "unresolved_assumptions": [
                        "Offline repository inspection cannot verify execution, enforcement, or effectiveness."
                    ],
                }
            )
        readiness_out = {
            "assessment_status": "UNSCORED",
            "assessment_completeness": readiness.assessment_completeness,
            "checks": checks,
            "limitations": list(readiness.limitations),
            "self_scan": readiness.self_scan,
        }

    # ---- Recommendations: derived from existing evidence, deduplicated ------
    recommendations: list[dict[str, Any]] = []
    covered_control_ids: set[str] = set()

    for s in sorted_scenarios:
        covered_control_ids.update(s.related_control_ids)
        recommendations.append(
            {
                "title": s.title,
                "why_it_matters": _redact_check(s.rationale),
                "evidence_summary": f"{len(s.evidence)} evidence item(s) — see risk {s.risk_id} for detail.",
                "suggested_action": _suggested_action_for(s.category),
                "related_risk_ids": [s.risk_id],
                "related_control_ids": s.related_control_ids,
                "_sort_key": (
                    0,
                    _SEVERITY_ORDER.get(s.severity, 99) if include_experimental_scoring else 0,
                    -s.score if include_experimental_scoring else s.risk_id,
                ),
            }
        )

    if next_level_blocked_reason:
        public_blocked_reason = next_level_blocked_reason
        if not include_experimental_scoring:
            public_blocked_reason = {
                "Level 2 not sufficiently achieved": (
                    "repeatable AI security testing evidence prerequisite not established"
                ),
                "Level 3 not sufficiently achieved": (
                    "CI-integrated security evaluation evidence prerequisite not established"
                ),
            }.get(next_level_blocked_reason, next_level_blocked_reason)
        recommendations.append(
            {
                "title": "Address the next process-evidence gap",
                "why_it_matters": public_blocked_reason,
                "evidence_summary": "See the unscored process-evidence checklist for detail.",
                "suggested_action": "Add reviewable evidence for the listed process check.",
                "related_risk_ids": [],
                "related_control_ids": [],
                "_sort_key": (1, 0, 0),
            }
        )

    for c in controls.controls:
        if c.status != "NOT_FOUND":
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
        limitations.append(
            "Some files contained many repeated matches of the same pattern; the report lists "
            "representative findings plus an exact count of the remainder (see the evidence "
            "appendix). All matches were counted — this is summarization, not an incomplete scan."
        )
    for lim in readiness.limitations:
        if lim not in limitations:
            limitations.append(lim)

    return VibeExplainerReport(
        metadata=metadata,
        executive_summary=executive_summary,
        ai_inventory=ai_inventory,
        attack_surface=attack_surface_out,
        data_flows=data_flows_out,
        unresolved_relationships=list(dataflow.unresolved),
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
    add("AI REPOSITORY EVIDENCE REVIEW")
    add(sep)
    add("")

    es = report.executive_summary
    experimental = bool(report.metadata.get("experimental_scoring_enabled"))
    add(f"SUPPORTED AI-RELATED EVIDENCE\n{es['ai_surface']}")
    add("")
    if es["ai_surface"] == "NOT_DETECTED":
        add(es["statement"])
        add("")
        add(sep)
        _render_limitations(add, report)
        return redact_secrets("\n".join(lines))

    add(f"FINDINGS\n{es['total_findings']} total "
        f"({es['production_findings']} in production code, "
        f"{es['total_findings'] - es['production_findings']} in test/example/docs/generated)")
    if es.get("defaulted_production_findings"):
        add(f"{es['defaulted_production_findings']} production finding(s) were classified by "
            "conservative default; confirm during analyst review.")
    add("")
    mode = "experimental scored" if experimental else "unscored"
    add(f"CONCERNS\n{es['risk_scenario_count']} {mode} scenario(s)")
    if experimental:
        add(f"Experimental highest: {es.get('highest_risk_severity') or 'none'}")
    add("")
    if experimental:
        level = es["readiness_level"]
        level_display = f"Level {level} — {_LEVEL_DISPLAY.get(level, es['readiness_name'])}" if level else es["readiness_name"]
        add(f"EXPERIMENTAL PROCESS CLASSIFICATION\n{level_display}")
    else:
        add("PROCESS EVIDENCE\nUNSCORED CHECKLIST — enforcement UNKNOWN")
    if es["assessment_completeness"] == "PARTIAL":
        add("!! ASSESSMENT INCOMPLETE — some files could not be assessed. Findings/risks")
        add("   below are a lower bound. Do not read as \"only N risks\".")
    elif es["assessment_completeness"] == "AGGREGATED":
        add("(Some files had many repeated matches; these were summarized with exact")
        add(" counts. The assessment is complete — see the evidence appendix for totals.)")
    add("")
    add(sep)

    if report.risks["scenarios"]:
        add("CONCERN SCENARIOS")
        add("")
        for s in report.risks["scenarios"][:5]:
            label = f"{s['severity']:<9} " if experimental else ""
            add(f"{label}{s['title']}")
            add(f"  Evidence: {s['evidence_strength']} | Reachability: {s['reachability_status']}")
            add(f"  {s['rationale'][:100]}{'...' if len(s['rationale']) > 100 else ''}")
            add("")
        add(sep)

    add("PROCESS-EVIDENCE CHECKLIST")
    add("")
    if experimental:
        for la in report.readiness["level_assessments"]:
            status_display = "ACHIEVED" if la["status"] == "ACHIEVED" else ("BLOCKED" if la["status"] == "NOT_ACHIEVED" else la["status"])
            add(f"Level {la['level']}  {_LEVEL_DISPLAY[la['level']]:<12} {status_display}")
            if la["status"] != "ACHIEVED" and la["missing_requirements"]:
                add(f"         └─ {la['missing_requirements'][0]}")
    else:
        for check in report.readiness["checks"]:
            add(f"{check['artifact_status']:<17} {check['name']}")
            add(f"  Enforcement: {check['enforcement_status']}")
            if check["missing_evidence"]:
                add(f"  Missing: {check['missing_evidence'][0]}")
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
    return redact_secrets("\n".join(lines))


def _render_limitations(add, report: VibeExplainerReport) -> None:
    add("ASSESSMENT LIMITATIONS")
    add("")
    for lim in report.limitations:
        add(f"- {lim}")
