"""Consultant-grade AI Security Readiness Assessment report.

A pure *packaging* layer: it consumes an already-built VibeExplainerReport (the
Phase 0-7 output) and renders a professional Markdown deliverable a security
consultant can hand to a client. It performs NO analysis of its own — it does not
scan, score, classify, or re-derive anything. Every conclusion it prints comes
straight from the report object, and every important conclusion carries an evidence
reference back to a finding/dataflow/control ID, which is the whole point: this is
what makes the artifact more than an LLM-written "security report."
"""

from __future__ import annotations

from datetime import date
from typing import Any

from .security_report import VibeExplainerReport

_SEVERITY_LABEL = {"CRITICAL": "Critical", "HIGH": "High", "MODERATE": "Moderate", "LOW": "Low"}
_LEVEL_NAME = {1: "Baseline", 2: "Managed", 3: "Hardened", 4: "Continuous"}
_CONTROL_STATUS_ORDER = ["DETECTED", "PARTIAL", "NOT_DETECTED", "UNKNOWN", "NOT_APPLICABLE"]


def render_consultant_markdown(report: VibeExplainerReport, *, assessment_date: str | None = None) -> str:
    """Render the full consultant deliverable as Markdown.

    assessment_date is the only injected value (defaults to today, UTC-naive). It is
    metadata for the human reader and never affects any analytical content — kept out
    of the underlying report object precisely so report IDs and ordering stay
    deterministic regardless of when the report is rendered.
    """
    m = report.metadata
    es = report.executive_summary
    lines: list[str] = []
    add = lines.append

    # ---- Header -----------------------------------------------------------
    add("# AI Security Readiness Assessment")
    add("")
    add("*Powered by Vibe Explainer*")
    add("")
    add(f"- **Repository:** `{m['repository']}`")
    add(f"- **Assessment date:** {assessment_date or date.today().isoformat()}")
    add(f"- **Engine version:** vibe-explainer {m['version']} (schema {m['schema_version']})")
    add(f"- **Assessment scope:** Static repository analysis — AI components, attack surface, "
        "data flow, security controls, risk, and readiness. Does not include runtime testing or "
        "adversarial validation.")
    add(f"- **Assessment completeness:** {m['assessment_completeness']}")
    add("")
    add("---")
    add("")

    # ---- Executive summary ------------------------------------------------
    add("## Executive Summary")
    add("")
    if es["ai_surface"] == "NOT_DETECTED":
        add("No AI security surface was detected from the available repository evidence. "
            "No AI security assessment was generated. This is a statement about detected "
            "evidence, not an assurance that the repository is free of AI functionality or secure.")
        add("")
        _render_limitations(add, report)
        return "\n".join(lines)

    highest = es["highest_risk_severity"]
    level = es["readiness_level"]
    add(f"AI functionality was detected in this repository. This assessment identified "
        f"**{es['risk_scenario_count']} AI security risk scenario(s)**"
        + (f", the highest of which is rated **{_SEVERITY_LABEL.get(highest, highest)}**." if highest else ".")
        )
    add("")
    add(f"The repository's demonstrated AI security readiness is assessed as "
        f"**Level {level} — {_LEVEL_NAME.get(level, es['readiness_name'])}**.")
    add("")
    add("Risk severity and readiness maturity are independent measures: risk describes how "
        "concerning the identified evidence is, while readiness describes how repeatable and "
        "mature the repository's demonstrated security practice is. A repository may carry a "
        "high-severity risk while showing an early-stage readiness level, or vice versa.")
    add("")
    if m["assessment_completeness"] == "PARTIAL":
        add("> **Note:** This assessment is marked **PARTIAL** because discovery results were "
            "truncated. The findings below may be incomplete.")
        add("")
    add("---")
    add("")

    # ---- AI attack surface ------------------------------------------------
    add("## AI Attack Surface")
    add("")
    add("AI-relevant components discovered in the repository, grouped by the surface they "
        "belong to. Each item references the finding it was derived from.")
    add("")
    surface = report.attack_surface
    any_surface = False
    for bucket in ("inputs", "model", "retrieval", "tools", "outputs", "storage"):
        items = surface.get(bucket, [])
        if not items:
            continue
        any_surface = True
        add(f"### {bucket.capitalize()}")
        add("")
        add("| Component | Location | Confidence | Evidence | Finding |")
        add("|---|---|---|---|---|")
        for i in items:
            add(f"| {i['component']} | `{i['file']}:{i['line']}` | {i['confidence']} | "
                f"{_cell(i['evidence'])} | `{i['finding_id']}` |")
        add("")
    if not any_surface:
        add("No populated attack-surface buckets were detected.")
        add("")
    add("---")
    add("")

    # ---- Data flow --------------------------------------------------------
    add("## AI Data Flows")
    add("")
    if report.data_flows:
        add("Observed same-file relationships between AI components. These are static "
            "inferences from code proximity, not confirmed runtime data flows.")
        add("")
        add("| Source | Relationship | Destination | Confidence | Location |")
        add("|---|---|---|---|---|")
        for e in report.data_flows:
            add(f"| {e['source']} | `{e['relationship']}` | {e['destination']} | "
                f"{e['confidence']} | `{e['file']}:{e['source_line']}→{e['destination_line']}` |")
        add("")
    else:
        add("No AI data-flow relationships were observed. Note that cross-file flows are not "
            "established by this assessment even when implied by imports.")
        add("")
    add("---")
    add("")

    # ---- Key risks --------------------------------------------------------
    add("## Key Risks")
    add("")
    dist = report.risks["by_severity"]
    add(f"**{report.risks['total']} scenario(s)** — "
        f"Critical: {dist.get('CRITICAL', 0)}, High: {dist.get('HIGH', 0)}, "
        f"Moderate: {dist.get('MODERATE', 0)}, Low: {dist.get('LOW', 0)}.")
    add("")
    if report.risks["scenarios"]:
        for s in report.risks["scenarios"]:
            add(f"### [{_SEVERITY_LABEL.get(s['severity'], s['severity'])}] {s['title']}")
            add("")
            add(f"- **Risk ID:** `{s['risk_id']}`")
            add(f"- **Category:** {s['category']}")
            add(f"- **Score:** {s['score']} / 25 ({s['severity']})")
            add(f"- **Factors:** Exposure {s.get('exposure', '-')}, Safety {s.get('safety_impact', '-')}, "
                f"Security {s.get('security_exposure', '-')}, Likelihood {s.get('likelihood', '-')}"
                if 'exposure' in s else f"- **Confidence:** {s['confidence']}")
            add(f"- **Assessment confidence:** {s['confidence']}")
            add("")
            add(f"{s['rationale']}")
            add("")
            if s["related_control_ids"]:
                add(f"- **Related controls:** {', '.join('`' + c + '`' for c in s['related_control_ids'])}")
            if s["related_finding_ids"]:
                add(f"- **Related findings:** {', '.join('`' + f + '`' for f in s['related_finding_ids'][:8])}"
                    + (" …" if len(s["related_finding_ids"]) > 8 else ""))
            add("")
    else:
        add("No AI security risk scenarios were generated from the available repository evidence. "
            "This does not constitute an assurance that the repository is secure.")
        add("")
    add("---")
    add("")

    # ---- Security controls ------------------------------------------------
    add("## Security Controls")
    add("")
    add("Evidence of security controls found in the repository. **DETECTED** means supporting "
        "evidence was found — not that the control is complete, effective, or resistant to "
        "bypass. **NOT_DETECTED** means no supporting evidence was found — not that the control "
        "definitely does not exist (it may live outside this repository).")
    add("")
    by_status = report.controls["by_status"]
    for status in _CONTROL_STATUS_ORDER:
        controls = by_status.get(status, [])
        if not controls:
            continue
        add(f"### {status.replace('_', ' ').title()}")
        add("")
        add("| Control | Confidence | Rationale |")
        add("|---|---|---|")
        for c in sorted(controls, key=lambda c: c["control_id"]):
            add(f"| {c['control_id']} {c['name']} | {c['confidence']} | {_cell(c['rationale'])} |")
        add("")
    add("---")
    add("")

    # ---- Readiness --------------------------------------------------------
    add("## AI Security Readiness")
    add("")
    add(f"**Current level: Level {level} — {_LEVEL_NAME.get(level, es['readiness_name'])}**")
    add("")
    blocked = report.readiness.get("blocked_from_next_level")
    if blocked:
        add(f"**Blocked from the next level by:** {blocked}")
        add("")
    add("| Level | Name | Status | Notes |")
    add("|---|---|---|---|")
    for la in report.readiness["level_assessments"]:
        note = ""
        if la["status"] != "ACHIEVED" and la["missing_requirements"]:
            note = la["missing_requirements"][0]
        add(f"| {la['level']} | {_LEVEL_NAME.get(la['level'], la['name'])} | {la['status']} | {_cell(note)} |")
    add("")
    add("---")
    add("")

    # ---- Top remediations -------------------------------------------------
    add("## Top Remediations")
    add("")
    if report.recommendations:
        for rec in report.recommendations:
            add(f"### {rec['priority']} — {rec['title']}")
            add("")
            add(f"**Why it matters:** {rec['why_it_matters']}")
            add("")
            add(f"**Suggested action:** {rec['suggested_action']}")
            add("")
            refs = []
            if rec["related_risk_ids"]:
                refs.append("risks " + ", ".join("`" + r + "`" for r in rec["related_risk_ids"]))
            if rec["related_control_ids"]:
                refs.append("controls " + ", ".join("`" + c + "`" for c in rec["related_control_ids"]))
            if refs:
                add(f"*Traces to: {'; '.join(refs)}.*")
                add("")
    else:
        add("No remediations were generated.")
        add("")
    add("---")
    add("")

    # ---- Evidence appendix ------------------------------------------------
    add("## Evidence Appendix")
    add("")
    add("Complete AI component inventory, grouped by category. Every finding above traces to "
        "an entry here by ID.")
    add("")
    if report.ai_inventory.get("truncation_notice"):
        add(f"> **{report.ai_inventory['truncation_notice']}**")
        add("")
    for category, findings in report.ai_inventory["categories"].items():
        add(f"### {category.replace('_', ' ').title()}")
        add("")
        add("| Finding ID | Location | Name | Confidence | Evidence |")
        add("|---|---|---|---|---|")
        for f in findings:
            add(f"| `{f['id']}` | `{f['file']}:{f['line']}` | {f['name']} | {f['confidence']} | {_cell(f['evidence'])} |")
        add("")
    add("---")
    add("")

    # ---- Limitations ------------------------------------------------------
    _render_limitations(add, report)
    return "\n".join(lines)


def _render_limitations(add, report: VibeExplainerReport) -> None:
    add("## Limitations")
    add("")
    add("This assessment is a static, evidence-based analysis. It is a professional aid, not a "
        "guarantee. In particular:")
    add("")
    for lim in report.limitations:
        add(f"- {lim}")
    add("")
    add("This assessment does not prove exploitability, does not confirm that any identified "
        "risk can be successfully exploited, and does not replace adversarial testing or a "
        "manual security review.")


def _cell(text: Any) -> str:
    """Make a string safe for a single Markdown table cell: escape pipes, collapse
    newlines, and trim length so the table stays readable."""
    if text is None:
        return ""
    s = str(text).replace("|", "\\|").replace("\n", " ").strip()
    if len(s) > 160:
        s = s[:157] + "…"
    return s
