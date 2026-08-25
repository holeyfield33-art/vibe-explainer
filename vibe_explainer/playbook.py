"""Mapping to the HackerOne 'Security for AI: Readiness and Risk Playbook'.

Vibe Explainer's risk formula and readiness ladder already implement this framework;
this module supplies the framework's exact published vocabulary so the consultant
deliverable cites recognizable playbook language (level names + goals, the risk-band
table, the [P]/[V]/[G] control taxonomy, platform archetypes) rather than a paraphrase.

Pure reference data + pure functions over already-computed report values. No analysis,
no engine coupling.
"""

from __future__ import annotations

# --- Readiness levels: exact playbook names, goals, and one-line testing posture ----
READINESS_LEVELS = {
    1: {
        "name": "Baseline",
        "goal": "AI as a feature; bring AI paths into scope with essential safeguards.",
        "posture": "Establish essential safeguards; confirm the system won't overshare or "
                   "behave unpredictably.",
    },
    2: {
        "name": "Managed",
        "goal": "Defined, repeatable AI testing with time-boxed adversarial exercises and "
                "light automation.",
        "posture": "Validate higher-risk behaviors (retrieval, integrations, multi-turn); "
                   "shift from ad-hoc checks to documented, time-boxed adversarial exercises.",
    },
    3: {
        "name": "Hardened",
        "goal": "Security-first; adversarial signal wired to releases.",
        "posture": "Ongoing assurance with automated evaluations and release gates "
                   "(fail -> fix -> retest -> ship).",
    },
    4: {
        "name": "Continuous",
        "goal": "Measurable, repeatable, automated AI assurance (SRE-like for models/agents).",
        "posture": "Continuous oversight: automated evals, drift monitoring, versioned "
                   "defensibility artifacts, leadership reporting.",
    },
}

# --- Risk band table (playbook page 8) ---------------------------------------------
# (low_inclusive, high_inclusive, severity, readiness_level)
RISK_BANDS = [
    (1, 7, "Low", 1),
    (8, 14, "Moderate", 2),
    (15, 19, "High", 3),
    (20, 25, "Critical", 4),
]

RISK_FORMULA = "ROUND(((Exposure + Safety + Security) / 3) * Likelihood)"

# --- Platform archetypes (playbook examples per level) ------------------------------
PLATFORM_ARCHETYPES = {
    1: "Simple Chatbot — single LLM, commercial foundation model, no tools or long-term memory.",
    2: "Enterprise LLM — single/multiple LLMs, APIs, internal datasets, RAG, MCP connectors.",
    3: "Agentic App — multi-agent orchestration; MCP tools, A2A/ACP auth and transcripts.",
    4: "Frontier / Core Infrastructure — proprietary training data, multi-tenant agentic systems.",
}

# --- Control taxonomy: [P] Preventive / [V] Validation / [G] Governance -------------
# Maps Vibe Explainer's 12 control IDs to the playbook's control class. This reflects
# what kind of evidence each control represents, per the playbook's [P]/[V]/[G] tags.
_CONTROL_CLASS = {
    "C01": "P",  # AI component inventory (foundational preventive posture)
    "C02": "G",  # Threat model / documentation (governance evidence)
    "C03": "P",  # Input validation / sanitization
    "C04": "P",  # Output handling / sanitization before downstream use
    "C05": "P",  # Tool / action authorization (human-in-the-loop, least privilege)
    "C06": "P",  # Prompt / response abuse guards
    "C07": "P",  # Rate limiting / abuse controls
    "C08": "P",  # Secret management
    "C09": "P",  # RAG source allow/deny, retrieval isolation
    "C10": "P",  # MCP permissioning / default-deny
    "C11": "P",  # Data access controls
    "C12": "V",  # Adversarial / security testing evidence (validation)
}

_CLASS_LABEL = {"P": "Preventive", "V": "Validation", "G": "Governance"}


def level_meta(level: int | None) -> dict[str, str]:
    if level is None or level not in READINESS_LEVELS:
        return {"name": "No AI surface", "goal": "", "posture": ""}
    return READINESS_LEVELS[level]


def platform_archetype(level: int | None) -> str:
    if level is None:
        return "No AI surface detected — no platform archetype applies."
    return PLATFORM_ARCHETYPES.get(level, "")


def control_class(control_id: str) -> str:
    """Return 'P' | 'V' | 'G' for a control ID (defaults to 'P')."""
    return _CONTROL_CLASS.get(control_id, "P")


def control_class_label(control_id: str) -> str:
    return _CLASS_LABEL[control_class(control_id)]


def band_for_score(score: int) -> tuple[str, int]:
    """Return (severity, readiness_level) for a raw risk score, per the playbook table."""
    for lo, hi, severity, level in RISK_BANDS:
        if lo <= score <= hi:
            return severity, level
    if score < 1:
        return "Low", 1
    return "Critical", 4


def risk_band_table_rows() -> list[tuple[str, str, str]]:
    """Rows for a rendered band table: (range, severity, readiness)."""
    names = {1: "Level 1: Baseline", 2: "Level 2: Managed", 3: "Level 3: Hardened", 4: "Level 4: Continuous"}
    return [(f"{lo}-{hi}", sev, names[lvl]) for lo, hi, sev, lvl in RISK_BANDS]
