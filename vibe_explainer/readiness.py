"""AI security readiness assessment — demonstrated process maturity, not risk severity.

"Readiness measures demonstrated AI security maturity and repeatability. It is
independent of the severity of individual risk scenarios."

"Running Vibe Explainer does not itself increase the assessed readiness of the target
repository." Every process-evidence check in this module looks at the TARGET
repository's own artifacts (test directories, CI config, documentation) — never at
the fact that a Vibe Explainer scan happened, and never at Vibe Explainer's own
source tree when assessing someone else's repository.

Consumes DiscoveryResult, AttackSurfaceResult, DataFlowGraph, ControlAssessment, and
RiskAssessment. Performs no new AI-component scan (that's ai_discovery.py's job) — the
one new thing this module does is a small, isolated PROCESS-evidence scan (test
directories, CI config, documentation headers) that Phases 1-5 have no reason to do.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .ai_discovery import DiscoveryResult, MAX_FILE_BYTES, _read_text
from .attack_surface import AttackSurfaceResult
from .controls import (
    STATUS_DETECTED,
    STATUS_PARTIAL as CONTROL_STATUS_PARTIAL,
    ControlAssessment,
)
from .dataflow import DataFlowGraph
from .risk import COMPLETENESS_PARTIAL, RiskAssessment
from .scanner import SKIP_DIRS

STATUS_ACHIEVED = "ACHIEVED"
STATUS_PARTIAL = "PARTIAL"
STATUS_NOT_ACHIEVED = "NOT_ACHIEVED"
STATUS_UNKNOWN = "UNKNOWN"
STATUS_NOT_APPLICABLE = "NOT_APPLICABLE"

EVIDENCE_REPOSITORY_ARTIFACT = "REPOSITORY_ARTIFACT"
EVIDENCE_DISCOVERY = "DISCOVERY_EVIDENCE"
EVIDENCE_CONTROL = "CONTROL_EVIDENCE"
EVIDENCE_DATAFLOW = "DATAFLOW_EVIDENCE"
EVIDENCE_RISK = "RISK_EVIDENCE"
EVIDENCE_PROCESS = "PROCESS_EVIDENCE"

LEVEL_NAMES = {1: "Baseline", 2: "Managed", 3: "Hardened", 4: "Continuous"}
NO_AI_SURFACE = "NO_AI_SURFACE"


# ---------------------------------------------------------------------------
# Small, isolated PROCESS-evidence scan. Deliberately separate from
# ai_discovery.py: this looks for evidence of a repeatable SECURITY PROCESS
# (test directories, CI config, documentation), not AI components. It is the
# one new scan this phase performs, per the directive's instruction to keep
# it isolated rather than duplicating the AI scanner.
# ---------------------------------------------------------------------------
_TEST_ARTIFACT_PATH_HINTS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)(^|/)tests?/(security|redteam|adversarial)(/|$)"), "high"),
    (re.compile(r"(?i)(^|/)evals?(/|$)"), "high"),
    (re.compile(r"(?i)(security|redteam|adversarial)[-_]test"), "moderate"),
]
_CI_CONFIG_PATH_HINT = re.compile(r"(?i)^\.github/workflows/.*\.ya?ml$|^\.gitlab-ci\.ya?ml$|^\.circleci/config\.ya?ml$")
_VERSIONED_EVIDENCE_PATH_HINT = re.compile(r"(?i)(^|/)security-reports?/|(\d{4}-\d{2}-\d{2}).*\.(md|txt|json)$")

_DOC_HEADER_HINTS: list[tuple[str, re.Pattern[str]]] = [
    ("documented_eval_process", re.compile(r"(?im)^#+\s*(?:ai )?(?:security )?(?:evaluation|testing) (?:process|procedure)\b")),
    ("remediation_retest", re.compile(r"(?im)^#+\s*remediation(?:\s*(?:and|&)\s*retest)?\s*workflow\b|^#+\s*remediation\b")),
    ("security_metrics", re.compile(r"(?im)^#+\s*security (?:metrics|dashboard)\b")),
    ("risk_register", re.compile(r"(?im)^#+\s*risk register\b")),
]

_CI_SECURITY_KEYWORD = re.compile(r"(?i)security|adversarial|redteam|eval")
_CI_TEST_RUN_KEYWORD = re.compile(r"(?i)\brun:|pytest|npm test|unittest\b")
_CI_SCHEDULE_KEYWORD = re.compile(r"(?im)^\s*schedule:")
_CI_CRON_KEYWORD = re.compile(r"(?im)cron:")

DOC_EXTS = {".md", ".rst", ".txt"}


@dataclass
class _ProcessEvidence:
    kind: str  # matches keys used in ProcessSignals below
    path: str
    confidence: str
    description: str


def _should_skip_dir(name: str) -> bool:
    # Only prune SKIP_DIRS exactly (which already includes ".git") — do NOT use a
    # startswith(".git") check, since that would also match ".github" and silently
    # hide .github/workflows/ from the CI-config scan.
    return name in SKIP_DIRS


def _iter_all_repo_paths(root_path: Path):
    """Yield regular repository files without following file symlinks.

    Streaming avoids retaining an attacker-controlled path list in memory. The
    shared bounded reader performs a second no-follow check before content reads.
    """
    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [d for d in dirnames if not _should_skip_dir(d)]
        for name in filenames:
            path = Path(dirpath) / name
            try:
                if stat.S_ISREG(path.lstat().st_mode):
                    yield path
            except OSError:
                continue


@dataclass
class ProcessSignals:
    security_test_artifact: list[_ProcessEvidence] = field(default_factory=list)
    ci_config: list[_ProcessEvidence] = field(default_factory=list)
    ci_security_gate: list[_ProcessEvidence] = field(default_factory=list)
    scheduled_security_evaluation: list[_ProcessEvidence] = field(default_factory=list)
    versioned_security_evidence: list[_ProcessEvidence] = field(default_factory=list)
    documented_eval_process: list[_ProcessEvidence] = field(default_factory=list)
    remediation_retest: list[_ProcessEvidence] = field(default_factory=list)
    security_metrics: list[_ProcessEvidence] = field(default_factory=list)
    risk_register: list[_ProcessEvidence] = field(default_factory=list)


def _scan_process_signals(root_path: Path) -> ProcessSignals:
    signals = ProcessSignals()
    for file_path in _iter_all_repo_paths(root_path):
        rel = str(file_path.relative_to(root_path)).replace("\\", "/")

        for pattern, confidence in _TEST_ARTIFACT_PATH_HINTS:
            if pattern.search(rel):
                signals.security_test_artifact.append(
                    _ProcessEvidence("security_test_artifact", rel, confidence, f"Path matches a security/redteam/eval test convention: {rel}")
                )
                break

        if _VERSIONED_EVIDENCE_PATH_HINT.search(rel):
            signals.versioned_security_evidence.append(
                _ProcessEvidence("versioned_security_evidence", rel, "moderate", f"Path suggests a versioned/dated security evidence artifact: {rel}")
            )

        is_ci = bool(_CI_CONFIG_PATH_HINT.match(rel))
        is_doc = file_path.suffix.lower() in DOC_EXTS
        if not (is_ci or is_doc):
            continue

        try:
            if file_path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        text = _read_text(file_path)
        if text is None:
            continue

        if is_ci:
            signals.ci_config.append(_ProcessEvidence("ci_config", rel, "high", f"CI configuration file present: {rel}"))
            has_security_kw = bool(_CI_SECURITY_KEYWORD.search(text))
            has_test_run = bool(_CI_TEST_RUN_KEYWORD.search(text))
            if has_security_kw and has_test_run:
                signals.ci_security_gate.append(
                    _ProcessEvidence("ci_security_gate", rel, "moderate", f"CI config at {rel} references both a security/eval keyword and a test-run step.")
                )
                if _CI_SCHEDULE_KEYWORD.search(text) and _CI_CRON_KEYWORD.search(text):
                    signals.scheduled_security_evaluation.append(
                        _ProcessEvidence("scheduled_security_evaluation", rel, "moderate", f"CI config at {rel} has a scheduled/cron trigger alongside security/eval evidence.")
                    )

        if is_doc:
            for kind, pattern in _DOC_HEADER_HINTS:
                m = pattern.search(text)
                if m:
                    line_no = text.count("\n", 0, m.start()) + 1
                    getattr(signals, kind).append(
                        _ProcessEvidence(kind, rel, "high", f"Documentation header matching '{kind.replace('_', ' ')}' found at {rel}:{line_no}.")
                    )

    return signals


# ---------------------------------------------------------------------------
# Readiness data model
# ---------------------------------------------------------------------------
@dataclass
class ReadinessEvidenceRef:
    type: str
    id: str
    description: str

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "id": self.id, "description": self.description}


@dataclass
class LevelAssessment:
    level: int
    name: str
    status: str
    evidence: list[ReadinessEvidenceRef]
    missing_requirements: list[str]
    confidence: str
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "name": self.name,
            "status": self.status,
            "evidence": [e.to_dict() for e in self.evidence],
            "missing_requirements": list(self.missing_requirements),
            "confidence": self.confidence,
            "rationale": self.rationale,
        }


@dataclass
class ReadinessAssessment:
    root: str
    ai_surface_detected: bool
    readiness_level: int | None
    readiness_name: str
    confidence: str
    rationale: str
    evidence: list[ReadinessEvidenceRef]
    level_assessments: list[LevelAssessment]
    blockers: list[str]
    limitations: list[str]
    assessment_completeness: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "ai_surface_detected": self.ai_surface_detected,
            "readiness_level": self.readiness_level,
            "readiness_name": self.readiness_name,
            "confidence": self.confidence,
            "rationale": self.rationale,
            "evidence": [e.to_dict() for e in self.evidence],
            "level_assessments": [la.to_dict() for la in self.level_assessments],
            "blockers": list(self.blockers),
            "limitations": list(self.limitations),
            "assessment_completeness": self.assessment_completeness,
        }


_STANDARD_LIMITATIONS = [
    "Process evidence is detected via file-path conventions, CI config keywords, and "
    "documentation headers — not by verifying the process actually runs or is enforced.",
    "This assessment reflects repository evidence only; a real security program that "
    "lives outside this repository (a separate ops repo, an external vendor, a private "
    "wiki) is invisible to it.",
    "Running Vibe Explainer does not itself increase the assessed readiness of the "
    "target repository — generated attack-surface/control/risk output is never counted "
    "as process evidence.",
]


def _evidence(type_: str, id_: str, description: str) -> ReadinessEvidenceRef:
    return ReadinessEvidenceRef(type=type_, id=id_, description=description)


def _process_evidence_refs(items: list[_ProcessEvidence], limit: int = 5) -> list[ReadinessEvidenceRef]:
    ordered = sorted(items, key=lambda p: p.path)[:limit]
    return [_evidence(EVIDENCE_PROCESS, hashlib.sha1(p.path.encode()).hexdigest()[:10], p.description) for p in ordered]


def _control(controls: ControlAssessment, control_id: str):
    for c in controls.controls:
        if c.control_id == control_id:
            return c
    return None


def assess_readiness(
    discovery: DiscoveryResult,
    attack_surface: AttackSurfaceResult,
    dataflow: DataFlowGraph,
    controls: ControlAssessment,
    risks: RiskAssessment,
) -> ReadinessAssessment:
    """Evidence-based AI security readiness assessment. Consumes Phases 1-5 output
    plus one small, isolated process-evidence scan of the TARGET repository (test
    directories, CI config, documentation headers). Never re-derives or overrides
    Phase 5's risk scores — risk and readiness are reported side by side, never
    multiplied together.
    """
    root = discovery.root
    completeness = COMPLETENESS_PARTIAL if discovery.truncated else risks.assessment_completeness

    if not discovery.has_ai_signal():
        return ReadinessAssessment(
            root=root,
            ai_surface_detected=False,
            readiness_level=None,
            readiness_name=NO_AI_SURFACE,
            confidence="high",
            rationale="No AI components were discovered in this repository — no AI security readiness level applies.",
            evidence=[],
            level_assessments=[],
            blockers=[],
            limitations=list(_STANDARD_LIMITATIONS),
            assessment_completeness=completeness,
        )

    root_path = Path(root)
    signals = _scan_process_signals(root_path)

    c01 = _control(controls, "C01")
    c02 = _control(controls, "C02")
    c05 = _control(controls, "C05")
    c07 = _control(controls, "C07")
    c09 = _control(controls, "C09")
    c10 = _control(controls, "C10")

    def control_ok(c) -> bool:
        return c is not None and c.status in (STATUS_DETECTED, CONTROL_STATUS_PARTIAL)

    level_assessments: list[LevelAssessment] = []

    # ---- LEVEL 1 — BASELINE -------------------------------------------
    # Gate: AI has been brought into security scope at all. Always true here
    # (has_ai_signal already checked above), matching the directive's own
    # worked example: Level 1 is readily achievable, with gaps reported
    # rather than withheld — but note the discovery/attack-surface/data-flow
    # evidence below is DISCOVERY_EVIDENCE (what the scan found), never
    # treated as proof of a maintained program.
    l1_evidence = [
        _evidence(EVIDENCE_DISCOVERY, "discovery", f"{len(discovery.findings)} AI component finding(s) identified."),
        _evidence(EVIDENCE_DISCOVERY, "attack_surface", f"Attack surface mapped across {sum(1 for b in attack_surface.by_bucket().values() if b)} non-empty bucket(s)."),
        _evidence(EVIDENCE_DATAFLOW, "dataflow", f"{len(dataflow.edges)} data-flow relationship(s) observed."),
    ]
    l1_missing = []
    if not c01 or c01.status != STATUS_DETECTED:
        l1_missing.append("documented AI inventory (C01 not DETECTED)")
    else:
        l1_evidence.append(_evidence(EVIDENCE_CONTROL, "C01", "AI inventory documentation detected (C01 DETECTED)."))
    if not c02 or c02.status != STATUS_DETECTED:
        l1_missing.append("documented threat model (C02 not DETECTED)")
    else:
        l1_evidence.append(_evidence(EVIDENCE_CONTROL, "C02", "AI threat-model documentation detected (C02 DETECTED)."))
    if signals.risk_register:
        l1_evidence.extend(_process_evidence_refs(signals.risk_register, limit=1))
    else:
        l1_missing.append("formal risk register documentation")
    level_assessments.append(
        LevelAssessment(
            level=1, name=LEVEL_NAMES[1], status=STATUS_ACHIEVED,
            evidence=l1_evidence,
            missing_requirements=[m for m in l1_missing if m],
            confidence="high",
            rationale="AI components, attack surface, and data-flow relationships were identified in this repository — AI has been brought into security scope.",
        )
    )

    # ---- LEVEL 2 — MANAGED ----------------------------------------------
    # Mandatory gate: evidence of a REPEATABLE security test/eval practice.
    # Per directive: "No recurring adversarial testing -> cannot award Level 2."
    l2_gate = bool(signals.security_test_artifact) or bool(signals.documented_eval_process)
    l2_supporting = []
    if signals.security_test_artifact:
        l2_supporting.append("security_test_artifact")
    if signals.documented_eval_process:
        l2_supporting.append("documented_eval_process")
    governance_signals = [c for c in (c05, c07, c09, c10) if control_ok(c)]
    if governance_signals:
        l2_supporting.append("tool_governance")

    if not l2_gate:
        level_assessments.append(
            LevelAssessment(
                level=2, name=LEVEL_NAMES[2], status=STATUS_NOT_ACHIEVED,
                evidence=[], missing_requirements=[
                    "no repeatable AI/security test artifact detected (e.g. tests/security/, tests/redteam/, evals/)",
                    "no documented AI evaluation process found in repository documentation",
                ],
                confidence="moderate",
                rationale="No evidence of a repeatable, documented AI security testing practice was found — Level 2 requires this as a gating requirement.",
            )
        )
    else:
        l2_status = STATUS_ACHIEVED if len(l2_supporting) >= 2 else STATUS_PARTIAL
        l2_evidence = _process_evidence_refs(signals.security_test_artifact + signals.documented_eval_process)
        for c in governance_signals:
            l2_evidence.append(_evidence(EVIDENCE_CONTROL, c.control_id, f"{c.control_id} {c.name}: {c.status} — supports tool/prompt/retrieval governance evidence."))
        l2_missing = []
        if "security_test_artifact" not in l2_supporting:
            l2_missing.append("no dedicated security/redteam/eval test directory found")
        if "documented_eval_process" not in l2_supporting:
            l2_missing.append("no documented AI evaluation process found")
        if "tool_governance" not in l2_supporting:
            l2_missing.append("no tool/prompt/retrieval governance control evidence found (C05/C07/C09/C10)")
        level_assessments.append(
            LevelAssessment(
                level=2, name=LEVEL_NAMES[2], status=l2_status,
                evidence=l2_evidence,
                missing_requirements=l2_missing,
                confidence="moderate" if l2_status == STATUS_PARTIAL else "high",
                rationale=(
                    "Repository evidence shows a repeatable AI security testing artifact or "
                    "documented evaluation process." + (" Supporting governance evidence is limited." if l2_status == STATUS_PARTIAL else "")
                ),
            )
        )

    l2_final_status = level_assessments[-1].status

    # ---- LEVEL 3 — HARDENED ----------------------------------------------
    # Mandatory gate: CI-integrated security evaluation (a real release-process
    # signal, not just a standalone scanner). Per directive: "No security-
    # integrated release process -> cannot award Level 3."
    l3_prereq_ok = l2_final_status in (STATUS_ACHIEVED, STATUS_PARTIAL)
    l3_gate = bool(signals.ci_security_gate) and l3_prereq_ok

    if not l3_gate:
        missing = [] if l3_prereq_ok else ["Level 2 not sufficiently achieved"]
        if not signals.ci_security_gate:
            missing.append("no CI configuration found integrating security/eval testing into the release process")
        level_assessments.append(
            LevelAssessment(
                level=3, name=LEVEL_NAMES[3], status=STATUS_NOT_ACHIEVED,
                evidence=[], missing_requirements=missing,
                confidence="moderate",
                rationale="No evidence that AI security testing is integrated into CI/release workflow was found — Level 3 requires this as a gating requirement.",
            )
        )
    else:
        l3_supporting = ["ci_security_gate"]
        if signals.remediation_retest:
            l3_supporting.append("remediation_retest")
        if control_ok(c07):
            l3_supporting.append("audit_trail")
        l3_status = STATUS_ACHIEVED if len(l3_supporting) >= 2 else STATUS_PARTIAL
        l3_evidence = _process_evidence_refs(signals.ci_security_gate + signals.remediation_retest)
        if control_ok(c07):
            l3_evidence.append(_evidence(EVIDENCE_CONTROL, "C07", f"C07 Logging/Auditability: {c07.status} — supports audit-trail evidence."))
        l3_missing = []
        if "remediation_retest" not in l3_supporting:
            l3_missing.append("no documented remediation/retest workflow found")
        if "audit_trail" not in l3_supporting:
            l3_missing.append("no AI/security-specific audit-logging evidence found (C07)")
        level_assessments.append(
            LevelAssessment(
                level=3, name=LEVEL_NAMES[3], status=l3_status,
                evidence=l3_evidence,
                missing_requirements=l3_missing,
                confidence="moderate" if l3_status == STATUS_PARTIAL else "high",
                rationale="Repository CI configuration integrates security/evaluation testing into the workflow." + (" Supporting remediation/audit evidence is limited." if l3_status == STATUS_PARTIAL else ""),
            )
        )

    l3_final_status = level_assessments[-1].status

    # ---- LEVEL 4 — CONTINUOUS ---------------------------------------------
    # Mandatory gate: an actual loop — CI security gate AND a scheduled/
    # recurring trigger, not just CI existing. Per directive: "If only one
    # component exists, do not award Level 4."
    l4_prereq_ok = l3_final_status in (STATUS_ACHIEVED, STATUS_PARTIAL)
    l4_loop_ok = bool(signals.ci_security_gate) and bool(signals.scheduled_security_evaluation)
    l4_gate = l4_loop_ok and l4_prereq_ok

    if not l4_gate:
        missing = [] if l4_prereq_ok else ["Level 3 not sufficiently achieved"]
        if not signals.scheduled_security_evaluation:
            missing.append("no scheduled/recurring security evaluation trigger found in CI configuration")
        level_assessments.append(
            LevelAssessment(
                level=4, name=LEVEL_NAMES[4], status=STATUS_NOT_ACHIEVED,
                evidence=[], missing_requirements=missing,
                confidence="moderate",
                rationale="No evidence of an ongoing, scheduled AI security assurance loop was found — Level 4 requires this as a gating requirement, and CI existing alone is not sufficient.",
            )
        )
    else:
        l4_supporting = ["scheduled_evaluation"]
        if signals.versioned_security_evidence:
            l4_supporting.append("versioned_evidence")
        if signals.security_metrics:
            l4_supporting.append("security_metrics")
        l4_status = STATUS_ACHIEVED if len(l4_supporting) >= 3 else STATUS_PARTIAL
        l4_evidence = _process_evidence_refs(signals.scheduled_security_evaluation + signals.versioned_security_evidence + signals.security_metrics)
        l4_missing = []
        if "versioned_evidence" not in l4_supporting:
            l4_missing.append("no versioned/dated security evidence artifacts found")
        if "security_metrics" not in l4_supporting:
            l4_missing.append("no security metrics/dashboard documentation found")
        level_assessments.append(
            LevelAssessment(
                level=4, name=LEVEL_NAMES[4], status=l4_status,
                evidence=l4_evidence,
                missing_requirements=l4_missing,
                confidence="moderate" if l4_status == STATUS_PARTIAL else "high",
                rationale="Repository evidence shows a scheduled/recurring security evaluation loop integrated with CI." + (" Supporting versioned-evidence/metrics artifacts are limited." if l4_status == STATUS_PARTIAL else ""),
            )
        )

    # ---- Final level selection: highest ACHIEVED level --------------------
    achieved_levels = [la.level for la in level_assessments if la.status == STATUS_ACHIEVED]
    final_level = max(achieved_levels) if achieved_levels else 1  # Level 1's gate is has_ai_signal, always met here
    final_assessment = next(la for la in level_assessments if la.level == final_level)

    blockers = []
    for la in level_assessments:
        if la.level == final_level + 1 and la.status != STATUS_ACHIEVED:
            blockers.extend(la.missing_requirements)

    risk_context_note = (
        f"Highest current risk severity from Phase 5: "
        f"{max((s.severity for s in risks.scenarios), default='none (no scenarios generated)', key=lambda sev: {'LOW': 0, 'MODERATE': 1, 'HIGH': 2, 'CRITICAL': 3}.get(sev, -1))}. "
        "This is provided as context only and did not influence the readiness level above — "
        "risk severity and readiness maturity are assessed independently."
    )

    return ReadinessAssessment(
        root=root,
        ai_surface_detected=True,
        readiness_level=final_level,
        readiness_name=LEVEL_NAMES[final_level],
        confidence=final_assessment.confidence,
        rationale=final_assessment.rationale + " " + risk_context_note,
        evidence=final_assessment.evidence,
        level_assessments=level_assessments,
        blockers=sorted(set(blockers)),
        limitations=list(_STANDARD_LIMITATIONS),
        assessment_completeness=completeness,
    )
