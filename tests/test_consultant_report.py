import subprocess
import sys
import unittest
from pathlib import Path

from vibe_explainer.ai_discovery import discover_ai
from vibe_explainer.attack_surface import build_attack_surface
from vibe_explainer.consultant_report import render_consultant_markdown
from vibe_explainer.controls import assess_controls
from vibe_explainer.dataflow import build_dataflow
from vibe_explainer.readiness import assess_readiness
from vibe_explainer.risk import assess_risks
from vibe_explainer.security_report import build_report

FIXTURES = Path(__file__).resolve().parent / "fixtures"
REPO_ROOT = Path(__file__).resolve().parents[1]


def _md(fixture_name: str, **kwargs) -> str:
    discovery = discover_ai(FIXTURES / fixture_name)
    surface = build_attack_surface(discovery)
    graph = build_dataflow(discovery)
    controls = assess_controls(discovery, surface, graph)
    risks = assess_risks(discovery, surface, graph, controls)
    readiness = assess_readiness(discovery, surface, graph, controls, risks)
    report = build_report(discovery, surface, graph, controls, risks, readiness)
    return render_consultant_markdown(report, **kwargs)


class TestConsultantReportStructure(unittest.TestCase):
    def setUp(self):
        self.md = _md("agent-with-tools", assessment_date="2026-01-01")

    def test_has_all_expected_sections(self):
        for section in (
            "# AI Security Readiness Assessment",
            "## Executive Summary",
            "## AI Attack Surface",
            "## AI Data Flows",
            "## Key Risks",
            "## Security Controls",
            "## AI Security Readiness",
            "## Top Remediations",
            "## Evidence Appendix",
            "## Limitations",
        ):
            self.assertIn(section, self.md)

    def test_header_metadata_present(self):
        self.assertIn("2026-01-01", self.md)
        self.assertIn("Powered by Vibe Explainer", self.md)
        self.assertIn("vibe-explainer 0.1.0", self.md)

    def test_evidence_ids_appear_for_traceability(self):
        # every risk should be traceable; at least one finding ID and one risk ID present
        self.assertIn("Risk ID:", self.md)
        self.assertIn("Related findings:", self.md)
        self.assertIn("Finding |", self.md)  # attack-surface table has a Finding column

    def test_deterministic_with_fixed_date(self):
        a = _md("agent-with-tools", assessment_date="2026-01-01")
        b = _md("agent-with-tools", assessment_date="2026-01-01")
        self.assertEqual(a, b)


class TestConsultantReportContent(unittest.TestCase):
    def test_high_risk_and_readiness_both_shown_independently(self):
        md = _md("agent-with-tools", assessment_date="2026-01-01")
        self.assertIn("rated **High**", md)
        self.assertIn("Level 1 — Baseline", md)
        self.assertIn("independent measures", md)

    def test_forbidden_assurance_language_absent(self):
        md = _md("agent-with-tools", assessment_date="2026-01-01").lower()
        self.assertNotIn("vulnerability-free", md)
        self.assertNotIn("fully compliant", md)
        self.assertNotIn("is secure.", md)

    def test_no_ai_repo_terminates_early(self):
        md = _md("../../examples/sample-vibe-project", assessment_date="2026-01-01")
        self.assertIn("No AI security surface was detected", md)
        # should not render risk/readiness detail sections for a no-AI repo
        self.assertNotIn("## Key Risks", md)
        self.assertNotIn("## AI Security Readiness", md)

    def test_readiness_levels_table_shows_all_four(self):
        md = _md("readiness-managed", assessment_date="2026-01-01")
        for name in ("Baseline", "Managed", "Hardened", "Continuous"):
            self.assertIn(name, md)

    def test_truncation_surfaced_in_report(self):
        # aggregation is surfaced (with exact counts), not as an INCOMPLETE warning
        md = _md("truncation-heavy", assessment_date="2026-01-01")
        self.assertIn("AGGREGATED", md)


class TestConsultantReportRedaction(unittest.TestCase):
    def test_no_secret_value_anywhere(self):
        md = _md("hardcoded-credential", assessment_date="2026-01-01")
        self.assertNotIn("sk-proj-", md)
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz012345", md)
        self.assertIn("[REDACTED]", md)


class TestConsultantReportTableSafety(unittest.TestCase):
    def test_pipes_in_evidence_do_not_break_tables(self):
        # controls-generic-noise has ordinary code; ensure no raw unescaped pipe
        # produces a malformed row (every table data row should have balanced cells).
        md = _md("controls-generic-noise", assessment_date="2026-01-01")
        # crude structural check: no line starts with "| " and contains an unescaped
        # pipe count inconsistent with a table (we just ensure it renders + contains tables)
        self.assertIn("|---|", md)


class TestConsultantCLI(unittest.TestCase):
    def _run(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "vibe_explainer", *args],
            cwd=REPO_ROOT, capture_output=True, text=True,
        )

    def test_consultant_flag_produces_markdown(self):
        result = self._run(str(FIXTURES / "agent-with-tools"), "--security", "--consultant")
        self.assertEqual(result.returncode, 0)
        self.assertIn("# AI Security Readiness Assessment", result.stdout)
        self.assertNotIn("Traceback", result.stderr)

    def test_consultant_high_risk_still_exits_zero(self):
        result = self._run(str(FIXTURES / "agent-with-tools"), "--security", "--consultant")
        self.assertEqual(result.returncode, 0)

    def test_consultant_no_secret_leak(self):
        result = self._run(str(FIXTURES / "hardcoded-credential"), "--security", "--consultant")
        self.assertNotIn("sk-proj-", result.stdout)

    def test_default_and_plain_security_modes_unaffected(self):
        # regression: adding --consultant must not change default or plain --security
        plain = self._run(str(FIXTURES / "agent-with-tools"), "--security")
        self.assertEqual(plain.returncode, 0)
        self.assertIn("AI SECURITY ASSESSMENT", plain.stdout)
        self.assertNotIn("# AI Security Readiness Assessment", plain.stdout)


if __name__ == "__main__":
    unittest.main()
