import json
import subprocess
import sys
import unittest
from pathlib import Path

from vibe_explainer.ai_discovery import discover_ai
from vibe_explainer.attack_surface import build_attack_surface
from vibe_explainer.controls import assess_controls
from vibe_explainer.dataflow import build_dataflow
from vibe_explainer.readiness import assess_readiness
from vibe_explainer.risk import assess_risks
from vibe_explainer.security_report import build_report, render_text

FIXTURES = Path(__file__).resolve().parent / "fixtures"
REPO_ROOT = Path(__file__).resolve().parents[1]


def _report(fixture_name: str):
    discovery = discover_ai(FIXTURES / fixture_name)
    surface = build_attack_surface(discovery)
    graph = build_dataflow(discovery)
    controls = assess_controls(discovery, surface, graph)
    risks = assess_risks(discovery, surface, graph, controls)
    readiness = assess_readiness(discovery, surface, graph, controls, risks)
    return build_report(discovery, surface, graph, controls, risks, readiness)


class TestExecutiveSummary(unittest.TestCase):
    def test_ai_detected_case(self):
        report = _report("agent-with-tools")
        es = report.executive_summary
        self.assertEqual(es["ai_surface"], "DETECTED")
        self.assertEqual(es["risk_scenario_count"], len(report.risks["scenarios"]))
        self.assertEqual(es["highest_risk_severity"], "HIGH")
        self.assertEqual(es["readiness_level"], 1)

    def test_no_ai_case(self):
        report = _report("../../examples/sample-vibe-project")
        es = report.executive_summary
        self.assertEqual(es["ai_surface"], "NOT_DETECTED")
        self.assertEqual(es["risk_scenario_count"], 0)
        self.assertIsNone(es["highest_risk_severity"])
        self.assertIsNone(es["readiness_level"])
        self.assertIn("no AI surface was detected", es["statement"])

    def test_forbidden_language_never_appears(self):
        for fixture in ("agent-with-tools", "controls-well-controlled", "../../examples/sample-vibe-project"):
            report = _report(fixture)
            js = report.to_json().lower()
            for banned in ("vulnerability-free", "fully compliant"):
                self.assertNotIn(banned, js)
            # "secure"/"safe" only allowed as part of larger unrelated words is fine;
            # check the executive statement specifically never claims either.
            self.assertNotIn("is secure", report.executive_summary["statement"].lower())
            self.assertNotIn("is safe", report.executive_summary["statement"].lower())


class TestAIInventory(unittest.TestCase):
    def test_grouped_by_category(self):
        report = _report("basic-chatbot")
        self.assertIn("model_provider", report.ai_inventory["categories"])
        self.assertIn("prompt_surface", report.ai_inventory["categories"])

    def test_truncation_notice_present_when_truncated(self):
        report = _report("truncation-heavy")
        self.assertIsNotNone(report.ai_inventory["truncation_notice"])
        self.assertTrue(report.ai_inventory["truncated"])

    def test_no_truncation_notice_when_not_truncated(self):
        report = _report("basic-chatbot")
        self.assertIsNone(report.ai_inventory["truncation_notice"])


class TestAttackSurface(unittest.TestCase):
    def test_all_six_buckets_always_present(self):
        report = _report("basic-chatbot")
        self.assertEqual(set(report.attack_surface.keys()), {"inputs", "model", "retrieval", "tools", "outputs", "storage"})

    def test_outputs_bucket_empty_not_fabricated(self):
        report = _report("basic-chatbot")
        self.assertEqual(report.attack_surface["outputs"], [])


class TestDataFlows(unittest.TestCase):
    def test_edges_present_for_connected_fixture(self):
        report = _report("basic-chatbot")
        self.assertGreater(len(report.data_flows), 0)
        self.assertTrue(all("relationship" in e for e in report.data_flows))

    def test_no_cross_file_flow_implied(self):
        report = _report("dataflow-cross-file")
        self.assertEqual(report.data_flows, [])


class TestControls(unittest.TestCase):
    def test_grouped_by_status_includes_not_detected(self):
        report = _report("agent-with-tools")
        self.assertTrue(report.controls["by_status"]["NOT_DETECTED"])

    def test_not_detected_note_present(self):
        report = _report("agent-with-tools")
        self.assertIn("not that the control definitely does not exist", report.controls["note"])


class TestRiskSummary(unittest.TestCase):
    def test_severity_distribution_present(self):
        report = _report("agent-with-tools")
        self.assertEqual(sum(report.risks["by_severity"].values()), report.risks["total"])

    def test_risks_sorted_by_severity_then_score(self):
        report = _report("agent-with-tools")
        severities = [s["severity"] for s in report.risks["scenarios"]]
        order = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "LOW": 3}
        ranks = [order[sev] for sev in severities]
        self.assertEqual(ranks, sorted(ranks))


class TestReadiness(unittest.TestCase):
    def test_all_four_levels_shown(self):
        report = _report("basic-chatbot")
        levels = [la["level"] for la in report.readiness["level_assessments"]]
        self.assertEqual(levels, [1, 2, 3, 4])

    def test_blocked_reason_present_when_not_at_top(self):
        report = _report("basic-chatbot")
        self.assertIsNotNone(report.readiness["blocked_from_next_level"])

    def test_no_blocked_reason_at_level_four(self):
        report = _report("readiness-continuous")
        self.assertIsNone(report.readiness["blocked_from_next_level"])


class TestRiskReadinessDistinctionPreserved(unittest.TestCase):
    def test_both_present_and_independent_in_report(self):
        report = _report("agent-with-tools")
        self.assertIn("risk_scenario_count", report.executive_summary)
        self.assertIn("readiness_level", report.executive_summary)
        # sanity: same fixture as readiness Phase 6 test -- HIGH risk, Level 1
        self.assertEqual(report.executive_summary["highest_risk_severity"], "HIGH")
        self.assertEqual(report.executive_summary["readiness_level"], 1)


class TestRecommendations(unittest.TestCase):
    def test_recommendations_generated_for_high_risk(self):
        report = _report("agent-with-tools")
        self.assertTrue(report.recommendations)
        self.assertEqual(report.recommendations[0]["priority"], "P0")

    def test_priorities_sequential(self):
        report = _report("agent-with-tools")
        priorities = [r["priority"] for r in report.recommendations]
        self.assertEqual(priorities, [f"P{i}" for i in range(len(priorities))])

    def test_no_recommendations_for_well_controlled(self):
        report = _report("controls-well-controlled")
        # no risk scenarios, and readiness blocker still yields at most one rec
        risk_derived = [r for r in report.recommendations if r["related_risk_ids"]]
        self.assertEqual(risk_derived, [])

    def test_dedup_control_not_double_recommended_with_its_risk(self):
        report = _report("agent-with-tools")
        c05_recs = [r for r in report.recommendations if "C05" in r["related_control_ids"] and not r["related_risk_ids"]]
        # C05 gap is already covered by the TOOL_SECURITY/HIGH_IMPACT_ACTION risk
        # recommendations -- must not ALSO get its own standalone C05 recommendation
        self.assertEqual(c05_recs, [])


class TestLimitations(unittest.TestCase):
    def test_limitations_always_present(self):
        for fixture in ("agent-with-tools", "../../examples/sample-vibe-project"):
            report = _report(fixture)
            self.assertTrue(report.limitations)

    def test_truncation_limitation_added_when_truncated(self):
        report = _report("truncation-heavy")
        self.assertTrue(any("truncated" in lim for lim in report.limitations))


class TestSecretRedaction(unittest.TestCase):
    def test_no_secret_value_anywhere_in_report(self):
        report = _report("hardcoded-credential")
        js = report.to_json()
        self.assertNotIn("sk-proj-", js)
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz012345", js)
        self.assertIn("[REDACTED]", js)

    def test_risk_scenario_evidence_specifically_redacted(self):
        # Pinpoint check on the exact field an external review flagged: the risk
        # scenario evidence list was being serialized with e.to_dict() and no
        # redaction pass at the Phase 7 boundary. Verify the specific field now.
        report = _report("hardcoded-credential")
        secret_scenarios = [s for s in report.risks["scenarios"] if s["category"] == "SECRET_EXPOSURE"]
        self.assertTrue(secret_scenarios)
        for scenario in secret_scenarios:
            for e in scenario["evidence"]:
                self.assertNotIn("sk-proj-", e["description"])
                self.assertNotIn("abcdefghijklmnopqrstuvwxyz012345", e["description"])


class TestJSONValidity(unittest.TestCase):
    def test_valid_json_no_ansi(self):
        report = _report("agent-with-tools")
        js = report.to_json()
        parsed = json.loads(js)  # raises if invalid
        self.assertIn("executive_summary", parsed)
        self.assertNotIn("\x1b[", js)  # no ANSI escape codes

    def test_deterministic_serialization(self):
        r1 = _report("agent-with-tools")
        r2 = _report("agent-with-tools")
        self.assertEqual(r1.to_json(), r2.to_json())

    def test_ids_traceable_in_json(self):
        report = _report("agent-with-tools")
        js = json.loads(report.to_json())
        finding_ids = {f["id"] for cat in js["ai_inventory"]["categories"].values() for f in cat}
        for scenario in js["risks"]["scenarios"]:
            for fid in scenario["related_finding_ids"]:
                self.assertIn(fid, finding_ids)


class TestTextRendering(unittest.TestCase):
    def test_renders_without_error_for_ai_and_no_ai(self):
        for fixture in ("agent-with-tools", "../../examples/sample-vibe-project"):
            report = _report(fixture)
            text = render_text(report)
            self.assertIn("VIBE EXPLAINER", text)
            self.assertNotIn("\x1b[", text)


class TestCLI(unittest.TestCase):
    def _run(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "vibe_explainer", *args],
            cwd=REPO_ROOT, capture_output=True, text=True,
        )

    def test_default_mode_unchanged(self):
        result = self._run(str(FIXTURES / "basic-chatbot"))
        self.assertEqual(result.returncode, 0)
        self.assertIn("Mental model", result.stdout)

    def test_security_mode_human_readable(self):
        result = self._run(str(FIXTURES / "agent-with-tools"), "--security")
        self.assertEqual(result.returncode, 0)
        self.assertIn("AI SECURITY ASSESSMENT", result.stdout)
        self.assertIn("RISKS", result.stdout)
        self.assertIn("READINESS", result.stdout)
        self.assertNotIn("Traceback", result.stderr)

    def test_security_mode_json(self):
        result = self._run(str(FIXTURES / "agent-with-tools"), "--security", "--json")
        self.assertEqual(result.returncode, 0)
        parsed = json.loads(result.stdout)
        self.assertIn("executive_summary", parsed)

    def test_high_risk_repo_still_exits_zero(self):
        result = self._run(str(FIXTURES / "agent-with-tools"), "--security", "--json")
        self.assertEqual(result.returncode, 0)

    def test_no_ai_repo_security_mode(self):
        result = self._run(str(REPO_ROOT / "examples" / "sample-vibe-project"), "--security")
        self.assertEqual(result.returncode, 0)
        self.assertIn("NOT_DETECTED", result.stdout)

    def test_bad_path_exits_nonzero_no_traceback(self):
        result = self._run("/definitely/not/a/real/path", "--security")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("Traceback", result.stderr)

    def test_no_secret_leakage_via_cli(self):
        result = self._run(str(FIXTURES / "hardcoded-credential"), "--security", "--json")
        self.assertNotIn("sk-proj-", result.stdout)


if __name__ == "__main__":
    unittest.main()
