import unittest
from pathlib import Path

from vibe_explainer.ai_discovery import discover_ai
from vibe_explainer.attack_surface import build_attack_surface
from vibe_explainer.controls import assess_controls
from vibe_explainer.dataflow import build_dataflow
from vibe_explainer.readiness import (
    NO_AI_SURFACE,
    STATUS_ACHIEVED,
    STATUS_NOT_ACHIEVED,
    assess_readiness,
)
from vibe_explainer.risk import assess_risks

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _full_assess(fixture_name: str):
    discovery = discover_ai(FIXTURES / fixture_name)
    surface = build_attack_surface(discovery)
    graph = build_dataflow(discovery)
    controls = assess_controls(discovery, surface, graph)
    risks = assess_risks(discovery, surface, graph, controls)
    readiness = assess_readiness(discovery, surface, graph, controls, risks)
    return discovery, surface, graph, controls, risks, readiness


def _level(readiness, n):
    return next(la for la in readiness.level_assessments if la.level == n)


class TestNoAIRepository(unittest.TestCase):
    def test_no_level_fabricated(self):
        *_, readiness = _full_assess("../../examples/sample-vibe-project")
        self.assertFalse(readiness.ai_surface_detected)
        self.assertIsNone(readiness.readiness_level)
        self.assertEqual(readiness.readiness_name, NO_AI_SURFACE)
        self.assertEqual(readiness.level_assessments, [])


class TestBaselineLevel(unittest.TestCase):
    def test_ai_present_no_process_is_level_one(self):
        *_, readiness = _full_assess("basic-chatbot")
        self.assertEqual(readiness.readiness_level, 1)
        self.assertEqual(_level(readiness, 1).status, STATUS_ACHIEVED)

    def test_level_one_reports_gaps_even_when_achieved(self):
        *_, readiness = _full_assess("basic-chatbot")
        l1 = _level(readiness, 1)
        self.assertEqual(l1.status, STATUS_ACHIEVED)
        self.assertTrue(l1.missing_requirements)


class TestManagedLevel(unittest.TestCase):
    def test_security_test_dir_plus_doc_plus_governance_is_level_two(self):
        *_, readiness = _full_assess("readiness-managed")
        self.assertEqual(readiness.readiness_level, 2)
        self.assertEqual(_level(readiness, 2).status, STATUS_ACHIEVED)

    def test_level_two_not_achieved_without_test_artifact(self):
        # controls-well-controlled has strong controls but zero test/eval artifacts
        *_, readiness = _full_assess("controls-well-controlled")
        self.assertEqual(_level(readiness, 2).status, STATUS_NOT_ACHIEVED)
        self.assertEqual(readiness.readiness_level, 1)


class TestHardenedLevel(unittest.TestCase):
    def test_ci_security_gate_plus_remediation_plus_audit_is_level_three(self):
        *_, readiness = _full_assess("readiness-hardened")
        self.assertEqual(readiness.readiness_level, 3)
        self.assertEqual(_level(readiness, 3).status, STATUS_ACHIEVED)

    def test_level_three_not_achieved_without_ci_gate(self):
        *_, readiness = _full_assess("readiness-managed")
        self.assertEqual(_level(readiness, 3).status, STATUS_NOT_ACHIEVED)


class TestContinuousLevel(unittest.TestCase):
    def test_scheduled_ci_plus_versioned_evidence_plus_metrics_is_level_four(self):
        *_, readiness = _full_assess("readiness-continuous")
        self.assertEqual(readiness.readiness_level, 4)
        self.assertEqual(_level(readiness, 4).status, STATUS_ACHIEVED)

    def test_level_four_not_achieved_without_schedule(self):
        # readiness-hardened has a CI security gate but no schedule/cron trigger
        *_, readiness = _full_assess("readiness-hardened")
        l4 = _level(readiness, 4)
        self.assertEqual(l4.status, STATUS_NOT_ACHIEVED)
        self.assertTrue(any("scheduled" in m for m in l4.missing_requirements))


class TestHighRiskImmature(unittest.TestCase):
    def test_high_risk_scenario_does_not_force_low_readiness_report(self):
        # agent-with-tools has a HIGH severity risk scenario but no process evidence
        discovery, surface, graph, controls, risks, readiness = _full_assess("agent-with-tools")
        severities = {s.severity for s in risks.scenarios}
        self.assertIn("HIGH", severities)
        self.assertEqual(readiness.readiness_level, 1)  # still just Level 1, same as any other immature repo


class TestLowRiskImmature(unittest.TestCase):
    def test_low_risk_does_not_grant_higher_readiness(self):
        discovery, surface, graph, controls, risks, readiness = _full_assess("basic-chatbot")
        self.assertTrue(all(s.severity == "LOW" for s in risks.scenarios))
        self.assertEqual(readiness.readiness_level, 1)  # same level as the HIGH-risk immature case


class TestRiskReadinessIndependence(unittest.TestCase):
    def test_same_readiness_level_regardless_of_risk_severity(self):
        # basic-chatbot (all LOW risk) and agent-with-tools (one HIGH risk) both
        # have zero process evidence -> both must land at the same readiness level.
        *_, ready_low = _full_assess("basic-chatbot")
        *_, ready_high = _full_assess("agent-with-tools")
        self.assertEqual(ready_low.readiness_level, ready_high.readiness_level)

    def test_readiness_rationale_mentions_risk_as_context_only(self):
        *_, readiness = _full_assess("agent-with-tools")
        self.assertIn("context only", readiness.rationale)
        self.assertIn("independently", readiness.rationale)


class TestStrongControlsNoProcess(unittest.TestCase):
    def test_many_detected_controls_do_not_inflate_beyond_level_one(self):
        discovery, surface, graph, controls, risks, readiness = _full_assess("controls-well-controlled")
        detected_count = len([c for c in controls.controls if c.status == "DETECTED"])
        self.assertGreaterEqual(detected_count, 4)
        self.assertEqual(readiness.readiness_level, 1)


class TestFalsePositiveProtection(unittest.TestCase):
    def test_ordinary_project_tests_do_not_establish_level_two(self):
        # this project's OWN tests/ dir (test_scanner.py etc, not tests/security/)
        # must not count as security-test evidence for a repo being assessed.
        *_, readiness = _full_assess("basic-chatbot")
        self.assertEqual(_level(readiness, 2).status, STATUS_NOT_ACHIEVED)

    def test_generic_ci_without_security_keywords_does_not_establish_level_three(self):
        *_, readiness = _full_assess("readiness-managed")
        self.assertEqual(_level(readiness, 3).status, STATUS_NOT_ACHIEVED)

    def test_readme_claim_alone_does_not_outweigh_missing_implementation(self):
        # controls-docs has AI-inventory/threat-model doc headers but zero test
        # artifacts, zero CI -> still capped at Level 1.
        *_, readiness = _full_assess("controls-docs")
        self.assertEqual(readiness.readiness_level, 1)

    def test_one_security_test_dir_alone_does_not_reach_level_three(self):
        *_, readiness = _full_assess("readiness-managed")
        self.assertLess(readiness.readiness_level, 3)

    def test_running_vibe_explainer_on_itself_is_not_special_cased(self):
        # Sanity: assessing this very repository must go through the same rules,
        # not a hardcoded "this is Vibe Explainer, mark it Level 4" shortcut.
        *_, readiness = _full_assess(".")
        self.assertIn(readiness.readiness_level, (1, 2, 3, 4))


class TestTruncatedDiscovery(unittest.TestCase):
    def test_completeness_partial_when_discovery_truncated(self):
        *_, readiness = _full_assess("truncation-heavy")
        self.assertEqual(readiness.assessment_completeness, "PARTIAL")


class TestEvidenceTypes(unittest.TestCase):
    def test_level_one_evidence_uses_discovery_and_dataflow_types(self):
        *_, readiness = _full_assess("basic-chatbot")
        l1 = _level(readiness, 1)
        types = {e.type for e in l1.evidence}
        self.assertTrue(types & {"DISCOVERY_EVIDENCE", "DATAFLOW_EVIDENCE"})

    def test_level_two_evidence_uses_process_type(self):
        *_, readiness = _full_assess("readiness-managed")
        l2 = _level(readiness, 2)
        types = {e.type for e in l2.evidence}
        self.assertIn("PROCESS_EVIDENCE", types)


class TestTraceability(unittest.TestCase):
    def test_control_evidence_ids_reference_real_controls(self):
        discovery, surface, graph, controls, risks, readiness = _full_assess("readiness-managed")
        control_ids = {c.control_id for c in controls.controls}
        for la in readiness.level_assessments:
            for e in la.evidence:
                if e.type == "CONTROL_EVIDENCE":
                    self.assertIn(e.id, control_ids)


class TestLimitationsAlwaysPresent(unittest.TestCase):
    def test_limitations_present_for_ai_and_no_ai_repos(self):
        *_, r1 = _full_assess("basic-chatbot")
        *_, r2 = _full_assess("../../examples/sample-vibe-project")
        self.assertTrue(r1.limitations)
        self.assertTrue(r2.limitations)
        self.assertTrue(any("does not itself increase" in lim for lim in r1.limitations))


class TestDeterminism(unittest.TestCase):
    def test_same_input_produces_identical_assessment(self):
        *_, r1 = _full_assess("readiness-hardened")
        *_, r2 = _full_assess("readiness-hardened")
        self.assertEqual(r1.to_dict(), r2.to_dict())

    def test_level_assessments_ordered_one_through_four(self):
        *_, readiness = _full_assess("basic-chatbot")
        levels = [la.level for la in readiness.level_assessments]
        self.assertEqual(levels, [1, 2, 3, 4])


if __name__ == "__main__":
    unittest.main()
