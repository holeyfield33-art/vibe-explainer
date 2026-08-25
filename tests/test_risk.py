import unittest
from pathlib import Path

from vibe_explainer.ai_discovery import discover_ai
from vibe_explainer.attack_surface import build_attack_surface
from vibe_explainer.controls import assess_controls
from vibe_explainer.dataflow import build_dataflow
from vibe_explainer.risk import (
    COMPLETENESS_COMPLETE,
    COMPLETENESS_AGGREGATED,
    COMPLETENESS_PARTIAL,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MODERATE,
    assess_risks,
    score_risk,
    severity_for,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _assess(fixture_name: str):
    discovery = discover_ai(FIXTURES / fixture_name)
    surface = build_attack_surface(discovery)
    graph = build_dataflow(discovery)
    controls = assess_controls(discovery, surface, graph)
    return assess_risks(discovery, surface, graph, controls)


def _by_category(assessment, category):
    return [s for s in assessment.scenarios if s.category == category]


class TestScoringFormula(unittest.TestCase):
    def test_all_ones(self):
        self.assertEqual(score_risk(1, 1, 1, 1), 1)

    def test_all_fives(self):
        self.assertEqual(score_risk(5, 5, 5, 5), 25)

    def test_worked_example_from_directive(self):
        # exposure 4, safety 5, security 5, likelihood 4 -> 19
        self.assertEqual(score_risk(4, 5, 5, 4), 19)


class TestSeverityBoundaries(unittest.TestCase):
    def test_seven_is_low(self):
        self.assertEqual(severity_for(7), SEVERITY_LOW)

    def test_eight_is_moderate(self):
        self.assertEqual(severity_for(8), SEVERITY_MODERATE)

    def test_fourteen_is_moderate(self):
        self.assertEqual(severity_for(14), SEVERITY_MODERATE)

    def test_fifteen_is_high(self):
        self.assertEqual(severity_for(15), SEVERITY_HIGH)

    def test_nineteen_is_high(self):
        self.assertEqual(severity_for(19), SEVERITY_HIGH)

    def test_twenty_is_critical(self):
        self.assertEqual(severity_for(20), SEVERITY_CRITICAL)

    def test_twentyfive_is_critical(self):
        self.assertEqual(severity_for(25), SEVERITY_CRITICAL)


class TestNoAIRepository(unittest.TestCase):
    def test_zero_scenarios_and_surface_not_detected(self):
        assessment = _assess("../../examples/sample-vibe-project")
        self.assertFalse(assessment.ai_surface_detected)
        self.assertEqual(assessment.scenarios, [])

    def test_summary_note_never_claims_security(self):
        assessment = _assess("../../examples/sample-vibe-project")
        self.assertNotIn("secure", assessment.summary_note.lower())


class TestLowImpactChatbot(unittest.TestCase):
    def test_generates_low_or_moderate_scenarios_not_nothing(self):
        assessment = _assess("basic-chatbot")
        self.assertTrue(assessment.ai_surface_detected)
        self.assertGreater(len(assessment.scenarios), 0)
        for s in assessment.scenarios:
            self.assertIn(s.severity, (SEVERITY_LOW, SEVERITY_MODERATE))


class TestUserInputToModel(unittest.TestCase):
    def test_input_security_scenario_generated(self):
        assessment = _assess("basic-chatbot")
        scenarios = _by_category(assessment, "INPUT_SECURITY")
        self.assertEqual(len(scenarios), 1)
        self.assertTrue(scenarios[0].evidence)


class TestAuthorizedVsUnauthorizedTool(unittest.TestCase):
    def test_unauthorized_tool_has_higher_security_exposure(self):
        unauth = _by_category(_assess("agent-with-tools"), "TOOL_SECURITY")[0]
        auth = _by_category(_assess("controls-tool-with-auth"), "TOOL_SECURITY")[0]
        self.assertGreater(unauth.security_exposure, auth.security_exposure)
        self.assertGreaterEqual(unauth.score, auth.score)

    def test_unauthorized_high_impact_scores_higher_than_authorized(self):
        unauth = _by_category(_assess("agent-with-tools"), "HIGH_IMPACT_ACTION")[0]
        auth = _by_category(_assess("controls-tool-with-auth"), "HIGH_IMPACT_ACTION")[0]
        self.assertGreater(unauth.score, auth.score)
        self.assertEqual(unauth.severity, SEVERITY_HIGH)
        self.assertEqual(auth.severity, SEVERITY_LOW)

    def test_authorized_tool_scenario_rationale_recognizes_control(self):
        auth = _by_category(_assess("controls-tool-with-auth"), "TOOL_SECURITY")[0]
        self.assertIn("C05", auth.rationale)


class TestSecretExposure(unittest.TestCase):
    def setUp(self):
        self.assessment = _assess("hardcoded-credential")
        self.scenarios = _by_category(self.assessment, "SECRET_EXPOSURE")

    def test_secret_exposure_scenario_generated(self):
        self.assertEqual(len(self.scenarios), 1)

    def test_secret_value_is_redacted(self):
        for e in self.scenarios[0].evidence:
            self.assertNotIn("sk-proj-", e.description)
            self.assertNotIn("abcdefghijklmnopqrstuvwxyz012345", e.description)

    def test_no_hardcoded_secret_no_scenario(self):
        clean = _assess("basic-chatbot")
        self.assertEqual(_by_category(clean, "SECRET_EXPOSURE"), [])


class TestRedactionBoundaryHoldsRegardlessOfPath(unittest.TestCase):
    """Regression coverage for a gap an external review found: redaction must hold
    for EVERY evidence description this module produces, not just the specific
    field a particular fixture happens to exercise. Tests the redaction helpers
    directly with a synthetic secret, independent of whether today's fixtures can
    naturally coerce a secret into that specific code path."""

    def test_dataflow_evidence_ref_redacts_regardless_of_content(self):
        from vibe_explainer.dataflow import STATUS_INFERRED, DataFlowObservation
        from vibe_explainer.risk import _dataflow_evidence_ref

        fake_edge = DataFlowObservation(
            source_finding_id="aaa", destination_finding_id="bbb",
            source_type="secret_config", destination_type="ai_usage",
            relationship="reads_storage", file="x.py", source_line=1, destination_line=2,
            confidence="high",
            evidence="synthetic evidence containing sk-proj-abcdefghijklmnopqrstuvwxyz012345",
            status=STATUS_INFERRED,
        )
        ref = _dataflow_evidence_ref(fake_edge, "test note")
        self.assertNotIn("sk-proj-abcdefghijklmnopqrstuvwxyz012345", ref.description)
        self.assertIn("[REDACTED]", ref.description)

    def test_control_evidence_ref_redacts_regardless_of_content(self):
        from vibe_explainer.controls import SecurityControl
        from vibe_explainer.risk import _control_evidence_ref

        fake_control = SecurityControl(
            control_id="C08", name="Secret Management", category="SECRET_MANAGEMENT",
            status="NOT_DETECTED", confidence="high", evidence=[],
            related_finding_ids=[], related_dataflow_ids=[],
            rationale="Found sk-proj-abcdefghijklmnopqrstuvwxyz012345 hardcoded in source.",
        )
        refs = _control_evidence_ref(fake_control)
        self.assertEqual(len(refs), 1)
        self.assertNotIn("sk-proj-abcdefghijklmnopqrstuvwxyz012345", refs[0].description)
        self.assertIn("[REDACTED]", refs[0].description)


class TestRAGWithoutControls(unittest.TestCase):
    def test_rag_security_scenario_generated(self):
        assessment = _assess("rag-app")
        scenarios = _by_category(assessment, "RAG_SECURITY")
        self.assertEqual(len(scenarios), 1)

    def test_rag_with_controls_scores_lower(self):
        without = _by_category(_assess("rag-app"), "RAG_SECURITY")[0]
        withc = _by_category(_assess("controls-rag-with-controls"), "RAG_SECURITY")[0]
        self.assertGreaterEqual(without.security_exposure, withc.security_exposure)


class TestMCPWithoutGovernance(unittest.TestCase):
    def test_mcp_security_scenario_generated(self):
        assessment = _assess("mcp-server")
        self.assertEqual(len(_by_category(assessment, "MCP_SECURITY")), 1)


class TestHighImpactAction(unittest.TestCase):
    def test_shell_sink_scores_high_severity_by_default(self):
        assessment = _assess("dataflow-model-to-shell")
        scenarios = _by_category(assessment, "HIGH_IMPACT_ACTION")
        self.assertEqual(len(scenarios), 1)
        self.assertEqual(scenarios[0].safety_impact, 5)
        self.assertEqual(scenarios[0].severity, SEVERITY_HIGH)


class TestTruncatedDiscovery(unittest.TestCase):
    def test_completeness_aggregated_when_truncated(self):
        # Repeated same-pattern matches summarized past the display cap are fully
        # counted -> AGGREGATED (thorough), not PARTIAL (a genuine gap).
        assessment = _assess("truncation-heavy")
        self.assertEqual(assessment.assessment_completeness, COMPLETENESS_AGGREGATED)

    def test_completeness_complete_when_not_truncated(self):
        assessment = _assess("basic-chatbot")
        self.assertEqual(assessment.assessment_completeness, COMPLETENESS_COMPLETE)


class TestFalsePositiveProtection(unittest.TestCase):
    def test_bare_llm_import_alone_does_not_create_critical_risk(self):
        # controls-docs has AI usage but no sinks, no prompt chain, no tools
        assessment = _assess("controls-docs")
        for s in assessment.scenarios:
            self.assertNotEqual(s.severity, SEVERITY_CRITICAL)

    def test_well_controlled_chatbot_produces_no_scenarios(self):
        assessment = _assess("controls-well-controlled")
        self.assertEqual(assessment.scenarios, [])

    def test_no_scenario_without_relevant_attack_surface(self):
        # no-AI repo: missing controls (all NOT_APPLICABLE) must not spawn risks
        assessment = _assess("../../examples/sample-vibe-project")
        self.assertEqual(assessment.scenarios, [])


class TestTraceability(unittest.TestCase):
    def test_related_finding_ids_reference_real_findings(self):
        discovery = discover_ai(FIXTURES / "agent-with-tools")
        assessment = _assess("agent-with-tools")
        finding_ids = {f.id for f in discovery.findings}
        for s in assessment.scenarios:
            for fid in s.related_finding_ids:
                self.assertIn(fid, finding_ids)

    def test_related_dataflow_ids_reference_real_edges(self):
        discovery = discover_ai(FIXTURES / "agent-with-tools")
        surface = build_attack_surface(discovery)
        graph = build_dataflow(discovery)
        edge_keys = {f"{e.source_finding_id}->{e.destination_finding_id}:{e.relationship}" for e in graph.edges}
        controls = assess_controls(discovery, surface, graph)
        assessment = assess_risks(discovery, surface, graph, controls)
        for s in assessment.scenarios:
            for did in s.related_dataflow_ids:
                self.assertIn(did, edge_keys)

    def test_related_control_ids_reference_real_controls(self):
        discovery = discover_ai(FIXTURES / "agent-with-tools")
        surface = build_attack_surface(discovery)
        graph = build_dataflow(discovery)
        controls = assess_controls(discovery, surface, graph)
        control_ids = {c.control_id for c in controls.controls}
        assessment = assess_risks(discovery, surface, graph, controls)
        for s in assessment.scenarios:
            for cid in s.related_control_ids:
                self.assertIn(cid, control_ids)


class TestGrouping(unittest.TestCase):
    def test_single_chain_produces_one_scenario_not_three(self):
        # basic-chatbot has 3 findings in one feeds_prompt chain (prompt, ai_usage,
        # plus the secret) -- must not explode into a risk per finding.
        assessment = _assess("basic-chatbot")
        input_scenarios = _by_category(assessment, "INPUT_SECURITY")
        self.assertEqual(len(input_scenarios), 1)


class TestDeterminism(unittest.TestCase):
    def test_same_input_produces_identical_assessment(self):
        a1 = _assess("agent-with-tools")
        a2 = _assess("agent-with-tools")
        self.assertEqual([s.to_dict() for s in a1.scenarios], [s.to_dict() for s in a2.scenarios])

    def test_scenarios_sorted_by_risk_id(self):
        assessment = _assess("agent-with-tools")
        ids = [s.risk_id for s in assessment.scenarios]
        self.assertEqual(ids, sorted(ids))


if __name__ == "__main__":
    unittest.main()
