import unittest
from pathlib import Path

from vibe_explainer.ai_discovery import discover_ai
from vibe_explainer.attack_surface import build_attack_surface
from vibe_explainer.controls import (
    STATUS_DETECTED,
    STATUS_NOT_APPLICABLE,
    STATUS_NOT_DETECTED,
    STATUS_PARTIAL,
    assess_controls,
)
from vibe_explainer.dataflow import build_dataflow

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _assess(fixture_name: str):
    discovery = discover_ai(FIXTURES / fixture_name)
    surface = build_attack_surface(discovery)
    graph = build_dataflow(discovery)
    return assess_controls(discovery, surface, graph)


def _control(assessment, control_id):
    return next(c for c in assessment.controls if c.control_id == control_id)


class TestWellControlledChatbot(unittest.TestCase):
    def setUp(self):
        self.assessment = _assess("controls-well-controlled")

    def test_input_handling_detected(self):
        self.assertEqual(_control(self.assessment, "C03").status, STATUS_DETECTED)

    def test_output_handling_detected(self):
        self.assertEqual(_control(self.assessment, "C04").status, STATUS_DETECTED)

    def test_logging_detected(self):
        self.assertEqual(_control(self.assessment, "C07").status, STATUS_DETECTED)

    def test_secret_management_detected_but_moderate_confidence(self):
        # env-based only: DETECTED, but confidence stays moderate — env vars
        # alone don't prove a real secret manager is behind them.
        c08 = _control(self.assessment, "C08")
        self.assertEqual(c08.status, STATUS_DETECTED)
        self.assertEqual(c08.confidence, "moderate")

    def test_multiple_controls_detected(self):
        detected = [c for c in self.assessment.controls if c.status == STATUS_DETECTED]
        self.assertGreaterEqual(len(detected), 4)

    def test_every_control_result_has_rationale(self):
        for c in self.assessment.controls:
            self.assertTrue(c.rationale)


class TestToolWithoutAuthorization(unittest.TestCase):
    def test_c05_not_detected(self):
        assessment = _assess("agent-with-tools")
        c05 = _control(assessment, "C05")
        self.assertEqual(c05.status, STATUS_NOT_DETECTED)
        # per the directive's own example: NOT_DETECTED can still carry
        # dataflow evidence explaining what was searched
        self.assertTrue(any(e.type == "dataflow" for e in c05.evidence))

    def test_c05_related_finding_ids_reference_real_findings(self):
        discovery = discover_ai(FIXTURES / "agent-with-tools")
        assessment = _assess("agent-with-tools")
        c05 = _control(assessment, "C05")
        finding_ids = {f.id for f in discovery.findings}
        for fid in c05.related_finding_ids:
            self.assertIn(fid, finding_ids)


class TestToolWithAuthorization(unittest.TestCase):
    def test_c05_detected(self):
        assessment = _assess("controls-tool-with-auth")
        c05 = _control(assessment, "C05")
        self.assertEqual(c05.status, STATUS_DETECTED)
        self.assertTrue(c05.evidence)


class TestHardcodedCredential(unittest.TestCase):
    def test_c08_not_detected_high_confidence(self):
        assessment = _assess("hardcoded-credential")
        c08 = _control(assessment, "C08")
        self.assertEqual(c08.status, STATUS_NOT_DETECTED)
        self.assertEqual(c08.confidence, "high")


class TestEnvBasedCredential(unittest.TestCase):
    def test_c08_detected_or_partial(self):
        assessment = _assess("basic-chatbot")
        c08 = _control(assessment, "C08")
        self.assertIn(c08.status, (STATUS_DETECTED, STATUS_PARTIAL))


class TestRAGWithoutControls(unittest.TestCase):
    def test_c09_not_detected(self):
        assessment = _assess("rag-app")
        self.assertEqual(_control(assessment, "C09").status, STATUS_NOT_DETECTED)


class TestRAGWithControls(unittest.TestCase):
    def test_c09_detected_or_partial(self):
        assessment = _assess("controls-rag-with-controls")
        c09 = _control(assessment, "C09")
        self.assertIn(c09.status, (STATUS_DETECTED, STATUS_PARTIAL))
        self.assertTrue(c09.evidence)


class TestMCPWithoutGovernance(unittest.TestCase):
    def test_c10_not_detected(self):
        assessment = _assess("mcp-server")
        self.assertEqual(_control(assessment, "C10").status, STATUS_NOT_DETECTED)


class TestNoAIApplication(unittest.TestCase):
    def test_all_conditional_controls_not_applicable(self):
        assessment = _assess("../../examples/sample-vibe-project")
        for c in assessment.controls:
            self.assertEqual(c.status, STATUS_NOT_APPLICABLE, msg=f"{c.control_id} was {c.status}")

    def test_not_applicable_controls_carry_no_evidence(self):
        assessment = _assess("../../examples/sample-vibe-project")
        for c in assessment.controls:
            self.assertEqual(c.evidence, [])


class TestDocumentationFixture(unittest.TestCase):
    def setUp(self):
        self.assessment = _assess("controls-docs")

    def test_ai_inventory_detected_from_docs(self):
        c01 = _control(self.assessment, "C01")
        self.assertEqual(c01.status, STATUS_DETECTED)
        self.assertTrue(any("README.md" in e.description for e in c01.evidence))

    def test_threat_model_detected_from_docs(self):
        c02 = _control(self.assessment, "C02")
        self.assertEqual(c02.status, STATUS_DETECTED)


class TestFalsePositiveProtection(unittest.TestCase):
    def test_generic_logger_does_not_prove_auditability(self):
        assessment = _assess("controls-generic-noise")
        self.assertEqual(_control(assessment, "C07").status, STATUS_NOT_DETECTED)

    def test_generic_validate_name_does_not_prove_input_security(self):
        assessment = _assess("controls-generic-noise")
        self.assertEqual(_control(assessment, "C03").status, STATUS_NOT_DETECTED)

    def test_env_var_alone_never_reaches_high_confidence(self):
        # env-based secret evidence is real evidence, but never overclaimed as
        # high confidence — that would imply certainty about a real vault/secret
        # manager, which env vars alone don't demonstrate.
        assessment = _assess("basic-chatbot")
        c08 = _control(assessment, "C08")
        if c08.status == STATUS_DETECTED:
            self.assertEqual(c08.confidence, "moderate")

    def test_tool_definition_alone_does_not_prove_authorization(self):
        assessment = _assess("agent-with-tools")
        self.assertEqual(_control(assessment, "C05").status, STATUS_NOT_DETECTED)

    def test_prompt_alone_does_not_prove_prompt_security(self):
        assessment = _assess("basic-chatbot")
        self.assertEqual(_control(assessment, "C03").status, STATUS_NOT_DETECTED)

    def test_rag_pipeline_alone_does_not_prove_retrieval_security(self):
        assessment = _assess("rag-app")
        self.assertEqual(_control(assessment, "C09").status, STATUS_NOT_DETECTED)

    def test_mcp_config_alone_does_not_prove_governance(self):
        assessment = _assess("mcp-server")
        self.assertEqual(_control(assessment, "C10").status, STATUS_NOT_DETECTED)


class TestEvidenceRule(unittest.TestCase):
    def test_no_evidence_is_manufactured_for_not_detected(self):
        assessment = _assess("rag-app")
        c09 = _control(assessment, "C09")
        self.assertEqual(c09.status, STATUS_NOT_DETECTED)
        self.assertEqual(c09.evidence, [])

    def test_detected_controls_always_carry_evidence(self):
        assessment = _assess("controls-well-controlled")
        for c in assessment.controls:
            if c.status in (STATUS_DETECTED, STATUS_PARTIAL):
                self.assertTrue(c.evidence, msg=f"{c.control_id} is {c.status} with no evidence")


class TestTraceability(unittest.TestCase):
    def test_finding_evidence_ids_are_real(self):
        discovery = discover_ai(FIXTURES / "controls-well-controlled")
        assessment = _assess("controls-well-controlled")
        finding_ids = {f.id for f in discovery.findings}
        for c in assessment.controls:
            for fid in c.related_finding_ids:
                self.assertIn(fid, finding_ids)


class TestConfidenceFiltering(unittest.TestCase):
    """Regression for the C05/C06/C07/C12 confidence-blindness bug: a single
    'low'-confidence finding (ai_discovery.py's own comment/string-literal
    downgrade) must not, by itself, drive a control to NOT_DETECTED/PARTIAL/
    DETECTED. Live repro was aegis-provenance's attribution.ts:367, a comment
    reading "a single exec() would only see the first..." — reproduced here
    with a minimal fixture of the same shape."""

    def test_real_high_confidence_tool_surface_still_not_detected(self):
        # TP: agent-with-tools has a genuine @tool decorator and a real
        # subprocess.run(..., shell=True) call — both high confidence. The
        # confidence filter must not neuter this real detection: C05/C06/C12
        # must still correctly report NOT_DETECTED (no auth/approval/
        # sandboxing evidence found near a real tool-invocation surface).
        assessment = _assess("agent-with-tools")
        for control_id in ("C05", "C06", "C12"):
            self.assertEqual(_control(assessment, control_id).status, STATUS_NOT_DETECTED, msg=control_id)

    def test_real_high_confidence_tool_surface_with_auth_still_detected(self):
        # TP: controls-tool-with-auth has the same high-confidence tool
        # surface plus real authorization evidence — must still be DETECTED.
        assessment = _assess("controls-tool-with-auth")
        self.assertEqual(_control(assessment, "C05").status, STATUS_DETECTED)
        self.assertEqual(_control(assessment, "C12").status, STATUS_DETECTED)

    def test_comment_only_exec_does_not_drive_c05_not_detected(self):
        # FP-regression: the ONLY tool_agent-shaped evidence in this fixture
        # is "exec()" inside a `//` comment, which ai_discovery.py already
        # downgrades to "low" confidence. Before the fix, controls.py ignored
        # confidence and still called this NOT_DETECTED, generating a P1
        # tool-authorization remediation for a surface that doesn't exist.
        assessment = _assess("controls-low-confidence-comment-only")
        c05 = _control(assessment, "C05")
        self.assertEqual(c05.status, STATUS_NOT_APPLICABLE)
        self.assertIn("low-confidence", c05.rationale)

    def test_comment_only_exec_does_not_drive_c06_c07_c12_not_detected(self):
        assessment = _assess("controls-low-confidence-comment-only")
        for control_id in ("C06", "C07", "C12"):
            control = _control(assessment, control_id)
            self.assertEqual(control.status, STATUS_NOT_APPLICABLE, msg=control_id)
            self.assertIn("low-confidence", control.rationale, msg=control_id)

    def test_low_confidence_finding_still_traceable(self):
        # Low-confidence findings are still real findings — they must still
        # appear in discovery output, just not drive a control verdict.
        discovery = discover_ai(FIXTURES / "controls-low-confidence-comment-only")
        low_conf = [f for f in discovery.findings if f.confidence == "low"]
        self.assertTrue(low_conf)

    def test_na_rationale_distinguishes_low_confidence_from_nothing_found(self):
        # An N/A driven by low-confidence-only evidence must read differently
        # from an N/A driven by no evidence at all (e.g. basic-chatbot, which
        # has no tool_agent/mcp findings whatsoever).
        low_conf_assessment = _assess("controls-low-confidence-comment-only")
        nothing_assessment = _assess("basic-chatbot")
        low_conf_rationale = _control(low_conf_assessment, "C05").rationale
        nothing_rationale = _control(nothing_assessment, "C05").rationale
        self.assertEqual(_control(nothing_assessment, "C05").status, STATUS_NOT_APPLICABLE)
        self.assertNotEqual(low_conf_rationale, nothing_rationale)


class TestCustomEnvSecretDetection(unittest.TestCase):
    """Regression for C08 only recognizing a fixed provider-name allowlist.
    Live repro was aegis-provenance reading AEGIS_EVAL_API_KEY via
    process.env — a real, correct secret-handling pattern the fixed
    provider-name list and the bare 'API_KEY' pattern both missed."""

    def test_custom_named_env_secret_detected(self):
        assessment = _assess("controls-custom-env-secret")
        c08 = _control(assessment, "C08")
        self.assertEqual(c08.status, STATUS_DETECTED)

    def test_custom_named_env_secret_traceable_to_finding(self):
        discovery = discover_ai(FIXTURES / "controls-custom-env-secret")
        names = {f.name for f in discovery.findings if f.category == "secret_config"}
        self.assertIn("Env-based credential reference", names)


class TestAllTwelveControlsPresent(unittest.TestCase):
    def test_twelve_controls_returned(self):
        assessment = _assess("basic-chatbot")
        ids = {c.control_id for c in assessment.controls}
        expected = {f"C{i:02d}" for i in range(1, 13)}
        self.assertEqual(ids, expected)


class TestDeterminism(unittest.TestCase):
    def test_same_input_produces_identical_assessment(self):
        a1 = _assess("basic-chatbot")
        a2 = _assess("basic-chatbot")
        self.assertEqual([c.to_dict() for c in a1.controls], [c.to_dict() for c in a2.controls])

    def test_controls_sorted_by_id(self):
        assessment = _assess("basic-chatbot")
        ids = [c.control_id for c in assessment.controls]
        self.assertEqual(ids, sorted(ids))


if __name__ == "__main__":
    unittest.main()
