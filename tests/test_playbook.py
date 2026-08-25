import unittest
from pathlib import Path

from vibe_explainer import playbook as pb
from vibe_explainer.ai_discovery import discover_ai
from vibe_explainer.attack_surface import build_attack_surface
from vibe_explainer.consultant_report import render_consultant_markdown
from vibe_explainer.controls import assess_controls
from vibe_explainer.dataflow import build_dataflow
from vibe_explainer.readiness import assess_readiness
from vibe_explainer.risk import assess_risks
from vibe_explainer.security_report import build_report

FIXTURES = Path(__file__).resolve().parent / "fixtures"


class TestPlaybookMapping(unittest.TestCase):
    def test_band_for_score_matches_playbook_table(self):
        self.assertEqual(pb.band_for_score(6), ("Low", 1))
        self.assertEqual(pb.band_for_score(7), ("Low", 1))
        self.assertEqual(pb.band_for_score(8), ("Moderate", 2))
        self.assertEqual(pb.band_for_score(14), ("Moderate", 2))
        self.assertEqual(pb.band_for_score(15), ("High", 3))
        self.assertEqual(pb.band_for_score(19), ("High", 3))
        self.assertEqual(pb.band_for_score(20), ("Critical", 4))
        self.assertEqual(pb.band_for_score(25), ("Critical", 4))

    def test_level_names_match_playbook(self):
        self.assertEqual(pb.level_meta(1)["name"], "Baseline")
        self.assertEqual(pb.level_meta(2)["name"], "Managed")
        self.assertEqual(pb.level_meta(3)["name"], "Hardened")
        self.assertEqual(pb.level_meta(4)["name"], "Continuous")

    def test_control_classes(self):
        self.assertEqual(pb.control_class("C02"), "G")   # threat model -> governance
        self.assertEqual(pb.control_class("C12"), "V")   # adversarial testing -> validation
        self.assertEqual(pb.control_class("C08"), "P")   # secret management -> preventive

    def test_no_ai_level_meta_graceful(self):
        meta = pb.level_meta(None)
        self.assertEqual(meta["name"], "No AI surface")


class TestConsultantReportPlaybookVocabulary(unittest.TestCase):
    def _md(self, fixture):
        d = discover_ai(FIXTURES / fixture)
        s = build_attack_surface(d)
        g = build_dataflow(d)
        c = assess_controls(d, s, g)
        r = assess_risks(d, s, g, c)
        ready = assess_readiness(d, s, g, c, r)
        return render_consultant_markdown(build_report(d, s, g, c, r, ready), assessment_date="2026-01-01")

    def test_cites_framework_by_name(self):
        md = self._md("agent-with-tools")
        self.assertIn("Security for AI: Readiness and Risk Playbook", md)

    def test_shows_risk_formula(self):
        md = self._md("agent-with-tools")
        self.assertIn("ROUND(((Exposure + Safety + Security) / 3) * Likelihood)", md)

    def test_shows_band_table(self):
        md = self._md("agent-with-tools")
        self.assertIn("Playbook readiness", md)
        self.assertIn("Level 3: Hardened", md)

    def test_shows_control_class_tags(self):
        md = self._md("agent-with-tools")
        self.assertTrue(any(tag in md for tag in ("[P]", "[V]", "[G]")))

    def test_shows_level_goal(self):
        md = self._md("agent-with-tools")
        self.assertIn("Level goal (playbook)", md)

    def test_factor_breakdown_present_when_risks_exist(self):
        # agent-with-tools yields real risk scenarios with factor inputs
        md = self._md("agent-with-tools")
        self.assertIn("Risk factors (playbook)", md)


if __name__ == "__main__":
    unittest.main()
