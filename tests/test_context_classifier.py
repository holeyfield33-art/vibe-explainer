import unittest
from pathlib import Path

from vibe_explainer.ai_discovery import discover_ai
from vibe_explainer.attack_surface import build_attack_surface
from vibe_explainer.context_classifier import (
    CONTEXT_DOCUMENTATION,
    CONTEXT_EXAMPLE,
    CONTEXT_GENERATED,
    CONTEXT_PRODUCTION,
    CONTEXT_TEST,
    classify_path,
    is_production,
)
from vibe_explainer.controls import assess_controls
from vibe_explainer.dataflow import build_dataflow
from vibe_explainer.readiness import assess_readiness
from vibe_explainer.risk import assess_risks
from vibe_explainer.security_report import build_report

FIXTURES = Path(__file__).resolve().parent / "fixtures"


class TestContextClassifier(unittest.TestCase):
    def test_production_is_default(self):
        self.assertEqual(classify_path("core/model_loader.py"), CONTEXT_PRODUCTION)
        self.assertEqual(classify_path("app/api/webhooks/stripe/route.ts"), CONTEXT_PRODUCTION)
        self.assertEqual(classify_path("middleware.ts"), CONTEXT_PRODUCTION)

    def test_tests_detected(self):
        for p in ("tests/test_agent.py", "src/__tests__/foo.js", "foo_test.go", "bar.spec.ts", "component.test.tsx"):
            self.assertEqual(classify_path(p), CONTEXT_TEST, msg=p)

    def test_examples_and_demos_detected(self):
        for p in ("examples/chatbot.py", "demo/app.py", "scripts/demo_layer_comparison.py", "samples/x.py", "fixtures/data.py"):
            self.assertEqual(classify_path(p), CONTEXT_EXAMPLE, msg=p)

    def test_documentation_detected(self):
        for p in ("docs/guide.md", "README.md", "notes.rst", "CHANGELOG.txt"):
            self.assertEqual(classify_path(p), CONTEXT_DOCUMENTATION, msg=p)

    def test_generated_detected(self):
        for p in ("data/semantic_manifest.json", "graph-ts.json", "package-lock.json", "dist/bundle.js", "charts/x/values.yaml", "node_modules/foo/index.js"):
            self.assertEqual(classify_path(p), CONTEXT_GENERATED, msg=p)

    def test_windows_paths_normalized(self):
        self.assertEqual(classify_path("tests\\test_x.py"), CONTEXT_TEST)

    def test_is_production_helper(self):
        self.assertTrue(is_production("core/exporters.py"))
        self.assertFalse(is_production("tests/test_exporters.py"))

    def test_aletheia_real_paths_separated(self):
        # the exact noise problem from the first real-world run: production
        # webhook/embeddings/qdrant must stay production; the 30 test/manifest/
        # helm matches must not.
        self.assertEqual(classify_path("core/exporters.py"), CONTEXT_PRODUCTION)
        self.assertEqual(classify_path("core/vector_store.py"), CONTEXT_PRODUCTION)
        self.assertEqual(classify_path("tests/test_observability.py"), CONTEXT_TEST)
        self.assertEqual(classify_path("data/semantic_manifest.json"), CONTEXT_GENERATED)
        self.assertEqual(classify_path("charts/aletheia-core/templates/deployment.yaml"), CONTEXT_GENERATED)


class TestContextInReport(unittest.TestCase):
    def _report(self, fixture):
        d = discover_ai(FIXTURES / fixture)
        s = build_attack_surface(d)
        g = build_dataflow(d)
        c = assess_controls(d, s, g)
        r = assess_risks(d, s, g, c)
        ready = assess_readiness(d, s, g, c, r)
        return build_report(d, s, g, c, r, ready)

    def test_executive_summary_has_context_breakdown(self):
        report = self._report("agent-with-tools")
        es = report.executive_summary
        self.assertIn("total_findings", es)
        self.assertIn("production_findings", es)
        self.assertIn("findings_by_context", es)
        self.assertLessEqual(es["production_findings"], es["total_findings"])

    def test_attack_surface_items_carry_context(self):
        report = self._report("agent-with-tools")
        for bucket_items in report.attack_surface.values():
            for item in bucket_items:
                self.assertIn("context", item)
                self.assertIn(item["context"], (CONTEXT_PRODUCTION, CONTEXT_TEST, CONTEXT_EXAMPLE, CONTEXT_DOCUMENTATION, CONTEXT_GENERATED))

    def test_inventory_findings_carry_context(self):
        report = self._report("basic-chatbot")
        for findings in report.ai_inventory["categories"].values():
            for f in findings:
                self.assertIn("context", f)

    def test_fixture_findings_classified_relative_to_scan_root(self):
        # Discovery paths are relative to the scanned root, so when the scan root
        # IS the fixture dir, agent.py has no tests/ prefix and reads as PRODUCTION.
        # This is correct: the classifier classifies what the scanner sees. The
        # context layer's value shows on real repos scanned from their root, where
        # tests/ and data/ prefixes are present (see TestContextClassifier).
        report = self._report("agent-with-tools")
        es = report.executive_summary
        self.assertEqual(es["total_findings"], es["production_findings"])


if __name__ == "__main__":
    unittest.main()
