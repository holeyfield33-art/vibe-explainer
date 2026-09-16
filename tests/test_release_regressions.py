import json
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from vibe_explainer import ai_discovery
from vibe_explainer.ai_discovery import discover_ai
from vibe_explainer.attack_surface import build_attack_surface
from vibe_explainer.cli import _git_provenance
from vibe_explainer.controls import assess_controls
from vibe_explainer.dataflow import build_dataflow
from vibe_explainer.readiness import assess_readiness
from vibe_explainer.risk import assess_risks
from vibe_explainer.security_report import build_report

ROOT = Path(__file__).parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
RELEASE_FIXTURES = ROOT / "tests" / "release_fixtures"


def _report(path: Path):
    discovery = discover_ai(path)
    surface = build_attack_surface(discovery)
    flow = build_dataflow(discovery)
    controls = assess_controls(discovery, surface, flow)
    risks = assess_risks(discovery, surface, flow, controls)
    readiness = assess_readiness(discovery, surface, flow, controls, risks)
    return discovery, build_report(discovery, surface, flow, controls, risks, readiness)


class TestReleaseFixtures(unittest.TestCase):
    def test_core_fixture_semantics(self):
        cases = {
            ROOT / "examples" / "sample-vibe-project": set(),
            FIXTURES / "basic-chatbot": {"model_provider", "ai_usage", "prompt_surface"},
            FIXTURES / "rag-app": {"rag_retrieval"},
            FIXTURES / "agent-with-tools": {"tool_agent"},
            FIXTURES / "mcp-server": {"mcp"},
        }
        for path, expected in cases.items():
            with self.subTest(path=path.name):
                discovery, report = _report(path)
                categories = {finding.category for finding in discovery.conclusion_findings()}
                self.assertTrue(expected.issubset(categories))
                self.assertEqual(report.metadata["schema_version"], "2.0")
                self.assertNotIn("highest_risk_severity", report.executive_summary)
                self.assertNotIn("readiness_level", report.executive_summary)

    def test_mixed_context_fixture(self):
        discovery, _report_object = _report(RELEASE_FIXTURES / "mixed_context")
        contexts = {finding.context for finding in discovery.conclusion_findings()}
        self.assertTrue({"PRODUCTION", "TEST", "EXAMPLE"}.issubset(contexts))

    def test_partial_scan_is_explicit(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "large.py").write_text("from openai import OpenAI\n" * 10, encoding="utf-8")
            with unittest.mock.patch.object(ai_discovery, "MAX_FILE_BYTES", 10):
                _discovery, report = _report(Path(root))
            self.assertEqual(report.metadata["assessment_completeness"], "PARTIAL")

    def test_hostile_symlink_is_never_followed_when_supported(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outside:
            secret = Path(outside) / "secret.py"
            secret.write_text("from openai import OpenAI\n", encoding="utf-8")
            try:
                (Path(root) / "linked.py").symlink_to(secret)
            except OSError:
                self.skipTest("symlink creation is unavailable")
            discovery = discover_ai(root)
            self.assertEqual(discovery.findings, [])
            self.assertEqual(discovery.files_unreadable, 1)


class TestReleaseOutputAndProvenance(unittest.TestCase):
    def _run(self, *args: str):
        return subprocess.run(
            [sys.executable, "-m", "vibe_explainer", *args], cwd=ROOT,
            capture_output=True, text=True, check=False,
        )

    def test_product_boundary_checker(self):
        result = subprocess.run(
            [sys.executable, "scripts/check_product_boundary.py"], cwd=ROOT,
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_default_terminal_json_and_markdown_have_no_awards(self):
        fixture = str(FIXTURES / "basic-chatbot")
        terminal = self._run(fixture)
        json_result = self._run(fixture, "--json")
        markdown = self._run(fixture, "--report")
        self.assertEqual((terminal.returncode, json_result.returncode, markdown.returncode), (0, 0, 0))
        payload = json.loads(json_result.stdout)
        self.assertFalse(payload["metadata"]["experimental_scoring_enabled"])
        self.assertNotIn("highest_risk_severity", payload["executive_summary"])
        self.assertNotIn("readiness_level", payload["executive_summary"])
        self.assertTrue(all("priority" not in item for item in payload["recommendations"]))
        for output in (terminal.stdout, markdown.stdout):
            self.assertNotIn("Risk score:", output)
            self.assertNotIn("Readiness Level", output)
            self.assertNotRegex(output, r"(?m)^P[012]\s")
        self.assertIn("ANALYST REVIEW ACTIONS", terminal.stdout)
        self.assertIn("## Analyst Review Actions", markdown.stdout)

    def test_regenerated_golden_report_matches_current_product_boundary(self):
        golden = (
            ROOT / "examples" / "sample-assessment" / "synthetic-ai-review.md"
        ).read_text(encoding="utf-8")
        self.assertIn("## Analyst Review Actions", golden)
        self.assertNotIn("## Top Remediations", golden)
        self.assertNotRegex(golden, r"(?m)^### P[012]\b")
        self.assertIn("If model output is consumed", golden)
        self.assertNotIn("**Score:**", golden)
        self.assertIn("**Repository revision available:** true", golden)
        self.assertIn("**Repository commit:**", golden)
        self.assertIn("**Repository dirty state:** False", golden)
        self.assertIn("## Limitations", golden)

    def test_manifest_is_derived_and_complete(self):
        result = self._run(str(FIXTURES / "basic-chatbot"), "--json")
        manifest = json.loads(result.stdout)["assessment_manifest"]
        self.assertEqual(manifest["engine"], "vibe-explainer")
        self.assertEqual(manifest["engine_version"], "0.2.0a1")
        self.assertEqual(manifest["schema_version"], "2.0")
        self.assertIn("repository_revision", manifest)
        self.assertIn("scan_configuration", manifest)
        self.assertEqual(manifest["asi_catalog"]["supplied"], False)

    def test_git_provenance_clean_dirty_and_non_git(self):
        with tempfile.TemporaryDirectory() as root:
            repo = Path(root)
            subprocess.run(["git", "init", "-b", "main"], cwd=repo, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
            (repo / "tracked.txt").write_text("clean", encoding="utf-8")
            subprocess.run(["git", "add", "tracked.txt"], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-m", "fixture"], cwd=repo, check=True, capture_output=True)
            clean = _git_provenance(repo)
            self.assertTrue(clean["available"])
            self.assertFalse(clean["dirty"])
            self.assertEqual(clean["branch"], "main")
            (repo / "tracked.txt").write_text("dirty", encoding="utf-8")
            self.assertTrue(_git_provenance(repo)["dirty"])
        with tempfile.TemporaryDirectory() as root:
            self.assertEqual(_git_provenance(Path(root)), {
                "commit": None, "branch": None, "dirty": None, "available": False,
            })


if __name__ == "__main__":
    unittest.main()
