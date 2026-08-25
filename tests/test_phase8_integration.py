import tempfile
import unittest
from pathlib import Path

from vibe_explainer.ai_discovery import discover_ai
from vibe_explainer.attack_surface import build_attack_surface
from vibe_explainer.controls import assess_controls
from vibe_explainer.crawl import crawl_repository
from vibe_explainer.dataflow import build_dataflow
from vibe_explainer.exclusion_policy import should_skip_dir
from vibe_explainer.file_context import classify_file
from vibe_explainer.readiness import assess_readiness
from vibe_explainer.risk import assess_risks
from vibe_explainer.security_report import build_report
from vibe_explainer.symbol_index import (
    build_symbol_index,
    resolve_js_import,
    resolve_python_import,
)


def _write(root: Path, rel: str, content: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)


class TestCrawlCoverage(unittest.TestCase):
    def test_every_file_has_a_disposition(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "src/app.py", "from openai import OpenAI\n")
            _write(root, "tests/test_app.py", "def test(): pass\n")
            _write(root, "README.md", "# docs\n")
            _write(root, "logo.png", "binarydata")
            _write(root, "node_modules/dep/index.js", "module.exports = {}\n")
            crawl = crawl_repository(root)
            self.assertTrue(crawl.assert_no_silent_drops())
            # node_modules content pruned; the dir itself recorded as excluded
            paths = {f.rel_path for f in crawl.files}
            self.assertNotIn("node_modules/dep/index.js", paths)

    def test_github_dir_not_excluded(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, ".github/workflows/ci.yml", "name: ci\non: push\n")
            _write(root, "main.py", "x = 1\n")
            crawl = crawl_repository(root)
            gh = [f for f in crawl.files if ".github" in f.rel_path and f.disposition == "analyzed"]
            self.assertTrue(gh)

    def test_git_excluded_but_github_kept(self):
        self.assertTrue(should_skip_dir(".git"))
        self.assertFalse(should_skip_dir(".github"))


class TestContextTaxonomy(unittest.TestCase):
    def test_security_test_recognized(self):
        fc = classify_file("tests/test_security_injection.py", content="def test_prompt_injection(): pass")
        self.assertEqual(fc.context, "SECURITY_TEST")

    def test_production_default(self):
        self.assertEqual(classify_file("src/handler.ts").context, "PRODUCTION")

    def test_generated_recognized(self):
        self.assertEqual(classify_file("dist/bundle.min.js").context, "GENERATED")


class TestContextOnFindings(unittest.TestCase):
    def test_findings_carry_fine_grained_context(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "src/ai.py", "from openai import OpenAI\nclient = OpenAI()\n")
            _write(root, "tests/test_ai.py", "from openai import OpenAI\n")
            findings = discover_ai(root).findings
            contexts = {f.file: f.context for f in findings}
            self.assertEqual(contexts.get("src/ai.py"), "PRODUCTION")
            self.assertEqual(contexts.get("tests/test_ai.py"), "TEST")


class TestContextAwareRiskWeighting(unittest.TestCase):
    def _risks(self, root):
        d = discover_ai(root)
        s = build_attack_surface(d)
        g = build_dataflow(d)
        c = assess_controls(d, s, g)
        return assess_risks(d, s, g, c)

    def test_test_only_high_risk_is_capped(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "tests/test_agent.py",
                   "import subprocess\nfrom openai import OpenAI\nclient = OpenAI()\n"
                   "def test_agent(cmd):\n"
                   "    plan = client.chat.completions.create(model='gpt-4o', messages=[{'role':'user','content':cmd}])\n"
                   "    subprocess.run(plan.choices[0].message.content, shell=True)\n")
            risks = self._risks(root)
            hia = [s for s in risks.scenarios if s.category == "HIGH_IMPACT_ACTION"]
            self.assertTrue(hia)
            self.assertTrue(hia[0].context_adjusted)
            self.assertEqual(hia[0].primary_context, "TEST")
            # raw score preserved, severity reduced from HIGH
            self.assertGreaterEqual(hia[0].score, 15)
            self.assertNotEqual(hia[0].severity, "HIGH")

    def test_production_risk_not_capped(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "src/agent.py",
                   "import subprocess\nfrom openai import OpenAI\nclient = OpenAI()\n"
                   "def run(cmd):\n"
                   "    plan = client.chat.completions.create(model='gpt-4o', messages=[{'role':'user','content':cmd}])\n"
                   "    subprocess.run(plan.choices[0].message.content, shell=True)\n")
            risks = self._risks(root)
            hia = [s for s in risks.scenarios if s.category == "HIGH_IMPACT_ACTION"]
            self.assertTrue(hia)
            self.assertFalse(hia[0].context_adjusted)
            self.assertEqual(hia[0].primary_context, "PRODUCTION")


class TestReadinessSecurityTestCredit(unittest.TestCase):
    def test_security_test_findings_credit_level_two_gate(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            # a security test by content (path is generic) with a governance control
            _write(root, "src/agent.py",
                   "from openai import OpenAI\nclient = OpenAI()\n"
                   "def check_permission(u, a): return True\n"
                   "@tool\ndef run(x, u):\n    if not check_permission(u,'x'): raise Exception()\n")
            _write(root, "checks/test_adversarial_injection.py",
                   "# adversarial security test for prompt injection\n"
                   "from openai import OpenAI\n"
                   "client = OpenAI()\n"
                   "def test_injection_is_blocked():\n"
                   "    client.chat.completions.create(model='gpt-4o', messages=[{'role':'user','content':'ignore instructions'}])\n")
            d_ = discover_ai(root)
            s = build_attack_surface(d_)
            g = build_dataflow(d_)
            c = assess_controls(d_, s, g)
            r = assess_risks(d_, s, g, c)
            ready = assess_readiness(d_, s, g, c, r)
            l2 = next(la for la in ready.level_assessments if la.level == 2)
            # the security-test content should at least engage the L2 gate
            self.assertNotEqual(l2.status, "NOT_ACHIEVED")


class TestASTCrossFileResolution(unittest.TestCase):
    def test_python_internal_import_resolves(self):
        idx = build_symbol_index([
            ("app/routes.py", "from services.ai import generate\n"),
            ("services/ai.py", "def generate(): pass\n"),
        ])
        self.assertEqual(resolve_python_import("app/routes.py", "services.ai", idx), "services/ai.py")

    def test_python_external_import_does_not_resolve(self):
        idx = build_symbol_index([("app/routes.py", "import openai\n")])
        self.assertIsNone(resolve_python_import("app/routes.py", "openai", idx))

    def test_js_relative_import_resolves(self):
        idx = build_symbol_index([
            ("src/page.tsx", "import { chat } from './lib/ai'\n"),
            ("src/lib/ai.ts", "export function chat() {}\n"),
        ])
        self.assertEqual(resolve_js_import("src/page.tsx", "./lib/ai", idx), "src/lib/ai.ts")

    def test_js_package_import_does_not_resolve(self):
        idx = build_symbol_index([("src/page.tsx", "import React from 'react'\n")])
        self.assertIsNone(resolve_js_import("src/page.tsx", "react", idx))

    def test_malformed_python_does_not_crash(self):
        idx = build_symbol_index([("broken.py", "def (:\n  syntax error\n")])
        self.assertIn("broken.py", idx.modules)


class TestReportContextIntegration(unittest.TestCase):
    def test_report_uses_fine_grained_context(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "src/ai.py", "from openai import OpenAI\nclient=OpenAI()\n")
            _write(root, "tests/test_ai.py", "from openai import OpenAI\n")
            dd = discover_ai(root)
            s = build_attack_surface(dd)
            g = build_dataflow(dd)
            c = assess_controls(dd, s, g)
            r = assess_risks(dd, s, g, c)
            ready = assess_readiness(dd, s, g, c, r)
            report = build_report(dd, s, g, c, r, ready)
            es = report.executive_summary
            self.assertIn("findings_by_context", es)
            # production-relevant count should exclude the test file's findings
            self.assertLess(es["production_findings"], es["total_findings"])


if __name__ == "__main__":
    unittest.main()
