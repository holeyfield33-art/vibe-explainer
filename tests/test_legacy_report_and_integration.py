import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vibe_explainer.cli import _run_security_mode, build_parser, main
from vibe_explainer.integrate_vibe_check import load_vibe_check_report, summarize_vibe_findings
from vibe_explainer.report import _architecture_mermaid, _stack_guess, _start_here, render_markdown
from vibe_explainer.scanner import FileInfo, ScanResult


REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "tests" / "fixtures"
SAMPLE = REPO_ROOT / "examples" / "sample-vibe-project"


def _scan(**overrides):
    values = {
        "root": "/tmp/example",
        "files": [],
        "entry_points": ["app.py"],
        "manifests": ["pyproject.toml"],
        "top_dirs": [("src", 2)],
        "by_ext": {".py": 2},
        "largest_files": [FileInfo("src/core.py", 100, 900, ".py")],
        "readme_paths": ["README.md"],
        "total_code_files": 2,
        "total_lines": 950,
    }
    values.update(overrides)
    return ScanResult(**values)


class TestLegacyReportBranches(unittest.TestCase):
    def test_stack_guesses_cover_supported_and_fallback_shapes(self):
        self.assertEqual(_stack_guess(_scan(by_ext={".py": 1})), "Python")
        combined = _stack_guess(_scan(by_ext={".js": 1, ".go": 1, ".rs": 1}))
        self.assertIn("JavaScript/TypeScript", combined)
        self.assertIn("Go", combined)
        self.assertIn("Rust", combined)
        self.assertEqual(_stack_guess(_scan(by_ext={})), "mixed / other")

    def test_start_here_deduplicates_and_skips_test_weight(self):
        scan = _scan(
            readme_paths=["README.md", "README.md"],
            entry_points=["app.py", "app.py"],
            largest_files=[
                FileInfo("tests/test_big.py", 1, 2000, ".py"),
                FileInfo("src/core.py", 1, 1200, ".py"),
            ],
        )
        paths = [path for path, _ in _start_here(scan)]
        self.assertEqual(paths.count("README.md"), 1)
        self.assertNotIn("tests/test_big.py", paths)
        self.assertIn("src/core.py", paths)

    def test_architecture_and_full_report_variants(self):
        scan = _scan(top_dirs=[('src"quoted', 2)])
        diagram = _architecture_mermaid(scan)
        self.assertIn("flowchart TD", diagram)
        self.assertIn("src'quoted", diagram)

        report = render_markdown(scan, vibe_notes=["one issue"], offline=False)
        self.assertIn("LLM-assisted", report)
        self.assertIn("one issue", report)
        self.assertIn("Large file", report)

        empty = render_markdown(
            _scan(
                root="/",
                entry_points=[], manifests=[], top_dirs=[], by_ext={},
                largest_files=[], readme_paths=[], total_code_files=0, total_lines=0,
            )
        )
        self.assertIn("No obvious conventional entry points", empty)
        self.assertIn("No strong start-here candidates", empty)
        self.assertIn("No vibe-check report supplied", empty)


class TestVibeCheckIntegration(unittest.TestCase):
    def test_loader_handles_missing_invalid_nonobject_and_valid(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.assertIsNone(load_vibe_check_report(root / "missing.json"))
            invalid = root / "invalid.json"
            invalid.write_text("{")
            self.assertIsNone(load_vibe_check_report(invalid))
            array = root / "array.json"
            array.write_text("[]")
            self.assertIsNone(load_vibe_check_report(array))
            valid = root / "valid.json"
            valid.write_text('{"summary": {"stubs": 2}}')
            self.assertEqual(load_vibe_check_report(valid)["summary"]["stubs"], 2)

    def test_summary_covers_disposition_and_all_positive_counters(self):
        summary = {
            key: index + 1
            for index, key in enumerate((
                "syntax_errors", "package_risks", "duplicate_blocks", "stubs",
                "unreferenced_definitions", "giant_files", "circular_imports",
                "comment_buzzwords",
            ))
        }
        notes = summarize_vibe_findings({
            "summary": summary,
            "triage": {"disposition": "REVIEW"},
        })
        self.assertEqual(len(notes), 9)
        self.assertIn("REVIEW", notes[0])
        self.assertEqual(summarize_vibe_findings({"triage": "invalid"}), [])


class TestCLIInProcess(unittest.TestCase):
    def test_parser_and_default_main_stdout(self):
        self.assertEqual(build_parser().prog, "vibe-explainer")
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = main([str(SAMPLE), "--offline"])
        self.assertEqual(code, 0)
        self.assertIn("Mental model", stdout.getvalue())

    def test_default_main_output_file_and_vibe_report_paths(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            out = Path(temp_dir) / "report.md"
            vibe = Path(temp_dir) / "vibe.json"
            vibe.write_text(json.dumps({"disposition": {"disposition": "REVIEW"}}))
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                code = main([str(SAMPLE), "--vibe-check-report", str(vibe), "--out", str(out)])
            self.assertEqual(code, 0)
            self.assertIn("REVIEW", out.read_text())
            self.assertIn("Wrote", stderr.getvalue())

            warning = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(warning):
                self.assertEqual(main([str(SAMPLE), "--vibe-check-report", str(Path(temp_dir) / "missing")]), 0)
            self.assertIn("warning", warning.getvalue())

    def test_bad_path_and_default_scan_error(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.assertEqual(main(["/definitely/missing"]), 2)
        self.assertIn("not a directory", stderr.getvalue())

        with patch("vibe_explainer.cli.scan_repo", side_effect=RuntimeError("boom")):
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(main([str(SAMPLE)]), 1)
        self.assertIn("scan failed", stderr.getvalue())

    def test_security_modes_and_error_boundary_in_process(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(_run_security_mode(FIXTURES / "agent-with-tools", True, False, None), 0)
        self.assertIn('"executive_summary"', stdout.getvalue())

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(_run_security_mode(FIXTURES / "agent-with-tools", False, True, None), 0)
        self.assertIn("# AI Security Readiness Assessment", stdout.getvalue())

        with tempfile.TemporaryDirectory() as temp_dir:
            out = Path(temp_dir) / "security.txt"
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(_run_security_mode(FIXTURES / "agent-with-tools", False, False, str(out)), 0)
            self.assertIn("AI SECURITY ASSESSMENT", out.read_text())

        with patch("vibe_explainer.ai_discovery.discover_ai", side_effect=RuntimeError("boom")):
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(_run_security_mode(FIXTURES / "agent-with-tools", False, False, None), 1)
        self.assertIn("Unable to analyze", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
