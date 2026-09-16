import tempfile
import unittest
import re
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path

from vibe_explainer import __version__
from vibe_explainer.ai_discovery import discover_ai
from vibe_explainer.output import OutputExistsError, atomic_write_text
from vibe_explainer.readiness import _ProcessEvidence, _process_evidence_refs


class TestAtomicOutput(unittest.TestCase):
    def test_existing_output_is_preserved_without_force(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.json"
            path.write_text("customer-owned", encoding="utf-8")
            with self.assertRaises(OutputExistsError):
                atomic_write_text(path, "replacement")
            self.assertEqual(path.read_text(encoding="utf-8"), "customer-owned")
            self.assertEqual(list(path.parent.glob(".report.json.*.tmp")), [])

    def test_force_atomically_replaces_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nested" / "report.md"
            atomic_write_text(path, "first")
            atomic_write_text(path, "second", overwrite=True)
            self.assertEqual(path.read_text(encoding="utf-8"), "second")


class TestEvidenceIdentity(unittest.TestCase):
    def test_unrelated_line_insertion_does_not_change_finding_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.py"
            source = "from openai import OpenAI\nclient = OpenAI()\nclient.responses.create(input='hi')\n"
            path.write_text(source, encoding="utf-8")
            before = [(f.category, f.name, f.id) for f in discover_ai(tmp).findings]
            path.write_text("# unrelated heading\n\n" + source, encoding="utf-8")
            after = [(f.category, f.name, f.id) for f in discover_ai(tmp).findings]
            self.assertEqual(before, after)

    def test_distinct_process_signals_in_one_path_have_distinct_ids(self):
        signals = [
            _ProcessEvidence("security_tests", "tests/security/test_ai.py", "high", "asserts auth"),
            _ProcessEvidence("security_tests", "tests/security/test_ai.py", "high", "asserts isolation"),
        ]
        refs = _process_evidence_refs(signals)
        self.assertEqual(len({ref.id for ref in refs}), 2)


class TestVersionSource(unittest.TestCase):
    def test_version_is_defined_once_for_dynamic_packaging(self):
        pyproject = (Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('dynamic = ["version"]', pyproject)
        self.assertIn('version = {attr = "vibe_explainer.__version__"}', pyproject)
        self.assertRegex(__version__, r"^\d+\.\d+\.\d+(?:a\d+|b\d+|rc\d+)?$")

    def test_license_metadata_matches_repository_license(self):
        root = Path(__file__).parents[1]
        metadata = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
        license_text = (root / "LICENSE").read_text(encoding="utf-8")
        readme = (root / "README.md").read_text(encoding="utf-8")
        self.assertEqual(metadata["project"]["license"], "Apache-2.0")
        self.assertIn("Apache License", license_text)
        self.assertIn("Version 2.0", license_text)
        self.assertIn("Apache-2.0", readme)


class TestBuiltArtifacts(unittest.TestCase):
    def test_wheel_and_sdist_metadata_and_contents(self):
        root = Path(__file__).parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(
                [sys.executable, "-m", "build", "--no-isolation", "--outdir", tmp],
                cwd=root, check=True, capture_output=True, text=True,
            )
            wheel = next(Path(tmp).glob("*.whl"))
            sdist = next(Path(tmp).glob("*.tar.gz"))
            with zipfile.ZipFile(wheel) as archive:
                wheel_names = archive.namelist()
                metadata_name = next(name for name in wheel_names if name.endswith(".dist-info/METADATA"))
                wheel_metadata = archive.read(metadata_name).decode("utf-8")
            with tarfile.open(sdist, "r:gz") as archive:
                sdist_names = archive.getnames()
            self.assertIn("Version: 0.2.0a1", wheel_metadata)
            self.assertIn("License-Expression: Apache-2.0", wheel_metadata)
            for name in wheel_names + sdist_names:
                normalized = name.lower().replace("\\", "/")
                self.assertNotRegex(normalized, r"(^|/)(\.git|\.env|\.venv|venv|htmlcov)(/|$)")
                self.assertNotRegex(normalized, r"(^|/)\.coverage$")
                self.assertNotIn("aletheia-core-assessment", normalized)


if __name__ == "__main__":
    unittest.main()
