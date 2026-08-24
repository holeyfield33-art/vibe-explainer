import unittest
from pathlib import Path

from vibe_explainer.scanner import scan_repo

SAMPLE = Path(__file__).resolve().parents[1] / "examples" / "sample-vibe-project"


class TestScanner(unittest.TestCase):
    def test_sample_project_scan(self):
        result = scan_repo(SAMPLE)
        self.assertGreater(result.total_code_files, 0)
        self.assertTrue(any("app.py" in p for p in result.entry_points))
        self.assertTrue(any("requirements.txt" in p for p in result.manifests))
        self.assertGreater(result.total_lines, 10)

    def test_to_dict(self):
        result = scan_repo(SAMPLE)
        d = result.to_dict()
        self.assertIn("entry_points", d)
        self.assertIn("total_code_files", d)


if __name__ == "__main__":
    unittest.main()
