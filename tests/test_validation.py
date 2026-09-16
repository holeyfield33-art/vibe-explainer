import json
import tempfile
import unittest
from pathlib import Path

from vibe_explainer.validation import DEFAULT_CORPUS, evaluate_corpus, main


class TestValidationCorpus(unittest.TestCase):
    def test_checked_in_corpus_reproduces_dispositions(self):
        report = evaluate_corpus()
        self.assertGreaterEqual(report["overall"]["precision"], 0.9)
        self.assertGreaterEqual(report["by_language"]["python"]["precision"], 0.9)
        obfuscation = next(case for case in report["cases"] if case["id"] == "py_obfuscated_import")
        self.assertFalse(obfuscation["passed"])
        self.assertIn("python", report["by_language"])
        self.assertIn("unsupported_language", report["by_construct"])

    def test_check_command_and_output_are_offline_and_deterministic(self):
        with tempfile.TemporaryDirectory() as root:
            output = Path(root) / "metrics.json"
            self.assertEqual(main(["--corpus", str(DEFAULT_CORPUS), "--output", str(output), "--check"]), 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload, evaluate_corpus())


if __name__ == "__main__":
    unittest.main()
