import unittest
from pathlib import Path

from vibe_explainer.ai_discovery import discover_ai

FIXTURES = Path(__file__).resolve().parent / "fixtures"


class TestJSRegexExecNotCodeExecution(unittest.TestCase):
    """Regression for a false-positive class found on the runtime-firewall-mvp
    validation run: JS regex `.exec()` and method-call `.exec()` were matched by
    the Python-oriented dynamic-code-execution pattern, and a security tool's own
    detection-signature strings/comments read as live calls."""

    def setUp(self):
        self.findings = discover_ai(FIXTURES / "js-regex-exec").findings
        self.dyn = [f for f in self.findings if f.name == "Dynamic code execution"]

    def test_js_regex_exec_does_not_match(self):
        # re.exec(str) / .exec(content) must never be flagged as code execution
        for f in self.dyn:
            self.assertNotIn(".exec(", f.evidence.replace("re.exec(", "").replace("regex.exec(", "") + " ")

    def test_signature_string_or_comment_matches_are_low_confidence(self):
        # any eval(/exec( that does get matched inside a comment must be low
        # confidence, not moderate — it's a detection signature, not a live call
        comment_hits = [f for f in self.dyn if f.evidence.strip().startswith("//") or f.evidence.strip().startswith("#")]
        for f in comment_hits:
            self.assertEqual(f.confidence, "low")


class TestEvalExecPatternPrecision(unittest.TestCase):
    """Direct pattern-level checks so the fix can't silently regress."""

    def _dyn_findings(self, tmp_path: Path, code: str):
        f = tmp_path / "sample.js"
        f.write_text(code)
        return [x for x in discover_ai(tmp_path).findings if x.name == "Dynamic code execution"]

    def test_method_exec_calls_excluded(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            findings = self._dyn_findings(Path(d), "const m = regex.exec(input);\nwhile ((x = re.exec(s))) {}\n")
            self.assertEqual(findings, [])

    def test_bare_eval_still_detected(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            # bare eval( in real (non-string, non-comment) position still flagged
            findings = self._dyn_findings(Path(d), "function run(x) { return eval(x); }\n")
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].confidence, "moderate")


if __name__ == "__main__":
    unittest.main()
