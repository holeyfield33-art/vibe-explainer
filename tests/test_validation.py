import json
import tempfile
import unittest
from pathlib import Path

from vibe_explainer.validation import DEFAULT_CORPUS, _metrics, evaluate_corpus, main


def _write_corpus(root: str, cases: list[dict]) -> Path:
    path = Path(root) / "corpus.json"
    path.write_text(json.dumps({
        "version": "test",
        "label_review": {"status": "PENDING_INDEPENDENT_REVIEW"},
        "cases": cases,
    }), encoding="utf-8")
    return path


class TestValidationCorpus(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = evaluate_corpus()
        cls.corpus = json.loads(DEFAULT_CORPUS.read_text(encoding="utf-8"))

    def test_metric_gate_is_separate_from_exact_label_gate(self):
        self.assertEqual(main(["--corpus", str(DEFAULT_CORPUS), "--metrics-gate"]), 0)
        self.assertEqual(main(["--corpus", str(DEFAULT_CORPUS), "--check"]), 0)
        self.assertEqual(self.report["known_mismatches"], ["py_obfuscated_import"])

    def test_exact_label_gate_fails_on_mismatch(self):
        with tempfile.TemporaryDirectory() as root:
            corpus = _write_corpus(root, [{
                "id": "mandatory_miss", "language": "python", "construct": "import",
                "path": "app.py", "source": "value = 1\n", "expected": "authoritative",
            }])
            self.assertEqual(main(["--corpus", str(corpus), "--check"]), 1)

    def test_context_case_requires_correct_context(self):
        rows = {row["id"]: row for row in self.report["cases"]}
        for case_id in ("generated_context", "test_context", "example_context"):
            self.assertTrue(rows[case_id]["context_applicable"])
            self.assertTrue(rows[case_id]["context_pass"])
        self.assertEqual(self.report["overall"]["context"]["accuracy"], 1.0)

    def test_generated_context_not_treated_as_production(self):
        case = next(c for c in self.corpus["cases"] if c["id"] == "generated_context")
        self.assertEqual(case["expected_context"], "GENERATED")

    def test_test_context_not_treated_as_production(self):
        case = next(c for c in self.corpus["cases"] if c["id"] == "test_context")
        self.assertEqual(case["expected_context"], "TEST")

    def test_example_context_not_treated_as_production(self):
        case = next(c for c in self.corpus["cases"] if c["id"] == "example_context")
        self.assertEqual(case["expected_context"], "EXAMPLE")

    def test_expected_finding_category_required(self):
        case = next(row for row in self.report["cases"] if row["id"] == "py_mcp_server")
        self.assertTrue(case["finding_identity_applicable"])
        self.assertTrue(case["finding_identity_pass"])

    def test_unrelated_authoritative_finding_does_not_create_false_pass(self):
        with tempfile.TemporaryDirectory() as root:
            corpus = _write_corpus(root, [{
                "id": "wrong_signal", "language": "python", "construct": "identity",
                "path": "app.py", "source": "from openai import OpenAI\n",
                "expected": "authoritative",
                "expected_findings": [{"category": "mcp", "name": "FastMCP server"}],
            }])
            result = evaluate_corpus(corpus)
            self.assertTrue(result["cases"][0]["disposition_pass"])
            self.assertFalse(result["cases"][0]["finding_identity_pass"])
            self.assertEqual(main(["--corpus", str(corpus), "--check"]), 1)

    def test_multi_file_case_requires_expected_relationship(self):
        row = next(row for row in self.report["cases"] if row["id"] == "multi_file_import")
        self.assertTrue(row["relationship_applicable"])
        self.assertTrue(row["relationship_pass"])
        self.assertEqual(self.report["overall"]["relationship"]["accuracy"], 1.0)

    def test_missing_expected_relationship_fails(self):
        with tempfile.TemporaryDirectory() as root:
            corpus = _write_corpus(root, [{
                "id": "missing_edge", "language": "python", "construct": "multi_file",
                "path": "app.py", "source": "from openai import OpenAI\n",
                "expected": "authoritative",
                "expected_relationships": [{"relationship": "feeds_prompt"}],
            }])
            result = evaluate_corpus(corpus)
            self.assertFalse(result["cases"][0]["relationship_pass"])

    def test_comment_label_policy(self):
        case = next(c for c in self.corpus["cases"] if c["id"] == "py_comment_signature")
        self.assertEqual(case["expected"], "unsupported")
        self.assertTrue(next(r for r in self.report["cases"] if r["id"] == case["id"])["passed"])

    def test_bare_tool_decorator_is_unresolved(self):
        row = next(r for r in self.report["cases"] if r["id"] == "py_tool_decorator")
        self.assertEqual((row["expected"], row["actual"]), ("unresolved", "unresolved"))

    def test_provenance_backed_tool_decorator_is_authoritative(self):
        row = next(
            r for r in self.report["cases"]
            if r["id"] == "py_tool_decorator_provenance"
        )
        self.assertEqual((row["expected"], row["actual"]), ("authoritative", "authoritative"))
        self.assertTrue(row["finding_identity_pass"])

    def test_unbound_similarity_search_is_unresolved(self):
        row = next(r for r in self.report["cases"] if r["id"] == "py_rag_call")
        self.assertEqual((row["expected"], row["actual"]), ("unresolved", "unresolved"))

    def test_provenance_backed_retrieval_is_authoritative(self):
        row = next(
            r for r in self.report["cases"]
            if r["id"] == "py_rag_call_provenance"
        )
        self.assertEqual((row["expected"], row["actual"]), ("authoritative", "authoritative"))
        self.assertTrue(row["finding_identity_pass"])

    def test_obfuscated_import_remains_false_negative_until_supported(self):
        row = next(r for r in self.report["cases"] if r["id"] == "py_obfuscated_import")
        self.assertEqual((row["expected"], row["actual"]), ("authoritative", "none"))
        self.assertTrue(row["known_limitation"])
        self.assertFalse(row["mandatory"])

    def test_real_world_provenance_has_commit_and_license(self):
        cases = [case for case in self.corpus["cases"] if case["construct"] == "real_world"]
        self.assertGreaterEqual(len(cases), 2)
        for case in cases:
            self.assertRegex(case["provenance"]["commit"], r"^[0-9a-f]{40}$")
            self.assertIn(case["provenance"]["license"], {"Apache-2.0", "MIT"})
            self.assertIn("API-shape-preserving", case["provenance"]["adaptation"])

    def test_metrics_record_corpus_version(self):
        self.assertEqual(self.report["corpus_version"], self.corpus["version"])

    def test_zero_denominator_metrics_are_null(self):
        metrics = _metrics([])
        self.assertIsNone(metrics["authoritative_precision"])
        self.assertIsNone(metrics["authoritative_recall"])
        self.assertIsNone(metrics["context"]["accuracy"])

    def test_output_is_deterministic(self):
        with tempfile.TemporaryDirectory() as root:
            output = Path(root) / "metrics.json"
            self.assertEqual(main(["--output", str(output), "--metrics-gate", "--check"]), 0)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), evaluate_corpus())


if __name__ == "__main__":
    unittest.main()
