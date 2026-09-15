import json
import io
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

from vibe_explainer.security_utils import (
    minimal_match_excerpt,
    redact_secrets,
    redact_structure,
)


CORPUS = json.loads((Path(__file__).with_name("credential-corpus.json")).read_text(encoding="utf-8"))


class TestCredentialCorpus(unittest.TestCase):
    def test_positive_credentials_are_redacted(self):
        for case in CORPUS["positive"]:
            with self.subTest(label=case["label"]):
                value = "".join(case["parts"]) if "parts" in case else case["value"]
                secret = value if "parts" in case else case["secret"]
                output = redact_secrets(value)
                self.assertNotIn(secret, output)
                self.assertIn("[REDACTED]", output)

    def test_benign_examples_are_unchanged(self):
        for value in CORPUS["benign"]:
            with self.subTest(value=value):
                self.assertEqual(redact_secrets(value), value)

    def test_recursive_serialization_boundary(self):
        secret = "".join(("sk_", "live_", "51AbCdEfGhIjKlMnOpQrStUv"))
        value = {"error": secret, "nested": ["safe", {"diagnostic": secret}]}
        output = redact_structure(value)
        self.assertNotIn(secret, json.dumps(output))
        self.assertEqual(output["nested"][0], "safe")

    def test_json_text_markdown_and_exception_boundaries_share_redactor(self):
        from tests.test_report_cli import _report
        from vibe_explainer.cli import main
        from vibe_explainer.consultant_report import render_consultant_markdown
        from vibe_explainer.security_report import render_text

        secret = "".join(("sk_", "live_", "51AbCdEfGhIjKlMnOpQrStUv"))
        report = _report("basic-chatbot")
        report.limitations.append(secret)
        for rendered in (report.to_json(), render_text(report), render_consultant_markdown(report)):
            self.assertNotIn(secret, rendered)

        stderr = io.StringIO()
        with patch("vibe_explainer.ai_discovery.discover_ai", side_effect=RuntimeError(secret)):
            with redirect_stderr(stderr):
                rc = main([str(Path(__file__).parent / "fixtures" / "basic-chatbot"), "--json"])
        self.assertEqual(rc, 1)
        self.assertNotIn(secret, stderr.getvalue())
        self.assertIn("[REDACTED]", stderr.getvalue())


class TestMinimalEvidence(unittest.TestCase):
    def test_excerpt_does_not_retain_full_source_line(self):
        prefix = "customer_private_business_context_" * 4
        secret = "".join(("sk_", "live_", "51AbCdEfGhIjKlMnOpQrStUv"))
        text = f"{prefix} client = OpenAI(api_key='{secret}') trailing_private_context" 
        start = text.index("OpenAI")
        excerpt = minimal_match_excerpt(text, start, start + len("OpenAI"))
        self.assertLessEqual(len(excerpt), len("OpenAI") + 50)
        self.assertNotIn("customer_private_business_context", excerpt)
        self.assertNotIn(secret, excerpt)
        self.assertTrue(excerpt.startswith("…"))


if __name__ == "__main__":
    unittest.main()
