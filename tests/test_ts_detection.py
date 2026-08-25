import unittest
from pathlib import Path

from vibe_explainer.ai_discovery import discover_ai

FIXTURES = Path(__file__).resolve().parent / "fixtures"


class TestTSFetchOpenAIDetection(unittest.TestCase):
    """Regression for a false-NEGATIVE class found on creator-ai-hub-v2: a real
    production AI app calling OpenAI via raw fetch (not the SDK) surfaced only a
    handful of findings because patterns were Python/SDK-oriented. TS idioms —
    the provider endpoint URL, the messages array, role messages, and AI_* env
    vars — must be detected."""

    def setUp(self):
        self.findings = discover_ai(FIXTURES / "ts-fetch-openai").findings
        self.names = {f.name for f in self.findings}
        self.by_cat = {}
        for f in self.findings:
            self.by_cat.setdefault(f.category, set()).add(f.name)

    def test_openai_http_endpoint_detected(self):
        self.assertIn("OpenAI-compatible HTTP endpoint", self.names)

    def test_ai_usage_present(self):
        self.assertIn("ai_usage", self.by_cat)

    def test_messages_array_detected_as_ai_usage(self):
        self.assertIn("Chat messages array", self.by_cat.get("ai_usage", set()))

    def test_role_message_detected_as_prompt_surface(self):
        self.assertIn("Chat role message", self.by_cat.get("prompt_surface", set()))

    def test_ai_api_key_env_var_detected(self):
        secret_names = self.by_cat.get("secret_config", set())
        self.assertIn("Model API key env var", secret_names)

    def test_recovers_meaningful_surface(self):
        # sanity floor: this file alone should yield several AI findings, not 1-2
        self.assertGreaterEqual(len(self.findings), 5)


class TestNewTSPatternsDoNotOverfire(unittest.TestCase):
    """The TS patterns must be precise: a plain non-AI TS file should not trip
    the new AI-usage patterns just because it has a messages array or fetch."""

    def test_plain_messages_variable_not_flagged_as_ai(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "chat.ts"
            # a UI messages list, no role: shape, no provider endpoint
            p.write_text("const messages = ['hello', 'world'];\nfetch('/api/local');\n")
            findings = discover_ai(d).findings
            ai_names = {f.name for f in findings if f.category == "ai_usage"}
            self.assertNotIn("OpenAI-compatible HTTP endpoint", ai_names)
            self.assertNotIn("Chat messages array", ai_names)


if __name__ == "__main__":
    unittest.main()
