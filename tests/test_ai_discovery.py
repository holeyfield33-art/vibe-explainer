import unittest
from pathlib import Path

from vibe_explainer.ai_discovery import discover_ai

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SAMPLE_NO_AI = Path(__file__).resolve().parents[1] / "examples" / "sample-vibe-project"


def _names(findings, category=None):
    if category is not None:
        findings = [f for f in findings if f.category == category]
    return {f.name for f in findings}


class TestNoAISignal(unittest.TestCase):
    def test_non_ai_project_has_no_findings(self):
        result = discover_ai(SAMPLE_NO_AI)
        self.assertFalse(result.has_ai_signal())
        self.assertEqual(result.findings, [])


class TestBasicChatbot(unittest.TestCase):
    def setUp(self):
        self.result = discover_ai(FIXTURES / "basic-chatbot")

    def test_detects_openai_provider(self):
        self.assertIn("OpenAI", _names(self.result.findings, "model_provider"))

    def test_detects_chat_completion_call(self):
        self.assertIn("Chat/completions call", _names(self.result.findings, "ai_usage"))

    def test_detects_system_prompt(self):
        self.assertIn("System prompt variable", _names(self.result.findings, "prompt_surface"))

    def test_detects_api_key_env_var(self):
        self.assertIn("Model API key env var", _names(self.result.findings, "secret_config"))

    def test_findings_carry_evidence_and_confidence(self):
        for f in self.result.findings:
            self.assertTrue(f.evidence)
            self.assertIn(f.confidence, ("high", "moderate", "low"))
            self.assertGreater(f.line, 0)


class TestRAGApp(unittest.TestCase):
    def setUp(self):
        self.result = discover_ai(FIXTURES / "rag-app")

    def test_detects_anthropic_provider(self):
        self.assertIn("Anthropic", _names(self.result.findings, "model_provider"))

    def test_detects_vector_store(self):
        self.assertIn("Chroma", _names(self.result.findings, "rag_retrieval"))
        self.assertIn("Vector store / retriever", _names(self.result.findings, "rag_retrieval"))


class TestAgentWithTools(unittest.TestCase):
    def setUp(self):
        self.result = discover_ai(FIXTURES / "agent-with-tools")

    def test_detects_tool_decorator(self):
        self.assertIn("Tool/function decorator", _names(self.result.findings, "tool_agent"))

    def test_detects_shell_execution(self):
        self.assertIn("Shell execution", _names(self.result.findings, "tool_agent"))

    def test_detects_tool_choice_config(self):
        self.assertIn("Function-calling config", _names(self.result.findings, "tool_agent"))


class TestMCPServer(unittest.TestCase):
    def setUp(self):
        self.result = discover_ai(FIXTURES / "mcp-server")

    def test_detects_fastmcp(self):
        self.assertIn("FastMCP server", _names(self.result.findings, "mcp"))


class TestHardcodedCredential(unittest.TestCase):
    def setUp(self):
        self.result = discover_ai(FIXTURES / "hardcoded-credential")

    def test_detects_possible_hardcoded_key(self):
        names = _names(self.result.findings, "secret_config")
        self.assertIn("Possible hardcoded API key", names)
        finding = next(
            f for f in self.result.findings if f.name == "Possible hardcoded API key"
        )
        self.assertEqual(finding.confidence, "high")


class TestExternalAPIApp(unittest.TestCase):
    def setUp(self):
        self.result = discover_ai(FIXTURES / "external-api-app")

    def test_detects_http_client_call(self):
        self.assertIn("HTTP client call", _names(self.result.findings, "external_integration"))

    def test_detects_webhook(self):
        self.assertIn("Webhook handler", _names(self.result.findings, "external_integration"))

    def test_no_model_provider_signal(self):
        # This fixture has no LLM SDK at all — should not falsely claim one.
        self.assertEqual(_names(self.result.findings, "model_provider"), set())


class TestFindingIdentity(unittest.TestCase):
    def test_finding_has_stable_deterministic_id(self):
        r1 = discover_ai(FIXTURES / "basic-chatbot")
        r2 = discover_ai(FIXTURES / "basic-chatbot")
        ids1 = sorted(f.id for f in r1.findings)
        ids2 = sorted(f.id for f in r2.findings)
        self.assertTrue(all(ids1))  # no empty ids
        self.assertEqual(ids1, ids2)  # same input -> same ids, run to run

    def test_ids_are_unique_within_a_result(self):
        result = discover_ai(FIXTURES / "rag-app")
        ids = [f.id for f in result.findings]
        self.assertEqual(len(ids), len(set(ids)))


class TestTruncationIsRecorded(unittest.TestCase):
    def test_matches_beyond_cap_are_recorded_not_dropped(self):
        # Five distinct-line "OpenAI(" calls in one file, cap is 3 — verifies
        # truncation is tracked rather than silently discarded.
        result = discover_ai(FIXTURES / "truncation-heavy")
        self.assertGreater(len(result.truncated), 0)
        for t in result.truncated:
            self.assertGreater(t.additional_matches, 0)
            self.assertTrue(t.file)
            self.assertTrue(t.category)
            self.assertTrue(t.name)
        # 6 distinct-line matches total (the import line + 5 client lines),
        # cap 3 -> 3 kept, 3 recorded as truncated (deduped per-identity, not
        # per-pattern, so the import line's second low-confidence match on the
        # same line doesn't inflate this further)
        openai_trunc = next(
            t for t in result.truncated if t.category == "model_provider" and t.name == "OpenAI"
        )
        self.assertEqual(openai_trunc.additional_matches, 3)
        # and exactly 3 real findings were kept (not silently expanded either)
        kept = [f for f in result.findings if f.category == "model_provider" and f.name == "OpenAI"]
        self.assertEqual(len(kept), 3)

    def test_truncated_present_in_to_dict(self):
        result = discover_ai(FIXTURES / "truncation-heavy")
        d = result.to_dict()
        self.assertIn("truncated", d)
        self.assertEqual(len(d["truncated"]), len(result.truncated))


class TestIdentityCollisionAcrossPatterns(unittest.TestCase):
    def test_overlapping_patterns_on_same_line_upgrade_not_duplicate(self):
        # basic-chatbot's `from openai import OpenAI` line is matched by both
        # the specific "from openai import" pattern (high) and the generic
        # bare-word "openai" pattern (low). That must produce exactly one
        # finding at that identity, upgraded to the higher confidence — not two
        # findings sharing an id.
        result = discover_ai(FIXTURES / "basic-chatbot")
        ids = [f.id for f in result.findings]
        self.assertEqual(len(ids), len(set(ids)), "duplicate finding id found")
        line2 = [f for f in result.findings if f.line == 2 and f.category == "model_provider"]
        self.assertEqual(len(line2), 1)
        self.assertEqual(line2[0].confidence, "high")


if __name__ == "__main__":
    unittest.main()
