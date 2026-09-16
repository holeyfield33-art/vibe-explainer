import unittest
import unittest.mock
import os
import tempfile
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


class TestEnvBasedCredentialReference(unittest.TestCase):
    """Regression for C08 only recognizing a fixed provider-name allowlist
    (OPENAI_API_KEY, ANTHROPIC_API_KEY, ...) plus a bare 'API_KEY' pattern
    that requires the literal word boundary immediately before it. Neither
    matched aegis-provenance's real, correctly-env-based credential:
    AEGIS_EVAL_API_KEY via process.env (llm-eval.ts:679, real-model-asr.ts:285)."""

    def test_custom_named_process_env_reference_detected(self):
        result = discover_ai(FIXTURES / "controls-custom-env-secret")
        names = _names(result.findings, "secret_config")
        self.assertIn("Env-based credential reference", names)

    def test_os_getenv_custom_token_name_detected(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "config.py"
            f.write_text('token = os.getenv("SOMETHING_TOKEN")\n')
            result = discover_ai(Path(d))
            names = _names(result.findings, "secret_config")
            self.assertIn("Env-based credential reference", names)

    def test_os_environ_get_custom_secret_name_detected(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "config.py"
            f.write_text('secret = os.environ.get("SOMETHING_SECRET")\n')
            result = discover_ai(Path(d))
            names = _names(result.findings, "secret_config")
            self.assertIn("Env-based credential reference", names)

    def test_unrelated_env_vars_not_flagged(self):
        # Negative case: common non-credential env vars must not fire the
        # new pattern just because they're read via process.env/os.getenv.
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "server.ts"
            f.write_text(
                "const env = process.env.NODE_ENV;\n"
                "const port = process.env.PORT;\n"
            )
            result = discover_ai(Path(d))
            names = _names(result.findings, "secret_config")
            self.assertNotIn("Env-based credential reference", names)

    def test_unrelated_os_getenv_not_flagged(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "settings.py"
            f.write_text('debug = os.getenv("DEBUG")\nport = os.getenv("PORT")\n')
            result = discover_ai(Path(d))
            names = _names(result.findings, "secret_config")
            self.assertNotIn("Env-based credential reference", names)

    def test_fixed_provider_name_pattern_still_works_unchanged(self):
        # Regression: the existing fixed-provider-name case (basic-chatbot's
        # os.environ["OPENAI_API_KEY"]) must still be detected exactly as
        # before — this fix is additive, not a replacement.
        result = discover_ai(FIXTURES / "basic-chatbot")
        self.assertIn("Model API key env var", _names(result.findings, "secret_config"))

    def test_pattern_does_not_self_match_its_own_definition(self):
        # Self-referential-FP guard: running discovery over vibe_explainer's
        # own source must not have the new pattern match its own regex
        # pattern-definition string in ai_discovery.py (analogous to how
        # _SIGNATURE_PRONE_NAMES keeps eval/exec patterns from flagging
        # their own source).
        package_root = Path(__file__).resolve().parents[1] / "vibe_explainer"
        result = discover_ai(package_root)
        self_matches = [
            f
            for f in result.findings
            if f.name == "Env-based credential reference" and f.file == "ai_discovery.py"
        ]
        self.assertEqual(self_matches, [])


class TestUntrustedFilesystemSafety(unittest.TestCase):
    def test_file_symlink_outside_root_is_not_read(self):
        with tempfile.TemporaryDirectory() as root_dir, tempfile.TemporaryDirectory() as outside_dir:
            root = Path(root_dir)
            outside = Path(outside_dir) / "secret.py"
            outside.write_text('from openai import OpenAI\nOPENAI_API_KEY = "outside-secret"\n')
            try:
                (root / "linked.py").symlink_to(outside)
            except OSError:
                self.skipTest("symlink creation requires elevated privilege on this platform")

            result = discover_ai(root)

            self.assertEqual(result.findings, [])
            self.assertEqual(result.files_scanned, 0)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO test requires POSIX")
    def test_fifo_is_skipped_without_opening(self):
        with tempfile.TemporaryDirectory() as root_dir:
            fifo = Path(root_dir) / "blocked.py"
            os.mkfifo(fifo)

            result = discover_ai(root_dir)

            self.assertEqual(result.findings, [])
            self.assertEqual(result.files_scanned, 0)
            self.assertEqual(result.files_unreadable, 1)
            self.assertTrue(result.has_coverage_gap())


class TestCoverageBudgets(unittest.TestCase):
    # Issue #21/#9: global scan budgets on file count / total bytes / elapsed
    # time, and a loud count of *why* a candidate was never examined, rather
    # than an unbounded walk that could exhaust memory/time on a hostile or
    # accidental huge tree.

    def test_oversized_file_counted_not_silently_dropped(self):
        import vibe_explainer.ai_discovery as ai_discovery_module

        with tempfile.TemporaryDirectory() as root_dir:
            big = Path(root_dir) / "huge.py"
            big.write_text("x = 1\n" * 1000)

            with unittest.mock.patch.object(ai_discovery_module, "MAX_FILE_BYTES", 10):
                result = discover_ai(root_dir)

            self.assertEqual(result.files_scanned, 0)
            self.assertEqual(result.files_skipped_size, 1)
            self.assertTrue(result.has_coverage_gap())

    def test_file_count_budget_stops_scan_and_marks_exhausted(self):
        import vibe_explainer.ai_discovery as ai_discovery_module

        with tempfile.TemporaryDirectory() as root_dir:
            for i in range(5):
                (Path(root_dir) / f"f{i}.py").write_text("x = 1\n")

            with unittest.mock.patch.object(ai_discovery_module, "MAX_FILES_SCANNED", 2):
                result = discover_ai(root_dir)

            self.assertLessEqual(result.files_scanned, 2)
            self.assertTrue(result.budget_exhausted)
            self.assertIn("file count budget", result.budget_exhausted_reason)
            self.assertTrue(result.has_coverage_gap())

    def test_no_gap_reported_when_nothing_skipped(self):
        result = discover_ai(SAMPLE_NO_AI)
        self.assertFalse(result.has_coverage_gap())
        self.assertEqual(result.files_skipped_size, 0)
        self.assertEqual(result.files_unreadable, 0)
        self.assertFalse(result.budget_exhausted)


class TestEarlyEvidenceRedaction(unittest.TestCase):
    def test_unknown_format_secret_assignment_is_redacted_in_discovery(self):
        with tempfile.TemporaryDirectory() as root_dir:
            source = Path(root_dir) / "app.py"
            source.write_text('from openai import OpenAI\nOPENAI_API_KEY = "not-an-sk-secret-value"\n')

            result = discover_ai(root_dir)

            serialized = str(result.to_dict())
            self.assertNotIn("not-an-sk-secret-value", serialized)
            self.assertIn("[REDACTED]", serialized)


class TestSyntaxAwareDiscovery(unittest.TestCase):
    def test_python_comments_and_embedded_sdk_calls_are_leads_not_evidence(self):
        with tempfile.TemporaryDirectory() as root_dir:
            Path(root_dir, "app.py").write_text(
                '# from openai import OpenAI\n'
                'example = "client.chat.completions.create(model=\\"gpt-4o\\")"\n'
            )
            result = discover_ai(root_dir)

            self.assertFalse(result.has_ai_signal())
            self.assertTrue(result.has_any_lead())
            self.assertTrue(all(not finding.supports_conclusions for finding in result.findings))

    def test_aliased_python_import_is_structural_evidence(self):
        with tempfile.TemporaryDirectory() as root_dir:
            Path(root_dir, "app.py").write_text(
                "from openai import OpenAI as Client\nclient = Client()\n"
            )
            result = discover_ai(root_dir)

            provider = next(f for f in result.findings if f.name == "OpenAI")
            self.assertTrue(provider.supports_conclusions)
            self.assertEqual(provider.evidence_basis, "PYTHON_AST")
            self.assertTrue(result.has_ai_signal())

    def test_unsupported_language_match_cannot_establish_ai_signal(self):
        with tempfile.TemporaryDirectory() as root_dir:
            Path(root_dir, "app.ts").write_text(
                'import OpenAI from "openai";\nstreamText({ model: client });\n'
            )
            result = discover_ai(root_dir)

            self.assertFalse(result.has_ai_signal())
            self.assertTrue(result.findings)
            self.assertTrue(all(f.evidence_basis == "LEXICAL_LEAD" for f in result.findings))
            coverage = result.to_dict()["analysis_coverage"]
            self.assertEqual(coverage["authoritative_findings"], 0)
            self.assertGreater(coverage["unsupported_lexical_leads"], 0)


if __name__ == "__main__":
    unittest.main()
