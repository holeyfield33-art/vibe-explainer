import json
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from vibe_explainer.ai_discovery import discover_ai
from vibe_explainer.attack_surface import build_attack_surface
from vibe_explainer.controls import assess_controls
from vibe_explainer.dataflow import build_dataflow
from vibe_explainer.readiness import assess_readiness
from vibe_explainer.cli import _print_portable
from vibe_explainer.risk import assess_risks
from vibe_explainer.security_report import build_report, render_text, _repo_name
from vibe_explainer.security_utils import redact_secrets

FIXTURES = Path(__file__).resolve().parent / "fixtures"
REPO_ROOT = Path(__file__).resolve().parents[1]


class TestPortableOutput(unittest.TestCase):
    def test_legacy_windows_encoding_replaces_unsupported_glyphs(self):
        raw = io.BytesIO()
        stream = io.TextIOWrapper(raw, encoding="cp1252")
        original = sys.stdout
        try:
            sys.stdout = stream
            _print_portable("PASS \u2500 safe")
            stream.flush()
        finally:
            sys.stdout = original

        self.assertEqual(raw.getvalue().decode("cp1252").strip(), "PASS ? safe")


def _report(fixture_name: str, *, experimental: bool = False):
    discovery = discover_ai(FIXTURES / fixture_name)
    surface = build_attack_surface(discovery)
    graph = build_dataflow(discovery)
    controls = assess_controls(discovery, surface, graph)
    risks = assess_risks(discovery, surface, graph, controls)
    readiness = assess_readiness(discovery, surface, graph, controls, risks)
    return build_report(
        discovery, surface, graph, controls, risks, readiness,
        include_experimental_scoring=experimental,
    )


class TestExecutiveSummary(unittest.TestCase):
    def test_ai_detected_case(self):
        report = _report("agent-with-tools")
        es = report.executive_summary
        self.assertEqual(es["ai_surface"], "DETECTED")
        self.assertEqual(es["risk_scenario_count"], len(report.risks["scenarios"]))
        self.assertNotIn("highest_risk_severity", es)
        self.assertNotIn("readiness_level", es)

    def test_no_ai_case(self):
        report = _report("../../examples/sample-vibe-project")
        es = report.executive_summary
        self.assertEqual(es["ai_surface"], "NOT_DETECTED")
        self.assertEqual(es["risk_scenario_count"], 0)
        self.assertNotIn("highest_risk_severity", es)
        self.assertNotIn("readiness_level", es)
        self.assertIn("no supported AI-related signal was detected", es["statement"])

    def test_forbidden_language_never_appears(self):
        for fixture in ("agent-with-tools", "controls-well-controlled", "../../examples/sample-vibe-project"):
            report = _report(fixture)
            js = report.to_json().lower()
            for banned in ("vulnerability-free", "fully compliant"):
                self.assertNotIn(banned, js)
            # "secure"/"safe" only allowed as part of larger unrelated words is fine;
            # check the executive statement specifically never claims either.
            self.assertNotIn("is secure", report.executive_summary["statement"].lower())
            self.assertNotIn("is safe", report.executive_summary["statement"].lower())


class TestAIInventory(unittest.TestCase):
    def test_grouped_by_category(self):
        report = _report("basic-chatbot")
        self.assertIn("model_provider", report.ai_inventory["categories"])
        self.assertIn("prompt_surface", report.ai_inventory["categories"])

    def test_truncation_notice_present_when_truncated(self):
        report = _report("truncation-heavy")
        self.assertIsNotNone(report.ai_inventory["truncation_notice"])
        self.assertTrue(report.ai_inventory["truncated"])

    def test_no_truncation_notice_when_not_truncated(self):
        report = _report("basic-chatbot")
        self.assertIsNone(report.ai_inventory["truncation_notice"])


class TestAttackSurface(unittest.TestCase):
    def test_all_six_buckets_always_present(self):
        report = _report("basic-chatbot")
        self.assertEqual(set(report.attack_surface.keys()), {"inputs", "model", "retrieval", "tools", "outputs", "storage"})

    def test_outputs_bucket_empty_not_fabricated(self):
        report = _report("basic-chatbot")
        self.assertEqual(report.attack_surface["outputs"], [])


class TestDataFlows(unittest.TestCase):
    def test_edges_present_for_connected_fixture(self):
        report = _report("basic-chatbot")
        self.assertGreater(len(report.data_flows), 0)
        self.assertTrue(all("relationship" in e for e in report.data_flows))

    def test_no_cross_file_flow_implied(self):
        report = _report("dataflow-cross-file")
        self.assertEqual(report.data_flows, [])


class TestControls(unittest.TestCase):
    def test_grouped_by_status_includes_not_detected(self):
        report = _report("agent-with-tools")
        self.assertTrue(report.controls["by_status"]["NOT_DETECTED"])

    def test_not_detected_note_present(self):
        report = _report("agent-with-tools")
        self.assertIn("not that the control definitely does not exist", report.controls["note"])


class TestRiskSummary(unittest.TestCase):
    def test_default_summary_is_by_category_not_severity(self):
        report = _report("agent-with-tools")
        self.assertEqual(sum(report.risks["by_category"].values()), report.risks["total"])
        self.assertNotIn("by_severity", report.risks)

    def test_every_default_concern_has_evidence_and_reachability(self):
        report = _report("agent-with-tools")
        for scenario in report.risks["scenarios"]:
            self.assertIn("evidence_strength", scenario)
            self.assertTrue(scenario["evidence_class"])
            self.assertIn(scenario["reachability_status"], {"STATICALLY_INFERRED", "NOT_ESTABLISHED"})
            self.assertTrue(scenario["unresolved_assumptions"])
            self.assertNotIn("score", scenario)
            self.assertNotIn("severity", scenario)

    def test_experimental_option_restores_legacy_fields(self):
        report = _report("agent-with-tools", experimental=True)
        self.assertIn("by_severity", report.risks)
        self.assertTrue(all("score" in s and "severity" in s for s in report.risks["scenarios"]))


class TestReadiness(unittest.TestCase):
    def test_default_is_unscored_checklist(self):
        report = _report("basic-chatbot")
        self.assertEqual(report.readiness["assessment_status"], "UNSCORED")
        self.assertEqual(len(report.readiness["checks"]), 4)
        self.assertNotIn("readiness_level", report.readiness)

    def test_offline_enforcement_is_always_unknown(self):
        report = _report("basic-chatbot")
        self.assertTrue(all(c["enforcement_status"] == "UNKNOWN" for c in report.readiness["checks"]))

    def test_experimental_option_restores_level_model(self):
        report = _report("readiness-continuous")
        experimental = _report("readiness-continuous", experimental=True)
        self.assertNotIn("level_assessments", report.readiness)
        self.assertEqual(experimental.readiness["readiness_level"], 4)


class TestRiskReadinessDistinctionPreserved(unittest.TestCase):
    def test_unscored_concerns_and_process_checks_are_independent(self):
        report = _report("agent-with-tools")
        self.assertIn("risk_scenario_count", report.executive_summary)
        self.assertEqual(report.readiness["assessment_status"], "UNSCORED")
        self.assertNotIn("highest_risk_severity", report.executive_summary)


class TestRecommendations(unittest.TestCase):
    def test_recommendations_generated_for_high_risk(self):
        report = _report("agent-with-tools")
        self.assertTrue(report.recommendations)
        self.assertEqual(report.recommendations[0]["priority"], "P0")

    def test_priorities_sequential(self):
        report = _report("agent-with-tools")
        priorities = [r["priority"] for r in report.recommendations]
        self.assertEqual(priorities, [f"P{i}" for i in range(len(priorities))])

    def test_no_recommendations_for_well_controlled(self):
        report = _report("controls-well-controlled")
        # no risk scenarios, and readiness blocker still yields at most one rec
        risk_derived = [r for r in report.recommendations if r["related_risk_ids"]]
        self.assertEqual(risk_derived, [])

    def test_dedup_control_not_double_recommended_with_its_risk(self):
        report = _report("agent-with-tools")
        c05_recs = [r for r in report.recommendations if "C05" in r["related_control_ids"] and not r["related_risk_ids"]]
        # C05 gap is already covered by the TOOL_SECURITY/HIGH_IMPACT_ACTION risk
        # recommendations -- must not ALSO get its own standalone C05 recommendation
        self.assertEqual(c05_recs, [])


class TestLimitations(unittest.TestCase):
    def test_limitations_always_present(self):
        for fixture in ("agent-with-tools", "../../examples/sample-vibe-project"):
            report = _report(fixture)
            self.assertTrue(report.limitations)

    def test_aggregation_limitation_added_when_truncated(self):
        # summarized-repetition limitation is present and framed as counted, not lost
        report = _report("truncation-heavy")
        self.assertTrue(any("repeated matches" in lim or "summariz" in lim for lim in report.limitations))


class TestSecretRedaction(unittest.TestCase):
    def test_common_secret_formats_and_assignments_are_redacted(self):
        samples = (
            'ANTHROPIC_API_KEY = "custom-provider-secret"',
            "AWS_SECRET_ACCESS_KEY=aws-secret-value",
            "postgresql://user:database-password@example.test/db",
            "AKIAIOSFODNN7EXAMPLE",
            "ghp_abcdefghijklmnopqrstuvwxyz1234567890",
        )
        for sample in samples:
            with self.subTest(sample=sample):
                self.assertNotIn(
                    sample.split("=")[-1].strip('"') if "=" in sample else sample,
                    redact_secrets(sample),
                )

    def test_prefixed_keyword_assignments_still_redacted(self):
        # Regression guard: making the identifier prefix optional (TASK 2) must NOT
        # weaken the existing prefixed-variable behavior.
        for sample, secret in (
            ('MY_PASSWORD = "hunter2secretvalue"', "hunter2secretvalue"),
            ('DB_TOKEN = "tok_liveABCDEF"', "tok_liveABCDEF"),
            ('AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMIsecret"', "wJalrXUtnFEMIsecret"),
        ):
            with self.subTest(sample=sample):
                out = redact_secrets(sample)
                self.assertNotIn(secret, out)
                self.assertIn("[REDACTED]", out)

    def test_bare_keyword_assignments_are_redacted(self):
        # Regression for the bare-keyword bypass: PASSWORD/TOKEN/SECRET/API_KEY with
        # no leading identifier segment were not redacted before TASK 2.
        for sample, secret in (
            ('PASSWORD = "bareSecret123"', "bareSecret123"),
            ('TOKEN = "bareTokenXYZ"', "bareTokenXYZ"),
            ('SECRET = "bareSecretVal"', "bareSecretVal"),
            ('API_KEY = "bareApiKeyVal"', "bareApiKeyVal"),
        ):
            with self.subTest(sample=sample):
                out = redact_secrets(sample)
                self.assertNotIn(secret, out)
                self.assertIn("[REDACTED]", out)

    def test_url_password_with_embedded_at_sign_fully_redacted(self):
        # Regression for the @-in-password truncation bug (TASK 3): the whole
        # password, including embedded @, must be replaced, leaving nothing but
        # [REDACTED] between the colon and the final @ before the host.
        url = "postgres://admin:Sup3r@Secret@db.internal:5432/prod"
        out = redact_secrets(url)
        self.assertNotIn("Sup3r@Secret", out)
        self.assertNotIn("Secret", out)
        self.assertEqual(out, "postgres://admin:[REDACTED]@db.internal:5432/prod")
        # A URL with no credentials must be left untouched.
        no_cred = "postgres://db.internal:5432/prod"
        self.assertEqual(redact_secrets(no_cred), no_cred)

    def test_no_secret_value_anywhere_in_report(self):
        report = _report("hardcoded-credential")
        js = report.to_json()
        self.assertNotIn("sk-proj-", js)
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz012345", js)
        self.assertIn("[REDACTED]", js)

    def test_risk_scenario_evidence_specifically_redacted(self):
        # Pinpoint check on the exact field an external review flagged: the risk
        # scenario evidence list was being serialized with e.to_dict() and no
        # redaction pass at the Phase 7 boundary. Verify the specific field now.
        report = _report("hardcoded-credential")
        secret_scenarios = [s for s in report.risks["scenarios"] if s["category"] == "SECRET_EXPOSURE"]
        self.assertTrue(secret_scenarios)
        for scenario in secret_scenarios:
            for e in scenario["evidence"]:
                self.assertNotIn("sk-proj-", e["description"])
                self.assertNotIn("abcdefghijklmnopqrstuvwxyz012345", e["description"])


class TestJSONValidity(unittest.TestCase):
    def test_valid_json_no_ansi(self):
        report = _report("agent-with-tools")
        js = report.to_json()
        parsed = json.loads(js)  # raises if invalid
        self.assertIn("executive_summary", parsed)
        self.assertNotIn("\x1b[", js)  # no ANSI escape codes

    def test_deterministic_serialization(self):
        r1 = _report("agent-with-tools")
        r2 = _report("agent-with-tools")
        self.assertEqual(r1.to_json(), r2.to_json())

    def test_ids_traceable_in_json(self):
        report = _report("agent-with-tools")
        js = json.loads(report.to_json())
        finding_ids = {f["id"] for cat in js["ai_inventory"]["categories"].values() for f in cat}
        for scenario in js["risks"]["scenarios"]:
            for fid in scenario["related_finding_ids"]:
                self.assertIn(fid, finding_ids)


class TestTextRendering(unittest.TestCase):
    def test_renders_without_error_for_ai_and_no_ai(self):
        for fixture in ("agent-with-tools", "../../examples/sample-vibe-project"):
            report = _report(fixture)
            text = render_text(report)
            self.assertIn("VIBE EXPLAINER", text)
            self.assertNotIn("\x1b[", text)

    def test_defaulted_production_context_is_visible(self):
        text = render_text(_report("basic-chatbot"))
        self.assertIn("classified by conservative default", text)


class TestCLI(unittest.TestCase):
    def _run(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "vibe_explainer", *args],
            cwd=REPO_ROOT, capture_output=True, text=True,
        )

    def test_default_mode_is_ai_evidence_review(self):
        result = self._run(str(FIXTURES / "basic-chatbot"))
        self.assertEqual(result.returncode, 0)
        self.assertIn("AI REPOSITORY EVIDENCE REVIEW", result.stdout)

    def test_help_has_single_product_boundary(self):
        result = self._run("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("static AI repository evidence review", result.stdout)
        self.assertIn("--legacy-mental-model", result.stdout)
        self.assertIn("--report", result.stdout)
        self.assertNotIn("--offline", result.stdout)
        self.assertNotIn("--security", result.stdout)

    def test_legacy_mental_model_requires_explicit_flag(self):
        result = self._run(str(FIXTURES / "basic-chatbot"), "--legacy-mental-model")
        self.assertEqual(result.returncode, 0)
        self.assertIn("Mental model", result.stdout)

    def test_security_mode_human_readable(self):
        result = self._run(str(FIXTURES / "agent-with-tools"), "--security")
        self.assertEqual(result.returncode, 0)
        self.assertIn("AI REPOSITORY EVIDENCE REVIEW", result.stdout)
        self.assertIn("CONCERNS", result.stdout)
        self.assertIn("PROCESS-EVIDENCE CHECKLIST", result.stdout)
        self.assertNotIn("Traceback", result.stderr)

    def test_security_mode_json(self):
        result = self._run(str(FIXTURES / "agent-with-tools"), "--security", "--json")
        self.assertEqual(result.returncode, 0)
        parsed = json.loads(result.stdout)
        self.assertIn("executive_summary", parsed)
        self.assertNotIn("highest_risk_severity", parsed["executive_summary"])
        self.assertTrue(all("score" not in s for s in parsed["risks"]["scenarios"]))

    def test_experimental_scoring_requires_explicit_flag(self):
        result = self._run(
            str(FIXTURES / "agent-with-tools"), "--json", "--experimental-scoring"
        )
        self.assertEqual(result.returncode, 0)
        parsed = json.loads(result.stdout)
        self.assertTrue(parsed["metadata"]["experimental_scoring_enabled"])
        self.assertTrue(all("score" in s for s in parsed["risks"]["scenarios"]))

    def test_active_output_file_is_excluded_from_discovery(self):
        with tempfile.TemporaryDirectory() as root_dir:
            root = Path(root_dir)
            (root / "app.py").write_text(
                "from openai import OpenAI\nclient = OpenAI()\n",
                encoding="utf-8",
            )
            output = root / "review.json"
            output.write_text(
                '{"stale": "client.chat.completions.create shell=True"}',
                encoding="utf-8",
            )

            result = self._run(str(root), "--json", "--out", str(output))

            self.assertEqual(result.returncode, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            files = {
                finding["file"]
                for rows in payload["ai_inventory"]["categories"].values()
                for finding in rows
            }
            self.assertNotIn("review.json", files)

    def test_high_risk_repo_still_exits_zero(self):
        result = self._run(str(FIXTURES / "agent-with-tools"), "--security", "--json")
        self.assertEqual(result.returncode, 0)

    def test_no_ai_repo_security_mode(self):
        result = self._run(str(REPO_ROOT / "examples" / "sample-vibe-project"), "--security")
        self.assertEqual(result.returncode, 0)
        self.assertIn("NOT_DETECTED", result.stdout)

    def test_bad_path_exits_nonzero_no_traceback(self):
        result = self._run("/definitely/not/a/real/path", "--security")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("Traceback", result.stderr)

    def test_no_secret_leakage_via_cli(self):
        result = self._run(str(FIXTURES / "hardcoded-credential"), "--security", "--json")
        self.assertNotIn("sk-proj-", result.stdout)


class TestRepositoryNameNotLeaked(unittest.TestCase):
    """The first real-world run leaked an assessor's local path
    (C:\\Users\\SuperAdmin\\.vscode\\aletheia-core) into the report header. The
    deliverable should show only the project name; the full path lives separately."""

    def test_repo_name_extracts_basename_windows(self):
        self.assertEqual(_repo_name("C:\\Users\\SuperAdmin\\.vscode\\aletheia-core"), "aletheia-core")

    def test_repo_name_extracts_basename_posix(self):
        self.assertEqual(_repo_name("/home/user/projects/my-repo"), "my-repo")

    def test_repo_name_handles_trailing_slash(self):
        self.assertEqual(_repo_name("/home/user/projects/my-repo/"), "my-repo")

    def test_repo_name_empty_fallback(self):
        self.assertEqual(_repo_name(""), "repository")

    def test_report_metadata_repository_is_basename(self):
        report = _report("agent-with-tools")
        # metadata.repository is the clean name; the full path is separate
        self.assertNotIn("/", report.metadata["repository"])
        self.assertNotIn("\\", report.metadata["repository"])
        self.assertIn("repository_path", report.metadata)

    def test_consultant_header_shows_no_absolute_path(self):
        from vibe_explainer.consultant_report import render_consultant_markdown
        report = _report("agent-with-tools")
        md = render_consultant_markdown(report, assessment_date="2026-01-01")
        # the header line should carry the basename, not a full local path
        header_region = md.split("## Executive Summary")[0]
        self.assertNotIn("/home/", header_region)
        self.assertNotIn("C:\\", header_region)


if __name__ == "__main__":
    unittest.main()
