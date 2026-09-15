from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from vibe_explainer.ai_discovery import discover_ai
from vibe_explainer.asi_matrix import load_asi_catalog, map_report_to_asi
from vibe_explainer.attack_surface import build_attack_surface
from vibe_explainer.controls import assess_controls
from vibe_explainer.dataflow import build_dataflow
from vibe_explainer.readiness import assess_readiness
from vibe_explainer.risk import assess_risks
from vibe_explainer.security_report import build_report

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _real_report(fixture: str):
    discovery = discover_ai(FIXTURES / fixture)
    surface = build_attack_surface(discovery)
    dataflow = build_dataflow(discovery)
    controls = assess_controls(discovery, surface, dataflow)
    risks = assess_risks(discovery, surface, dataflow, controls)
    readiness = assess_readiness(discovery, surface, dataflow, controls, risks)
    return build_report(discovery, surface, dataflow, controls, risks, readiness)


class TestCatalogLoading(unittest.TestCase):
    def test_loads_split_attack_class_exports(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "catalog-meta.json").write_text(
                json.dumps({"version": "0.2.0-draft", "status": "draft", "classCount": 2}),
                encoding="utf-8",
            )
            (root / "attack-classes-01.json").write_text(
                json.dumps([
                    {"id": "AAC-01", "name": "Direct Prompt Injection", "protocols": ["Native"], "proposedMitigationIds": ["untrusted-io"]},
                ]),
                encoding="utf-8",
            )
            (root / "attack-classes-02.json").write_text(
                json.dumps([
                    {"id": "AAC-09", "name": "Token Mismanagement", "protocols": ["Native", "MCP"], "proposedMitigationIds": ["output-dlp"]},
                ]),
                encoding="utf-8",
            )

            catalog = load_asi_catalog(root)
            self.assertEqual([row["id"] for row in catalog["classes"]], ["AAC-01", "AAC-09"])
            self.assertEqual(catalog["metadata"]["version"], "0.2.0-draft")
            self.assertRegex(catalog["source_hash"], r"^sha256:[0-9a-f]{64}$")

    def test_loads_generated_combined_catalog_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "asi-catalog.json"
            path.write_text(
                json.dumps(
                    {
                        "catalog": {
                            "version": "0.2.0-draft",
                            "status": "draft",
                            "classCount": 1,
                        },
                        "attackClasses": [
                            {
                                "id": "AAC-01",
                                "name": "Direct Prompt Injection",
                                "protocols": ["Native"],
                                "mitigations": ["untrusted-io"],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            catalog = load_asi_catalog(path)
            self.assertEqual(catalog["metadata"]["version"], "0.2.0-draft")
            self.assertEqual(catalog["classes"][0]["proposedMitigationIds"], ["untrusted-io"])

    def test_rejects_incomplete_declared_catalog(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "catalog-meta.json").write_text(
                json.dumps({"version": "0.2.0-draft", "classCount": 40}),
                encoding="utf-8",
            )
            (root / "attack-classes-01.json").write_text(
                json.dumps([{"id": "AAC-01", "name": "x", "protocols": ["Native"]}]),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "Incomplete ASI catalog export"):
                load_asi_catalog(root)

    def test_rejects_duplicate_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "attack-classes.json"
            row = {"id": "AAC-01", "name": "x", "protocols": []}
            path.write_text(json.dumps([row, row]), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Duplicate ASI"):
                load_asi_catalog(path)


class TestMatrixMapping(unittest.TestCase):
    def _report(self):
        return SimpleNamespace(
            metadata={"repository": "sample-agent", "assessment_completeness": "COMPLETE"},
            executive_summary={"ai_surface": "DETECTED"},
            ai_inventory={
                "categories": {
                    "ai_usage": [
                        {"name": "Model call", "evidence": "client.responses.create(...)"},
                    ],
                    "mcp": [
                        {"name": "MCP server", "evidence": "mcp server"},
                    ],
                }
            },
            controls={
                "by_status": {
                    "DETECTED": [
                        {"control_id": "C03", "name": "Input Handling", "confidence": "high", "evidence": []},
                        {"control_id": "C05", "name": "Tool Authorization", "confidence": "high", "evidence": []},
                        {"control_id": "C08", "name": "Secret Management", "confidence": "moderate", "evidence": []},
                    ],
                    "NOT_DETECTED": [
                        {"control_id": "C12", "name": "High-Risk Action Controls", "confidence": "moderate", "evidence": []},
                    ],
                }
            },
            risks={
                "scenarios": [
                    {
                        "risk_id": "R-INPUT_SECURITY-1234",
                        "category": "INPUT_SECURITY",
                        "severity": "MODERATE",
                        "score": 9,
                        "confidence": "high",
                        "related_finding_ids": ["F1"],
                        "related_dataflow_ids": ["D1"],
                    },
                    {
                        "risk_id": "R-HIGH_IMPACT_ACTION-1234",
                        "category": "HIGH_IMPACT_ACTION",
                        "severity": "CRITICAL",
                        "score": 20,
                        "confidence": "high",
                        "related_finding_ids": ["F2"],
                        "related_dataflow_ids": ["D2"],
                    },
                ]
            },
        )

    def test_maps_evidence_without_claiming_attack_detection(self):
        catalog = {
            "source": "fixture",
            "metadata": {"version": "0.2.0-draft", "status": "draft"},
            "classes": [
                {
                    "id": "AAC-01",
                    "name": "Direct Prompt Injection",
                    "family": "injection",
                    "protocols": ["Native"],
                    "evidenceTier": "T2_field_incident",
                    "decision": "COVER_NOW",
                    "proposedMitigationIds": ["untrusted-io"],
                },
                {
                    "id": "AAC-11",
                    "name": "Command Injection & Execution",
                    "family": "execution",
                    "protocols": ["Native", "MCP"],
                    "evidenceTier": "T3_widespread",
                    "decision": "COVER_NOW",
                    "proposedMitigationIds": ["tool-sandbox"],
                },
                {
                    "id": "AAC-20",
                    "name": "Agent Card Poisoning",
                    "family": "injection",
                    "protocols": ["A2A"],
                    "evidenceTier": "T1_lab_poc",
                    "decision": "COVER_NOW",
                    "proposedMitigationIds": ["signed-cards"],
                },
            ],
        }

        result = map_report_to_asi(self._report(), catalog)
        rows = {row["id"]: row for row in result["classes"]}

        self.assertEqual(rows["AAC-01"]["applicability"]["status"], "APPLICABLE")
        self.assertEqual(
            rows["AAC-01"]["class_evidence"]["mapped_concerns"][0]["category"],
            "INPUT_SECURITY",
        )
        self.assertEqual(rows["AAC-01"]["class_evidence"]["attack_detection"], "NOT_PERFORMED")

        # Class evidence and mitigation state are independent axes. The mapped
        # concern does not hide the C12 NOT_DETECTED repository status.
        self.assertEqual(rows["AAC-11"]["class_evidence"]["status"], "OBSERVED")
        sandbox = next(
            item for item in rows["AAC-11"]["mitigation_evidence"]
            if item["mitigation_id"] == "tool-sandbox"
        )
        self.assertEqual(sandbox["mapped_controls"][0]["repository_status"], "NOT_DETECTED")

        self.assertEqual(rows["AAC-20"]["applicability"]["status"], "NOT_ESTABLISHED")
        self.assertEqual(rows["AAC-20"]["class_evidence"]["mapped_concerns"], [])

    def test_relevant_unassessed_is_not_misreported_as_safe(self):
        catalog = {
            "source": "fixture",
            "metadata": {},
            "classes": [
                {
                    "id": "AAC-14",
                    "name": "Shadow MCP Servers",
                    "family": "supply-chain",
                    "protocols": ["MCP"],
                    "proposedMitigationIds": ["drift-detect"],
                }
            ],
        }
        result = map_report_to_asi(self._report(), catalog)
        row = result["classes"][0]
        self.assertEqual(row["applicability"]["status"], "APPLICABLE")
        self.assertEqual(row["class_evidence"]["status"], "NOT_OBSERVED")
        self.assertEqual(row["class_evidence"]["attack_detection"], "NOT_PERFORMED")
        self.assertEqual(row["manual_review"]["status"], "REQUIRED")

    def test_unscored_report_does_not_gain_numeric_fields_in_mapping(self):
        report = self._report()
        for scenario in report.risks["scenarios"]:
            scenario.pop("score", None)
            scenario.pop("severity", None)
            scenario["evidence_strength"] = scenario.pop("confidence")
            scenario["evidence_class"] = ["DATAFLOW"]
            scenario["reachability_status"] = "STATICALLY_INFERRED"
            scenario["unresolved_assumptions"] = ["Runtime reachability was not tested."]
        catalog = {
            "source": "fixture",
            "metadata": {},
            "classes": [
                {"id": "AAC-01", "name": "Direct Prompt Injection", "protocols": ["Native"]}
            ],
        }

        result = map_report_to_asi(report, catalog)
        mapped = result["classes"][0]["class_evidence"]["mapped_concerns"][0]

        self.assertNotIn("score", mapped)
        self.assertNotIn("severity", mapped)
        self.assertEqual(mapped["reachability_status"], "STATICALLY_INFERRED")

    def test_conflicting_controls_are_preserved_without_aggregation(self):
        catalog = {
            "source": "fixture",
            "metadata": {},
            "classes": [
                {
                    "id": "AAC-07",
                    "name": "Scope Creep",
                    "protocols": ["Native"],
                    "proposedMitigationIds": ["least-privilege"],
                }
            ],
        }

        row = map_report_to_asi(self._report(), catalog)["classes"][0]
        controls = row["mitigation_evidence"][0]["mapped_controls"]
        statuses = {item["control_id"]: item["repository_status"] for item in controls}

        self.assertEqual(statuses["C05"], "DETECTED")
        self.assertEqual(statuses["C12"], "NOT_DETECTED")
        self.assertNotIn("evidence_status", row["mitigation_evidence"][0])

    def test_protocol_applicability_has_positive_and_negative_fixtures(self):
        positives = {
            "Native": {"ai_usage": [{"id": "F1", "file": "app.py", "name": "call", "evidence": "model call"}]},
            "MCP": {"mcp": [{"id": "F1", "file": "mcp.json", "name": "MCP", "evidence": "mcp server"}]},
            "RAG": {"rag_retrieval": [{"id": "F1", "file": "rag.py", "name": "vector", "evidence": "retrieval"}]},
            "A2A": {"integration": [{"id": "F1", "file": "card.json", "name": "Agent Card", "evidence": "A2A Agent Card"}]},
            "ANP": {"integration": [{"id": "F1", "file": "network.py", "name": "ANP", "evidence": "Agent Network Protocol"}]},
            "Skills": {"integration": [{"id": "F1", "file": "skills/review/SKILL.md", "name": "Agent skill", "evidence": "skill manifest"}]},
        }
        for protocol, categories in positives.items():
            with self.subTest(protocol=protocol):
                positive = self._report()
                positive.ai_inventory = {"categories": categories}
                positive.risks = {"scenarios": []}
                catalog = {
                    "source": "fixture",
                    "metadata": {},
                    "classes": [{"id": "AAC-X", "name": "x", "protocols": [protocol]}],
                }
                positive_row = map_report_to_asi(positive, catalog)["classes"][0]
                self.assertEqual(positive_row["applicability"]["status"], "APPLICABLE")
                self.assertTrue(positive_row["applicability"]["basis"])

                negative = self._report()
                negative.ai_inventory = {"categories": {}}
                negative.risks = {"scenarios": []}
                negative_row = map_report_to_asi(negative, catalog)["classes"][0]
                self.assertEqual(negative_row["applicability"]["status"], "NOT_ESTABLISHED")
                self.assertEqual(negative_row["applicability"]["basis"], [])


class TestPinnedFortyClassCatalog(unittest.TestCase):
    def setUp(self):
        self.catalog = load_asi_catalog(FIXTURES / "asi-catalog-40.json")
        self.matrix = map_report_to_asi(_real_report("basic-chatbot"), self.catalog)

    def test_golden_catalog_identity_and_summary(self):
        self.assertEqual(self.matrix["schema_version"], "2.0")
        self.assertEqual(self.matrix["catalog"]["version"], "0.2.0-draft")
        self.assertEqual(self.matrix["catalog"]["status"], "draft")
        self.assertTrue(self.matrix["catalog"]["independent_review"]["pending"])
        self.assertEqual(
            self.matrix["catalog"]["source_hash"],
            "sha256:034806b3bd7f423de7369c0651b985ebfb1dfe87eb0eb85cd0b1f776c7ccdc15",
        )
        self.assertEqual(self.matrix["summary"]["class_count"], 40)
        self.assertEqual(
            [row["id"] for row in self.matrix["classes"]],
            [f"AAC-{number:02d}" for number in range(1, 41)],
        )

    def test_basic_chatbot_gets_no_unrelated_class_gap_verdicts(self):
        rows = {row["id"]: row for row in self.matrix["classes"]}
        for class_id in ("AAC-17", "AAC-29", "AAC-35", "AAC-39"):
            with self.subTest(class_id=class_id):
                row = rows[class_id]
                self.assertEqual(row["class_evidence"]["status"], "NOT_OBSERVED")
                self.assertEqual(row["class_evidence"]["mapped_concerns"], [])
                self.assertNotIn("assessment_status", row)
                self.assertNotIn("CONTROL_GAP", json.dumps(row))

    def test_catalog_review_warning_is_machine_visible(self):
        self.assertEqual(self.matrix["catalog"]["status"], "draft")
        self.assertTrue(self.matrix["catalog"]["independent_review"]["pending"])


if __name__ == "__main__":
    unittest.main()
