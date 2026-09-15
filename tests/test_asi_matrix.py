from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from vibe_explainer.asi_matrix import load_asi_catalog, map_report_to_asi


class TestCatalogLoading(unittest.TestCase):
    def test_loads_split_attack_class_exports(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "catalog-meta.json").write_text(
                json.dumps({"version": "0.2.0-draft", "status": "draft"}),
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

        self.assertEqual(rows["AAC-01"]["assessment_status"], "EVIDENCE_CHAIN")
        self.assertEqual(rows["AAC-01"]["mapped_risks"][0]["category"], "INPUT_SECURITY")
        self.assertEqual(rows["AAC-01"]["attack_detection"], "NOT_PERFORMED")
        self.assertEqual(rows["AAC-01"]["mitigation_evidence"][0]["evidence_status"], "DETECTED")

        self.assertEqual(rows["AAC-11"]["assessment_status"], "EVIDENCE_CHAIN")
        self.assertEqual(rows["AAC-11"]["mitigation_evidence"][0]["evidence_status"], "NOT_DETECTED")

        self.assertEqual(rows["AAC-20"]["assessment_status"], "NOT_OBSERVED")
        self.assertEqual(rows["AAC-20"]["mapped_risks"], [])

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
        self.assertEqual(row["assessment_status"], "RELEVANT_UNASSESSED")
        self.assertEqual(row["attack_detection"], "NOT_PERFORMED")
        self.assertIn("does not prove", row["limitations"])


if __name__ == "__main__":
    unittest.main()
