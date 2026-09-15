"""Deterministically map Vibe Explainer evidence onto Agent Security Index rows.

This is a bridge layer, not a second scanner. It consumes an already-built
``VibeExplainerReport`` plus a *local* ASI export and reports row relevance,
related Vibe evidence, and repository evidence for mitigations Vibe knows how
to recognize. It never claims exploitability, attack presence, mitigation
effectiveness, or ASI validation.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "2.0"

# Vibe control -> ASI mitigation evidence bridges. These mean only that a Vibe
# control can provide repository evidence relevant to the mitigation.
_CONTROL_TO_ASI_MITIGATIONS: dict[str, tuple[str, ...]] = {
    "C03": ("untrusted-io", "schema-gov"),
    "C04": ("output-dlp", "schema-gov"),
    "C05": ("least-privilege", "capability-attest"),
    "C06": ("hitl",),
    "C07": ("telemetry", "trajectory"),
    "C08": ("output-dlp",),
    "C09": ("rag-validate", "provenance"),
    "C10": ("allowlist-servers", "least-privilege", "schema-gov"),
    "C11": ("least-privilege", "isolation"),
    "C12": ("tool-sandbox", "hitl", "least-privilege"),
}

# Keep attack-specific bridges deliberately narrow. Protocol relevance can make
# many more rows applicable, but unsupported rows must remain unassessed.
_RISK_CATEGORY_TO_AAC: dict[str, tuple[str, ...]] = {
    "INPUT_SECURITY": ("AAC-01",),
    "RAG_SECURITY": ("AAC-02",),
    "SECRET_EXPOSURE": ("AAC-09",),
    "HIGH_IMPACT_ACTION": ("AAC-11", "AAC-16"),
}

def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"ASI catalog path does not exist: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"ASI catalog is not valid JSON: {path}: {exc}") from exc


def _extract_attack_classes(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [
            row for row in payload
            if isinstance(row, dict) and str(row.get("id", "")).startswith("AAC-")
        ]
    if not isinstance(payload, dict):
        return []

    for key in ("attackClasses", "attack_classes", "classes"):
        rows = payload.get(key)
        if isinstance(rows, list):
            found = _extract_attack_classes(rows)
            if found:
                return found
    for key in ("catalog", "data", "matrix"):
        found = _extract_attack_classes(payload.get(key))
        if found:
            return found
    return []


def _extract_metadata(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    # ASI's generated combined snapshot uses `catalog`; accept older/generic
    # aliases too so Vibe does not couple to frontend internals.
    for key in ("catalog", "meta", "metadata"):
        value = payload.get(key)
        if isinstance(value, dict):
            return value
    return {}


def _normalize_class(row: dict[str, Any]) -> dict[str, Any]:
    out = dict(row)
    # JSON chunks historically used proposedMitigationIds; the current TS-derived
    # combined export uses mitigations. Normalize once at the boundary.
    if "proposedMitigationIds" not in out and isinstance(out.get("mitigations"), list):
        out["proposedMitigationIds"] = list(out["mitigations"])
    return out


def load_asi_catalog(path: str | Path) -> dict[str, Any]:
    """Load a local ASI export directory or JSON file; never fetch the network.

    Directory mode prefers a generated ``asi-catalog.json``. If it is absent,
    split ``attack-classes*.json`` files are accepted only when their observed
    count matches ``catalog-meta.json.classCount`` (when declared). This prevents
    a stale partial export from silently becoming a partial customer matrix.
    """
    source = Path(path)
    metadata: dict[str, Any] = {}
    classes: list[dict[str, Any]] = []
    source_files: list[Path] = []

    if source.is_dir():
        meta_path = source / "catalog-meta.json"
        if meta_path.is_file():
            source_files.append(meta_path)
            meta_payload = _load_json(meta_path)
            if isinstance(meta_payload, dict):
                metadata = meta_payload

        combined = source / "asi-catalog.json"
        if combined.is_file():
            source_files = [combined]
            payload = _load_json(combined)
            classes = _extract_attack_classes(payload)
            metadata = metadata or _extract_metadata(payload)
        else:
            for fragment in sorted(source.glob("attack-classes*.json")):
                source_files.append(fragment)
                classes.extend(_extract_attack_classes(_load_json(fragment)))
    else:
        source_files = [source]
        payload = _load_json(source)
        classes = _extract_attack_classes(payload)
        metadata = _extract_metadata(payload)

    classes = [_normalize_class(row) for row in classes]
    if not classes:
        raise ValueError(
            "No AAC attack classes found. Provide an ASI export directory, "
            "asi-catalog.json, or attack-classes JSON file."
        )

    ids = [str(row.get("id", "")) for row in classes]
    duplicates = sorted({item for item in ids if ids.count(item) > 1})
    if duplicates:
        raise ValueError(f"Duplicate ASI attack-class IDs: {', '.join(duplicates)}")

    expected_count = metadata.get("classCount") if isinstance(metadata, dict) else None
    if isinstance(expected_count, int) and expected_count > 0 and len(classes) != expected_count:
        raise ValueError(
            f"Incomplete ASI catalog export: metadata declares {expected_count} classes "
            f"but {len(classes)} were loaded. Run `npm run assemble:catalog` in "
            "agent-security-index and point Vibe at the generated export."
        )

    classes.sort(key=lambda row: str(row.get("id", "")))
    digest = hashlib.sha256()
    for source_file in sorted(source_files, key=lambda item: item.name):
        digest.update(source_file.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(source_file.read_bytes())
        digest.update(b"\0")
    return {
        "metadata": metadata,
        "classes": classes,
        "source": str(source),
        "source_hash": f"sha256:{digest.hexdigest()}",
        "source_files": [str(item) for item in source_files],
    }


def _protocol_observations(report: Any) -> dict[str, list[dict[str, Any]]]:
    """Return explicit repository evidence for each supported protocol family."""
    observations: dict[str, list[dict[str, Any]]] = {}
    categories = report.ai_inventory.get("categories", {})

    def add(protocol: str, category: str, item: dict[str, Any], reason: str) -> None:
        row = {
            "evidence_type": "REPOSITORY_FINDING",
            "category": category,
            "finding_id": item.get("id"),
            "file": item.get("file"),
            "reason": reason,
        }
        if row not in observations.setdefault(protocol, []):
            observations[protocol].append(row)

    for category, items in categories.items():
        for item in items:
            if category in {"ai_usage", "tool_agent"}:
                add("Native", category, item, "Native model/tool integration evidence observed.")
            if category == "mcp":
                add("MCP", category, item, "MCP-specific repository evidence observed.")
            if category == "rag_retrieval":
                add("RAG", category, item, "Retrieval/RAG repository evidence observed.")

            searchable = " ".join(
                str(item.get(key, "")) for key in ("name", "evidence", "file")
            )
            if re.search(r"(?i)\ba2a\b|agent[ -]?card", searchable):
                add("A2A", category, item, "A2A or Agent Card evidence observed.")
            if re.search(r"(?i)agent network protocol|\banp\b", searchable):
                add("ANP", category, item, "ANP-specific evidence observed.")
            if re.search(r"(?i)(?:^|[/\\])skills?(?:[/\\]|$)|skill\.md|agent[ -]?skill", searchable):
                add("Skills", category, item, "Agent-skill artifact evidence observed.")

    for rows in observations.values():
        rows.sort(key=lambda row: (str(row.get("file")), str(row.get("finding_id"))))
    return dict(sorted(observations.items()))


def _control_statuses(report: Any) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for status, controls in report.controls.get("by_status", {}).items():
        for control in controls:
            cid = str(control.get("control_id", ""))
            if cid:
                result[cid] = {
                    "status": status,
                    "name": control.get("name"),
                    "confidence": control.get("confidence"),
                    "related_finding_ids": list(control.get("related_finding_ids", [])),
                    "related_dataflow_ids": list(control.get("related_dataflow_ids", [])),
                }
    return result


def _mitigation_to_controls() -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for control_id, mitigation_ids in _CONTROL_TO_ASI_MITIGATIONS.items():
        for mitigation_id in mitigation_ids:
            result.setdefault(mitigation_id, []).append(control_id)
    return result


def _mapped_control_evidence(
    control_ids: list[str], controls: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    """Return every mapped control independently; never collapse contradictions."""
    evidence: list[dict[str, Any]] = []
    for control_id in sorted(control_ids):
        control = controls.get(control_id)
        if not control:
            continue
        status = str(control.get("status", "UNKNOWN"))
        evidence.append(
            {
                "control_id": control_id,
                "control_name": control.get("name"),
                "repository_status": status,
                "confidence": control.get("confidence"),
                "related_finding_ids": list(control.get("related_finding_ids", [])),
                "related_dataflow_ids": list(control.get("related_dataflow_ids", [])),
            }
        )
    return evidence


def _risk_rows_for_class(report: Any, class_id: str, applicable: bool) -> list[dict[str, Any]]:
    mapped: list[dict[str, Any]] = []
    for scenario in report.risks.get("scenarios", []):
        category = str(scenario.get("category", ""))
        if class_id not in _RISK_CATEGORY_TO_AAC.get(category, ()):
            continue
        # AAC-16 specifically concerns MCP STDIO; a generic shell path is not enough.
        if class_id == "AAC-16" and not applicable:
            continue
        row = {
            "risk_id": scenario.get("risk_id"),
            "category": category,
            "evidence_strength": scenario.get("evidence_strength", scenario.get("confidence")),
            "evidence_class": list(scenario.get("evidence_class", [])),
            "reachability_status": scenario.get("reachability_status", "NOT_ESTABLISHED"),
            "unresolved_assumptions": list(scenario.get("unresolved_assumptions", [])),
            "related_finding_ids": list(scenario.get("related_finding_ids", [])),
            "related_dataflow_ids": list(scenario.get("related_dataflow_ids", [])),
        }
        # Legacy numeric policy outputs are propagated only when the caller
        # explicitly built an experimental-scoring report.
        if "score" in scenario:
            row["score"] = scenario["score"]
        if "severity" in scenario:
            row["severity"] = scenario["severity"]
        mapped.append(row)
    return mapped


def map_report_to_asi(report: Any, catalog: dict[str, Any]) -> dict[str, Any]:
    """Map one report to ASI without collapsing independent evidence axes."""
    protocol_observations = _protocol_observations(report)
    protocols = sorted(protocol_observations)
    protocol_set = set(protocol_observations)
    controls = _control_statuses(report)
    mitigation_controls = _mitigation_to_controls()

    counts = {
        "applicable": 0,
        "applicability_not_established": 0,
        "class_evidence_observed": 0,
        "class_evidence_not_observed": 0,
        "manual_review_required": 0,
        "manual_review_deferred": 0,
    }
    rows: list[dict[str, Any]] = []

    for attack_class in catalog["classes"]:
        class_id = str(attack_class.get("id", ""))
        class_protocols = [str(p) for p in attack_class.get("protocols", [])]
        matched_protocols = sorted(protocol_set.intersection(class_protocols))
        applicable = bool(matched_protocols)
        applicability_basis = [
            {
                "basis_type": "PROTOCOL_EVIDENCE",
                "protocol": protocol,
                "observations": protocol_observations[protocol],
            }
            for protocol in matched_protocols
        ]
        if applicable:
            counts["applicable"] += 1
        else:
            counts["applicability_not_established"] += 1

        mapped_risks = _risk_rows_for_class(report, class_id, applicable)
        class_evidence_status = "OBSERVED" if mapped_risks else "NOT_OBSERVED"
        counts[f"class_evidence_{class_evidence_status.lower()}"] += 1
        proposed = [str(mid) for mid in attack_class.get("proposedMitigationIds", [])]
        mitigation_evidence: list[dict[str, Any]] = []
        for mitigation_id in proposed:
            control_evidence = _mapped_control_evidence(
                mitigation_controls.get(mitigation_id, []), controls
            )
            mitigation_evidence.append(
                {
                    "mitigation_id": mitigation_id,
                    "mapped_controls": control_evidence,
                    "mapping_basis": "STATIC_CONTROL_TO_MITIGATION_CROSSWALK",
                    "review_status": "REQUIRED" if control_evidence else "UNASSESSED",
                    "note": (
                        "Each control status is shown independently. Repository evidence does "
                        "not validate mitigation implementation or effectiveness for this class."
                    ),
                }
            )

        unresolved = [
            "Static repository review does not establish runtime exposure, exploitability, or attack presence.",
            "Mapped control artifacts do not establish mitigation enforcement or effectiveness.",
        ]
        if applicable:
            unresolved.append(
                "Protocol evidence establishes technical applicability only, not class-specific exposure."
            )
        else:
            unresolved.append(
                "No supported protocol evidence established applicability; external or deployed configuration was not assessed."
            )
        if not mapped_risks:
            unresolved.append("No class-specific Vibe evidence bridge was observed.")

        if applicable or mapped_risks:
            review_status = "REQUIRED"
            review_reason = "Applicability or class-specific evidence requires analyst disposition."
            counts["manual_review_required"] += 1
        else:
            review_status = "DEFERRED"
            review_reason = "Applicability was not established by supported repository evidence."
            counts["manual_review_deferred"] += 1

        rows.append(
            {
                "id": class_id,
                "name": attack_class.get("name"),
                "family": attack_class.get("family") or attack_class.get("vector"),
                "protocols": class_protocols,
                "evidence_tier": attack_class.get("evidenceTier"),
                "catalog_decision": attack_class.get("decision"),
                "applicability": {
                    "status": "APPLICABLE" if applicable else "NOT_ESTABLISHED",
                    "matched_protocols": matched_protocols,
                    "basis": applicability_basis,
                },
                "class_evidence": {
                    "status": class_evidence_status,
                    "attack_detection": "NOT_PERFORMED",
                    "mapped_concerns": mapped_risks,
                },
                "mitigation_evidence": mitigation_evidence,
                "unresolved_assumptions": unresolved,
                "manual_review": {"status": review_status, "reason": review_reason},
            }
        )

    metadata = catalog.get("metadata", {})
    independent_review = metadata.get("independentReview", {}) if isinstance(metadata, dict) else {}
    return {
        "schema_version": SCHEMA_VERSION,
        "repository": report.metadata.get("repository"),
        "assessment_completeness": report.metadata.get("assessment_completeness"),
        "catalog": {
            "source": catalog.get("source"),
            "source_hash": catalog.get("source_hash"),
            "version": metadata.get("version") if isinstance(metadata, dict) else None,
            "status": metadata.get("status") if isinstance(metadata, dict) else None,
            "independent_review": independent_review,
        },
        "detected_protocols": protocols,
        "protocol_evidence": protocol_observations,
        "summary": {"class_count": len(rows), **counts},
        "classes": rows,
        "limitations": [
            "This is a static repository-evidence mapping, not runtime attack detection.",
            "NOT_ESTABLISHED applicability is not a claim that the class is impossible.",
            "Mitigation mappings preserve every control status and do not aggregate them into a class verdict.",
            "Only explicit Vibe-to-ASI evidence bridges are used; protocol compatibility alone never becomes a control gap.",
        ],
    }
