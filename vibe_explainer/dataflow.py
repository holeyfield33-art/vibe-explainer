"""Static AI data-flow observation.

Connects AIFinding objects already produced by ai_discovery.py into a graph of
plausible relationships, using conservative same-file line-proximity heuristics.

WHAT THIS IS NOT:
- Not program analysis. No AST parsing, no control-flow graph, no import
  resolution, no taint tracking, no execution.
- Not proof. An edge means "these two pieces of evidence sit near each other
  in the same file and their categories match a documented rule" — nothing
  more. It does not mean data actually flows between them at runtime.

STATUS VOCABULARY
This module works with three statuses, but in practice only ever emits one:

  INFERRED - a same-file, category-paired, proximity-supported relationship.
             This is the *only* status this module produces.
  OBSERVED - reserved for a stronger evidentiary standard (e.g. execution
             tracing, instrumented runs) that this static-analysis phase does
             not implement. Never emitted here — emitting it would misrepresent
             an inference as a confirmed runtime flow.
  UNKNOWN  - reserved for "a relationship is suspected but there isn't enough
             evidence to classify it". Also never emitted here: per the
             detection rules below, insufficient evidence means *no edge is
             produced at all*, not an UNKNOWN edge. Inventing an UNKNOWN edge
             just because two components co-exist is exactly the kind of
             overclaiming this phase is designed to avoid.

CONFIDENCE
Two tiers only — "high" and "moderate". "low" is intentionally never emitted:
a proximity-only heuristic beyond the "moderate" range has crossed into
insufficient-evidence territory, where the correct action is no observation,
not a low-confidence edge produced just to increase coverage.

SCOPE (see docs/PHASE-3-DATA-FLOW.md for the full rationale)
Implemented relationships, all same-file only:
  prompt_surface  -> ai_usage              "feeds_prompt"
  rag_retrieval   -> ai_usage              "retrieved_context"
  ai_usage        -> tool_agent            "invokes_tool" (or "flows_to_output"
                                             for shell/eval-execution findings)
  ai_usage        -> external_integration  "calls_external_service"
  secret_config   -> model_provider        "reads_storage"
  secret_config   -> ai_usage              "reads_storage"

NOT implemented this phase (documented, not silently skipped):
  user_input -> prompt_surface   — no "user_input" discovery category exists
                                    yet; would require new Phase 1 detector
                                    work, out of scope here.
  cross-file relationships       — would require import-graph resolution,
                                    explicitly deferred.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .ai_discovery import AIFinding, DiscoveryResult

# Proximity threshold: two findings farther apart than this (same file) are not
# considered for a relationship at all — this is the line between "moderate
# confidence" and "no evidence", not a soft cutoff.
MAX_DATAFLOW_LINE_DISTANCE = 30

# Within-threshold distance below which a relationship is "high" confidence
# (proxy for "tight coupling" in the absence of real syntactic/AST evidence).
# Beyond this and up to MAX_DATAFLOW_LINE_DISTANCE, confidence is "moderate".
HIGH_CONFIDENCE_LINE_DISTANCE = 10

STATUS_INFERRED = "INFERRED"
STATUS_OBSERVED = "OBSERVED"  # reserved, unused this phase — see module docstring
STATUS_UNKNOWN = "UNKNOWN"  # reserved, unused this phase — see module docstring

# Ordered (source_category, destination_category) rule pairs this phase supports.
_RULE_PAIRS: list[tuple[str, str]] = [
    ("prompt_surface", "ai_usage"),
    ("rag_retrieval", "ai_usage"),
    ("ai_usage", "tool_agent"),
    ("ai_usage", "external_integration"),
    ("secret_config", "model_provider"),
    ("secret_config", "ai_usage"),
]

_SINK_TOOL_NAMES = {"Shell execution", "Dynamic code execution"}


def _relationship_name(source: AIFinding, dest: AIFinding) -> str:
    pair = (source.category, dest.category)
    if pair == ("prompt_surface", "ai_usage"):
        return "feeds_prompt"
    if pair == ("rag_retrieval", "ai_usage"):
        return "retrieved_context"
    if pair == ("ai_usage", "tool_agent"):
        return "flows_to_output" if dest.name in _SINK_TOOL_NAMES else "invokes_tool"
    if pair == ("ai_usage", "external_integration"):
        return "calls_external_service"
    if pair in {("secret_config", "model_provider"), ("secret_config", "ai_usage")}:
        return "reads_storage"
    raise ValueError(f"No relationship rule documented for pair {pair}")  # pragma: no cover


def _confidence_for_distance(distance: int) -> str:
    if distance <= HIGH_CONFIDENCE_LINE_DISTANCE:
        return "high"
    return "moderate"


@dataclass
class DataFlowObservation:
    source_finding_id: str
    destination_finding_id: str
    source_type: str
    destination_type: str
    relationship: str
    file: str
    source_line: int
    destination_line: int
    confidence: str
    evidence: str
    status: str = STATUS_INFERRED

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_finding_id": self.source_finding_id,
            "destination_finding_id": self.destination_finding_id,
            "source_type": self.source_type,
            "destination_type": self.destination_type,
            "relationship": self.relationship,
            "file": self.file,
            "source_line": self.source_line,
            "destination_line": self.destination_line,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "status": self.status,
        }


@dataclass
class DataFlowGraph:
    root: str
    nodes: list[str] = field(default_factory=list)  # all discovery finding ids
    edges: list[DataFlowObservation] = field(default_factory=list)
    truncated: list[dict[str, Any]] = field(default_factory=list)  # pass-through, not lost

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "nodes": list(self.nodes),
            "edges": [e.to_dict() for e in self.edges],
            "truncated": list(self.truncated),
            "summary": {
                "node_count": len(self.nodes),
                "edge_count": len(self.edges),
            },
        }


def _edge_sort_key(edge: DataFlowObservation) -> tuple:
    return (
        edge.file,
        min(edge.source_line, edge.destination_line),
        edge.relationship,
        edge.source_finding_id,
        edge.destination_finding_id,
    )


def build_dataflow(discovery: DiscoveryResult) -> DataFlowGraph:
    """Build a static data-flow graph from a DiscoveryResult.

    Deterministic: given the same set of findings, produces the same nodes,
    edges, confidence, and ordering regardless of the filesystem traversal
    order that produced those findings (edges are sorted at the end; findings
    are grouped by their own file/category/line fields, not by list order).
    """
    graph = DataFlowGraph(root=discovery.root)
    graph.nodes = sorted({f.id for f in discovery.findings})
    graph.truncated = [t.to_dict() for t in discovery.truncated]

    # index findings by (file, category) for cheap same-file/category lookup
    by_file_category: dict[tuple[str, str], list[AIFinding]] = {}
    for finding in discovery.findings:
        by_file_category.setdefault((finding.file, finding.category), []).append(finding)

    seen_edges: set[tuple[str, str, str]] = set()  # (source_id, dest_id, relationship)
    edges: list[DataFlowObservation] = []

    for source_cat, dest_cat in _RULE_PAIRS:
        for (file, cat), dest_findings in by_file_category.items():
            if cat != dest_cat:
                continue
            candidates = by_file_category.get((file, source_cat), [])
            if not candidates:
                continue
            for dest in dest_findings:
                # nearest same-file candidate within threshold; deterministic
                # tie-break on (distance, source_line, source_id)
                best: AIFinding | None = None
                best_key: tuple[int, int, str] | None = None
                for cand in candidates:
                    distance = abs(cand.line - dest.line)
                    if distance > MAX_DATAFLOW_LINE_DISTANCE:
                        continue
                    key = (distance, cand.line, cand.id)
                    if best_key is None or key < best_key:
                        best_key = key
                        best = cand
                if best is None:
                    continue  # insufficient evidence -> no observation, per spec

                relationship = _relationship_name(best, dest)
                edge_key = (best.id, dest.id, relationship)
                if edge_key in seen_edges:
                    continue
                seen_edges.add(edge_key)

                distance = abs(best.line - dest.line)
                confidence = _confidence_for_distance(distance)
                evidence = (
                    f"{best.category}:{best.name} at line {best.line} is "
                    f"{distance} line(s) from {dest.category}:{dest.name} "
                    f"at line {dest.line}, both in {file}."
                )

                edges.append(
                    DataFlowObservation(
                        source_finding_id=best.id,
                        destination_finding_id=dest.id,
                        source_type=best.category,
                        destination_type=dest.category,
                        relationship=relationship,
                        file=file,
                        source_line=best.line,
                        destination_line=dest.line,
                        confidence=confidence,
                        evidence=evidence,
                        status=STATUS_INFERRED,
                    )
                )

    edges.sort(key=_edge_sort_key)
    graph.edges = edges
    return graph
