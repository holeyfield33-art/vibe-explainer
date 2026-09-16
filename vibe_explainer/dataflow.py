"""Bounded static relationships between discovered AI findings.

Emitted edges require Python AST def-use, a consumed direct-import symbol, or a
direct imported-call argument. Category-compatible candidates lacking structural
evidence are retained with explicit unresolved reasons.

WHAT THIS IS NOT:
- Not runtime proof, a control-flow graph, or general taint tracking.
- Not support for dynamic dispatch, reflection, framework injection, or arbitrary
  interprocedural flow.

STATUS VOCABULARY
This module works with three statuses, but in practice only ever emits one:

  STRUCTURALLY_INFERRED - a bounded AST def-use/import-supported relationship.
                          This is the only status emitted for edges.
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

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .ai_discovery import AIFinding, DiscoveryResult, _read_text
from .security_utils import redact_secrets

# Proximity threshold: two findings farther apart than this (same file) are not
# considered for a relationship at all — this is the line between "moderate
# confidence" and "no evidence", not a soft cutoff.
MAX_DATAFLOW_LINE_DISTANCE = 30

# Within-threshold distance below which a relationship is "high" confidence
# (proxy for "tight coupling" in the absence of real syntactic/AST evidence).
# Beyond this and up to MAX_DATAFLOW_LINE_DISTANCE, confidence is "moderate".
HIGH_CONFIDENCE_LINE_DISTANCE = 10

STATUS_INFERRED = "STRUCTURALLY_INFERRED"
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


def _confidence_for_distance(distance: int) -> str:  # pragma: no cover - legacy compatibility
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
    resolution_method: str = "PYTHON_DEF_USE"
    source_file: str = ""  # populated for cross-file edges
    destination_file: str = ""

    def __post_init__(self) -> None:
        # Guaranteed redaction at construction, not left to whichever call
        # site happens to remember it — evidence strings are built from
        # finding names/categories today but this must hold even if a future
        # caller passes through raw source text.
        self.evidence = redact_secrets(self.evidence)

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
            "resolution_method": self.resolution_method,
            "source_file": self.source_file or self.file,
            "destination_file": self.destination_file or self.file,
        }


@dataclass
class DataFlowGraph:
    root: str
    nodes: list[str] = field(default_factory=list)  # all discovery finding ids
    edges: list[DataFlowObservation] = field(default_factory=list)
    truncated: list[dict[str, Any]] = field(default_factory=list)  # pass-through, not lost
    unresolved: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "nodes": list(self.nodes),
            "edges": [e.to_dict() for e in self.edges],
            "truncated": list(self.truncated),
            "unresolved": list(self.unresolved),
            "summary": {
                "node_count": len(self.nodes),
                "edge_count": len(self.edges),
                "unresolved_count": len(self.unresolved),
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


def _build_proximity_dataflow_legacy(  # pragma: no cover - retained for pre-2.0 compatibility
    discovery: DiscoveryResult,
) -> DataFlowGraph:
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

    # ---- Phase 8G: bounded cross-file edges via resolved imports ----------
    # When file A imports file B (resolved via the AST/regex symbol index) and a
    # source-category finding in A pairs with a destination-category finding in B,
    # emit a cross-file edge. This is BOUNDED STATIC INFERENCE, not proven data
    # flow: an import establishes that A can reach B's symbols, not that data
    # actually flows along this specific pair. Confidence is therefore capped at
    # moderate (never high) for import-resolved edges, per the resolution model.
    imports_by_file = getattr(discovery, "imports_by_file", {}) or {}
    by_file_cat_only: dict[tuple[str, str], list[AIFinding]] = by_file_category
    for source_cat, dest_cat in _RULE_PAIRS:
        for importer, imported_files in imports_by_file.items():
            source_candidates = by_file_cat_only.get((importer, source_cat), [])
            if not source_candidates:
                continue
            for imported in imported_files:
                dest_findings = by_file_cat_only.get((imported, dest_cat), [])
                if not dest_findings:
                    continue
                # deterministic representative pick: lowest-line finding on each side
                src = min(source_candidates, key=lambda f: (f.line, f.id))
                dest = min(dest_findings, key=lambda f: (f.line, f.id))
                relationship = _relationship_name(src, dest)
                edge_key = (src.id, dest.id, relationship)
                if edge_key in seen_edges:
                    continue
                seen_edges.add(edge_key)
                evidence = (
                    f"{importer} imports {imported}; {src.category}:{src.name} in the "
                    f"importer pairs with {dest.category}:{dest.name} in the imported "
                    f"module. Bounded static inference from import resolution — not a "
                    f"proven runtime data flow."
                )
                edges.append(
                    DataFlowObservation(
                        source_finding_id=src.id,
                        destination_finding_id=dest.id,
                        source_type=src.category,
                        destination_type=dest.category,
                        relationship=relationship,
                        file=importer,
                        source_line=src.line,
                        destination_line=dest.line,
                        confidence="moderate",
                        evidence=evidence,
                        status=STATUS_INFERRED,
                        resolution_method="IMPORT",
                        source_file=importer,
                        destination_file=imported,
                    )
                )

    edges.sort(key=_edge_sort_key)
    graph.edges = edges
    return graph


@dataclass
class _PythonFacts:
    tree: ast.AST
    statements: list[ast.stmt]
    functions: list[ast.AST]
    definitions: dict[ast.AST, list[tuple[int, set[str], set[str]]]]


def _node_span(node: ast.AST) -> tuple[int, int]:
    return getattr(node, "lineno", 1), getattr(node, "end_lineno", getattr(node, "lineno", 1))


def _scope_for(facts: _PythonFacts, line: int) -> ast.AST:
    scopes = [n for n in facts.functions if _node_span(n)[0] <= line <= _node_span(n)[1]]
    return min(scopes, key=lambda n: _node_span(n)[1] - _node_span(n)[0]) if scopes else facts.tree


def _statement_for(facts: _PythonFacts, line: int) -> ast.stmt | None:
    nodes = [n for n in facts.statements if _node_span(n)[0] <= line <= _node_span(n)[1]]
    return min(nodes, key=lambda n: _node_span(n)[1] - _node_span(n)[0]) if nodes else None


def _stored_names(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}


def _loaded_names(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}


def _call_inputs(statement: ast.stmt | None) -> set[str]:
    if statement is None:
        return set()
    result: set[str] = set()
    for call in (n for n in ast.walk(statement) if isinstance(n, ast.Call)):
        for value in [*call.args, *(kw.value for kw in call.keywords)]:
            result.update(_loaded_names(value))
    return result


def _parse_python_facts(root: Path, files: set[str]) -> dict[str, _PythonFacts]:
    parsed: dict[str, _PythonFacts] = {}
    for rel in sorted(files):
        if Path(rel).suffix.lower() != ".py":
            continue
        text = _read_text(root / rel)
        if text is None:
            continue
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError):
            continue
        statements = [n for n in ast.walk(tree) if isinstance(n, ast.stmt)]
        functions = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))]
        facts = _PythonFacts(tree, statements, functions, {})
        for scope in [tree, *functions]:
            rows: list[tuple[int, set[str], set[str]]] = []
            for statement in statements:
                if _scope_for(facts, _node_span(statement)[0]) is not scope:
                    continue
                targets = _stored_names(statement)
                if targets:
                    rows.append((_node_span(statement)[0], targets, _loaded_names(statement) - targets))
            facts.definitions[scope] = sorted(rows, key=lambda row: row[0])
        parsed[rel] = facts
    return parsed


def _dependency_closure(facts: _PythonFacts, scope: ast.AST, names: set[str], before_line: int) -> set[str]:
    closure = set(names)
    changed = True
    while changed:
        changed = False
        for line, targets, dependencies in facts.definitions.get(scope, []):
            if line > before_line or not (targets & closure):
                continue
            additions = dependencies - closure
            if additions:
                closure.update(additions)
                changed = True
    return closure


def _same_file_basis(facts: _PythonFacts, source: AIFinding, dest: AIFinding) -> tuple[bool, set[str], str]:
    source_scope = _scope_for(facts, source.line)
    dest_scope = _scope_for(facts, dest.line)
    if source_scope is not dest_scope and source_scope is not facts.tree:
        return False, set(), "DIFFERENT_FUNCTION_SCOPE"
    source_statement = _statement_for(facts, source.line)
    dest_statement = _statement_for(facts, dest.line)
    if source_statement is None or dest_statement is None:
        return False, set(), "NO_ENCLOSING_STATEMENT"
    if source_statement is dest_statement:
        return True, {"same-call"}, "SAME_CALL_CONFIGURATION"
    if source.line > dest.line:
        return False, set(), "NON_DIRECTIONAL_ORDER"
    outputs = _stored_names(source_statement)
    if not outputs:
        return False, set(), "SOURCE_VALUE_NOT_BOUND"
    inputs = _call_inputs(dest_statement)
    dependencies = _dependency_closure(facts, dest_scope, inputs, dest.line)
    shared = outputs & dependencies
    return (bool(shared), shared, "SHARED_DEF_USE" if shared else "NO_SHARED_VALUE_OR_SYMBOL")


def _import_symbol_map(discovery: DiscoveryResult, facts_by_file: dict[str, _PythonFacts]) -> dict[str, dict[str, tuple[str, str]]]:
    result: dict[str, dict[str, tuple[str, str]]] = {}
    imports_by_file = getattr(discovery, "imports_by_file", {}) or {}
    for importer, imported_files in imports_by_file.items():
        facts = facts_by_file.get(importer)
        if not facts:
            continue
        for node in ast.walk(facts.tree):
            if not isinstance(node, ast.ImportFrom):
                continue
            candidates = [f for f in imported_files if Path(f).stem == (node.module or "").split(".")[-1]]
            if len(candidates) != 1:
                continue
            for alias in node.names:
                local_name = alias.asname or alias.name
                result.setdefault(importer, {})[local_name] = (candidates[0], alias.name)
    # Collapse simple ``from x import y`` re-export chains to their defining file.
    for _ in range(len(result) + 1):
        changed = False
        for importer, symbols in result.items():
            for local_name, (target_file, target_name) in list(symbols.items()):
                origin = result.get(target_file, {}).get(target_name)
                if origin and origin != (target_file, target_name):
                    symbols[local_name] = origin
                    changed = True
        if not changed:
            break
    return result


def _imported_call_basis(
    source: AIFinding,
    dest: AIFinding,
    facts_by_file: dict[str, _PythonFacts],
    import_symbols: dict[str, dict[str, tuple[str, str]]],
) -> set[str]:
    source_facts = facts_by_file.get(source.file)
    dest_facts = facts_by_file.get(dest.file)
    if not source_facts or not dest_facts:
        return set()
    source_statement = _statement_for(source_facts, source.line)
    outputs = _stored_names(source_statement) if source_statement else set()
    if not outputs:
        return set()
    dest_scope = _scope_for(dest_facts, dest.line)
    dest_name = getattr(dest_scope, "name", None)
    if not dest_name:
        return set()
    scope = _scope_for(source_facts, source.line)
    for statement in source_facts.statements:
        line = _node_span(statement)[0]
        if line < source.line or _scope_for(source_facts, line) is not scope:
            continue
        for call in (n for n in ast.walk(statement) if isinstance(n, ast.Call)):
            if not isinstance(call.func, ast.Name):
                continue
            imported = import_symbols.get(source.file, {}).get(call.func.id)
            if imported != (dest.file, dest_name):
                continue
            inputs = set()
            for value in [*call.args, *(kw.value for kw in call.keywords)]:
                inputs.update(_loaded_names(value))
            dependencies = _dependency_closure(source_facts, scope, inputs, line)
            shared = outputs & dependencies
            if shared:
                return shared
    return set()


def build_dataflow(discovery: DiscoveryResult) -> DataFlowGraph:
    """Build bounded Python def-use relationships; retain ambiguity explicitly."""
    graph = DataFlowGraph(root=discovery.root)
    eligible = discovery.conclusion_findings()
    graph.nodes = sorted({f.id for f in eligible})
    graph.truncated = [t.to_dict() for t in discovery.truncated]
    files = {f.file for f in eligible}
    for importer, imported in (getattr(discovery, "imports_by_file", {}) or {}).items():
        files.add(importer)
        files.update(imported)
    facts_by_file = _parse_python_facts(Path(discovery.root), files)
    import_symbols = _import_symbol_map(discovery, facts_by_file)
    seen: set[tuple[str, str, str]] = set()

    for source_cat, dest_cat in _RULE_PAIRS:
        sources = [f for f in eligible if f.category == source_cat]
        destinations = [f for f in eligible if f.category == dest_cat]
        for source in sources:
            for dest in destinations:
                basis: set[str] = set()
                reason = "UNSUPPORTED_LANGUAGE_OR_PARSE"
                method = "PYTHON_DEF_USE"
                established = False
                if source.file == dest.file and source.file in facts_by_file:
                    established, basis, reason = _same_file_basis(facts_by_file[source.file], source, dest)
                elif source.file != dest.file and dest.file in facts_by_file:
                    dest_facts = facts_by_file[dest.file]
                    dest_statement = _statement_for(dest_facts, dest.line)
                    dest_scope = _scope_for(dest_facts, dest.line)
                    inputs = _dependency_closure(dest_facts, dest_scope, _call_inputs(dest_statement), dest.line)
                    imported = import_symbols.get(dest.file, {})
                    shared = {
                        local for local in inputs
                        if local in imported and imported[local][0] == source.file
                    }
                    source_statement = _statement_for(facts_by_file.get(source.file), source.line) if source.file in facts_by_file else None
                    source_outputs = _stored_names(source_statement) if source_statement else set()
                    matched = {local for local in shared if imported[local][1] in source_outputs}
                    established = bool(matched)
                    basis = matched
                    reason = "IMPORTED_SYMBOL_DEF_USE" if matched else "NO_SHARED_IMPORTED_SYMBOL"
                    method = "PYTHON_IMPORT_SYMBOL"
                    if not established:
                        called = _imported_call_basis(
                            source, dest, facts_by_file, import_symbols
                        )
                        if called:
                            established = True
                            basis = called
                            reason = "IMPORTED_CALL_ARGUMENT_DEF_USE"
                            method = "PYTHON_IMPORT_CALL"
                else:
                    continue

                relationship = _relationship_name(source, dest)
                if not established:
                    graph.unresolved.append({
                        "source_finding_id": source.id,
                        "destination_finding_id": dest.id,
                        "relationship": relationship,
                        "reason": reason,
                    })
                    continue
                edge_key = (source.id, dest.id, relationship)
                if edge_key in seen:
                    continue
                seen.add(edge_key)
                basis_text = ", ".join(sorted(basis))
                graph.edges.append(DataFlowObservation(
                    source_finding_id=source.id,
                    destination_finding_id=dest.id,
                    source_type=source.category,
                    destination_type=dest.category,
                    relationship=relationship,
                    file=dest.file,
                    source_line=source.line,
                    destination_line=dest.line,
                    confidence="high" if method == "PYTHON_DEF_USE" else "moderate",
                    evidence=f"Bounded structural relationship via {reason}: {basis_text}.",
                    status=STATUS_INFERRED,
                    resolution_method=method,
                    source_file=source.file,
                    destination_file=dest.file,
                ))

    graph.edges.sort(key=_edge_sort_key)
    graph.unresolved.sort(key=lambda row: (
        row["relationship"], row["source_finding_id"], row["destination_finding_id"]
    ))
    return graph
