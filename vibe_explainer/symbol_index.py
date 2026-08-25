"""Bounded static cross-file resolution (Phase 8G/8H) via AST for structure.

This is the AST layer. It uses Python's stdlib `ast` to extract FACTS a parser gives
deterministically — imports, top-level symbol definitions, and call sites — and builds
a repository symbol index plus an import graph. For JS/TS (no stdlib parser) it falls
back to regex import extraction, explicitly marked as lower-confidence resolution.

Crucial scope boundary, stated plainly and enforced by the confidence model below:
this is "bounded static cross-file flow inference," NOT proven data flow and NOT taint
tracking. AST is used to resolve *which file/symbol an import or call refers to* — a
structural fact — not to prove that data actually flows along that edge at runtime.
Confidence is never HIGH from mere connection; it reflects how the edge was resolved.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Resolution methods, most to least rigorous.
RES_IMPORT = "IMPORT"            # AST import + resolved to a repo module
RES_LOCAL_SYMBOL = "LOCAL_SYMBOL"  # AST call to a symbol defined in the same repo
RES_SAME_FILE = "SAME_FILE"      # same-file (Phase 3 style)
RES_CONFIG_REFERENCE = "CONFIG_REFERENCE"  # config/env name referenced across files
RES_PROXIMITY = "PROXIMITY"      # weakest — co-location only

# Confidence by resolution method. Never HIGH purely for being connected.
_RESOLUTION_CONFIDENCE = {
    RES_IMPORT: "moderate",        # AST import resolution is solid structurally, but
    #                                an import is not proof of a data path -> moderate
    RES_LOCAL_SYMBOL: "moderate",
    RES_SAME_FILE: "high",         # same-file direct proximity is the strongest we claim
    RES_CONFIG_REFERENCE: "low",
    RES_PROXIMITY: "low",
}

_JS_IMPORT = re.compile(r"""(?:import\s+(?:[\w*{}\s,]+\s+from\s+)?['"]([^'"]+)['"]|require\(\s*['"]([^'"]+)['"]\s*\))""")


@dataclass
class SymbolDef:
    name: str
    file: str
    line: int
    kind: str  # "function" | "class"


@dataclass
class ModuleInfo:
    file: str
    language: str  # "python" | "js"
    imports: list[str] = field(default_factory=list)  # raw import targets
    defined_symbols: list[SymbolDef] = field(default_factory=list)
    called_names: list[tuple[str, int]] = field(default_factory=list)  # (name, line)


@dataclass
class SymbolIndex:
    modules: dict[str, ModuleInfo] = field(default_factory=dict)
    # symbol name -> list of files defining it
    symbol_owners: dict[str, list[str]] = field(default_factory=dict)
    # module path (dotted or relative) -> file
    module_paths: dict[str, str] = field(default_factory=dict)


def _module_key_for_python(rel_path: str) -> str:
    no_ext = rel_path[:-3] if rel_path.endswith(".py") else rel_path
    parts = [p for p in no_ext.split("/") if p and p != "__init__"]
    return ".".join(parts)


def build_symbol_index(analyzed_files: list[tuple[str, str]]) -> SymbolIndex:
    """Build a symbol/import index from (rel_path, content) pairs.

    Only Python is parsed with AST; JS/TS uses regex import extraction. Files that
    fail to parse are skipped gracefully (recorded as no symbols), never crash the
    crawl.
    """
    index = SymbolIndex()
    for rel_path, content in analyzed_files:
        if rel_path.endswith(".py"):
            info = _index_python(rel_path, content)
            index.module_paths[_module_key_for_python(rel_path)] = rel_path
        elif rel_path.endswith((".js", ".jsx", ".ts", ".tsx")):
            info = _index_js(rel_path, content)
        else:
            continue
        index.modules[rel_path] = info
        for sym in info.defined_symbols:
            index.symbol_owners.setdefault(sym.name, []).append(rel_path)
    return index


def _index_python(rel_path: str, content: str) -> ModuleInfo:
    info = ModuleInfo(file=rel_path, language="python")
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return info
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                info.imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                info.imports.append(node.module)
        elif isinstance(node, ast.FunctionDef):
            info.defined_symbols.append(SymbolDef(node.name, rel_path, node.lineno, "function"))
        elif isinstance(node, ast.AsyncFunctionDef):
            info.defined_symbols.append(SymbolDef(node.name, rel_path, node.lineno, "function"))
        elif isinstance(node, ast.ClassDef):
            info.defined_symbols.append(SymbolDef(node.name, rel_path, node.lineno, "class"))
        elif isinstance(node, ast.Call):
            func = node.func
            name = None
            if isinstance(func, ast.Name):
                name = func.id
            elif isinstance(func, ast.Attribute):
                name = func.attr
            if name:
                info.called_names.append((name, getattr(node, "lineno", 0)))
    return info


def _index_js(rel_path: str, content: str) -> ModuleInfo:
    info = ModuleInfo(file=rel_path, language="js")
    for m in _JS_IMPORT.finditer(content):
        target = m.group(1) or m.group(2)
        if target:
            info.imports.append(target)
    return info


def resolve_python_import(importer_file: str, import_target: str, index: SymbolIndex) -> str | None:
    """Resolve a Python import target to a repo file, if it belongs to this repo.

    Only resolves imports that map onto a module we indexed — external packages
    (openai, requests, …) resolve to None, which is correct: they aren't repo files.
    """
    # exact dotted-module match
    if import_target in index.module_paths:
        return index.module_paths[import_target]
    # suffix match: "services.ai" importer resolving "ai" within a package
    for mod_key, f in index.module_paths.items():
        if mod_key.endswith("." + import_target) or mod_key == import_target:
            return f
    return None


def resolve_js_import(importer_file: str, import_target: str, index: SymbolIndex) -> str | None:
    """Resolve a relative JS/TS import (./x, ../y) to a repo file. Bare/package
    imports (react, next/…) resolve to None."""
    if not import_target.startswith("."):
        return None
    base = Path(importer_file).parent
    candidate = (base / import_target).as_posix()
    # normalize .. segments
    parts: list[str] = []
    for seg in candidate.split("/"):
        if seg == "..":
            if parts:
                parts.pop()
        elif seg not in (".", ""):
            parts.append(seg)
    stem = "/".join(parts)
    for ext in (".ts", ".tsx", ".js", ".jsx", "/index.ts", "/index.js"):
        cand = stem + ext
        if cand in index.modules:
            return cand
    # already had extension?
    if stem in index.modules:
        return stem
    return None


def confidence_for_resolution(method: str) -> str:
    return _RESOLUTION_CONFIDENCE.get(method, "low")
