"""Offline structural scan of a repository.

Produces a structured snapshot the synthesizer / report layer can turn into
a human-readable mental model. No network, no LLM — pure filesystem + heuristics.
"""

from __future__ import annotations

import os
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SKIP_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    ".next",
    "target",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    "coverage",
    ".coverage",
    "vendor",
    "third_party",
}

CODE_EXTS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".go",
    ".rs",
    ".java",
    ".rb",
    ".c",
    ".cpp",
    ".h",
    ".cs",
    ".php",
    ".swift",
    ".kt",
}

ENTRY_POINT_NAMES = {
    "main.py",
    "app.py",
    "server.py",
    "cli.py",
    "index.js",
    "index.ts",
    "index.tsx",
    "main.go",
    "main.rs",
    "manage.py",
    "wsgi.py",
    "asgi.py",
    "app.js",
    "app.ts",
    "server.js",
    "server.ts",
}

MANIFEST_NAMES = {
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "setup.py",
    "Cargo.toml",
    "go.mod",
    "pom.xml",
    "build.gradle",
    "Gemfile",
    "composer.json",
}


@dataclass
class FileInfo:
    rel_path: str
    size_bytes: int
    lines: int
    ext: str


@dataclass
class ScanResult:
    root: str
    files: list[FileInfo] = field(default_factory=list)
    entry_points: list[str] = field(default_factory=list)
    manifests: list[str] = field(default_factory=list)
    top_dirs: list[tuple[str, int]] = field(default_factory=list)  # (dir, file_count)
    by_ext: dict[str, int] = field(default_factory=dict)
    largest_files: list[FileInfo] = field(default_factory=list)
    readme_paths: list[str] = field(default_factory=list)
    total_code_files: int = 0
    total_lines: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "total_code_files": self.total_code_files,
            "total_lines": self.total_lines,
            "entry_points": self.entry_points,
            "manifests": self.manifests,
            "top_dirs": self.top_dirs,
            "by_ext": self.by_ext,
            "largest_files": [
                {"path": f.rel_path, "lines": f.lines, "size_bytes": f.size_bytes}
                for f in self.largest_files
            ],
            "readme_paths": self.readme_paths,
        }


def _should_skip_dir(name: str) -> bool:
    return name in SKIP_DIRS or name.startswith(".")


def _count_lines(path: Path) -> int:
    try:
        with path.open("rb") as f:
            # cheap line count; ignore decode errors
            return sum(1 for _ in f)
    except OSError:
        return 0


def scan_repo(root: str | Path, max_files: int = 5000) -> ScanResult:
    """Walk *root* and return a structural snapshot."""
    root_path = Path(root).resolve()
    if not root_path.is_dir():
        raise NotADirectoryError(f"Not a directory: {root}")

    result = ScanResult(root=str(root_path))
    dir_counts: dict[str, int] = defaultdict(int)
    files: list[FileInfo] = []

    for dirpath, dirnames, filenames in os.walk(root_path):
        # prune in-place
        dirnames[:] = [d for d in dirnames if not _should_skip_dir(d)]

        rel_dir = os.path.relpath(dirpath, root_path)
        if rel_dir == ".":
            rel_dir = ""

        for name in filenames:
            full = Path(dirpath) / name
            rel = str(Path(rel_dir) / name) if rel_dir else name
            rel = rel.replace("\\", "/")

            lower = name.lower()
            if lower in ("readme.md", "readme.rst", "readme.txt", "readme"):
                result.readme_paths.append(rel)

            if name in MANIFEST_NAMES or lower in MANIFEST_NAMES:
                result.manifests.append(rel)

            if name in ENTRY_POINT_NAMES or lower in ENTRY_POINT_NAMES:
                result.entry_points.append(rel)

            ext = full.suffix.lower()
            if ext not in CODE_EXTS:
                continue

            try:
                size = full.stat().st_size
            except OSError:
                continue
            if size > 2_000_000:  # skip huge files (same spirit as vibe-check)
                continue

            lines = _count_lines(full)
            info = FileInfo(rel_path=rel, size_bytes=size, lines=lines, ext=ext)
            files.append(info)
            result.by_ext[ext] = result.by_ext.get(ext, 0) + 1
            result.total_lines += lines

            top = rel.split("/")[0] if "/" in rel else "(root)"
            dir_counts[top] += 1

            if len(files) >= max_files:
                break
        if len(files) >= max_files:
            break

    result.files = files
    result.total_code_files = len(files)
    result.largest_files = sorted(files, key=lambda f: f.lines, reverse=True)[:15]
    result.top_dirs = sorted(dir_counts.items(), key=lambda x: x[1], reverse=True)[:12]

    # de-dupe entry points / manifests while preserving order
    result.entry_points = list(dict.fromkeys(result.entry_points))
    result.manifests = list(dict.fromkeys(result.manifests))
    result.readme_paths = list(dict.fromkeys(result.readme_paths))

    return result
