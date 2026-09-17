"""Centralized directory/file exclusion policy (Phase 8B).

One place where "should this path be excluded, and why" is decided, instead of
scattered skip-lists across modules. Every exclusion carries a category, a
human-readable reason, and the rule that produced it, so a crawl can report exactly
why any file was not analyzed — no silent drops.

Critically, this policy excludes only VCS metadata, dependency trees, build output,
and caches. It deliberately does NOT exclude .github, tests, security tests,
examples, fixtures, or docs — those must stay visible to the contextual classifier
(they are evidence, not noise). The previous `name.startswith(".git")` bug that hid
`.github` is explicitly guarded against here with exact-name matching plus a
regression test.
"""

from __future__ import annotations

import os
import stat as stat_module
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

# Category constants for exclusions.
EXCL_VCS = "VCS_METADATA"
EXCL_DEPENDENCY = "DEPENDENCY_TREE"
EXCL_BUILD = "BUILD_ARTIFACT"
EXCL_CACHE = "GENERATED_CACHE"

# Exact directory names to exclude, mapped to (category, reason). Exact-name only —
# never a prefix/startswith check, which is what caused `.github` to be hidden by a
# `.git` rule. `.github` is intentionally absent from this set.
_EXCLUDED_DIRS: dict[str, tuple[str, str]] = {
    ".git": (EXCL_VCS, "Git version-control metadata"),
    ".hg": (EXCL_VCS, "Mercurial version-control metadata"),
    ".svn": (EXCL_VCS, "Subversion version-control metadata"),
    "node_modules": (EXCL_DEPENDENCY, "JavaScript dependency tree"),
    "vendor": (EXCL_DEPENDENCY, "Vendored dependency tree"),
    "third_party": (EXCL_DEPENDENCY, "Third-party dependency tree"),
    ".venv": (EXCL_DEPENDENCY, "Python virtual environment"),
    "venv": (EXCL_DEPENDENCY, "Python virtual environment"),
    "site-packages": (EXCL_DEPENDENCY, "Installed Python packages"),
    "dist": (EXCL_BUILD, "Build output directory"),
    "build": (EXCL_BUILD, "Build output directory"),
    "out": (EXCL_BUILD, "Build output directory"),
    ".next": (EXCL_BUILD, "Next.js build output"),
    "target": (EXCL_BUILD, "Build output directory (Rust/Java)"),
    "__pycache__": (EXCL_CACHE, "Python bytecode cache"),
    ".mypy_cache": (EXCL_CACHE, "mypy type-check cache"),
    ".pytest_cache": (EXCL_CACHE, "pytest cache"),
    ".tox": (EXCL_CACHE, "tox environment cache"),
    ".ruff_cache": (EXCL_CACHE, "ruff cache"),
    "coverage": (EXCL_CACHE, "coverage output"),
    ".coverage": (EXCL_CACHE, "coverage output"),
}

# Public, stable view of the excluded-directory names, for callers (scanner.py's
# SKIP_DIRS re-export) that want the set without reaching into the private dict.
EXCLUDED_DIR_NAMES: frozenset[str] = frozenset(_EXCLUDED_DIRS)

# Directory names that a naive prefix check might wrongly exclude but which MUST
# remain visible. Used only by a regression test, but documented here as intent.
NEVER_EXCLUDE_DIRS = frozenset({
    ".github",  # CI/workflow config — critical readiness evidence
    "tests",
    "test",
    "examples",
    "example",
    "fixtures",
    "docs",
    "doc",
    "security",
})


@dataclass(frozen=True)
class ExclusionResult:
    excluded: bool
    category: str | None = None
    reason: str | None = None
    rule: str | None = None


_NOT_EXCLUDED = ExclusionResult(excluded=False)


def classify_dir_exclusion(dir_name: str) -> ExclusionResult:
    """Decide whether a single directory NAME (not path) should be excluded.

    Exact-name membership only. A name that merely starts with an excluded name
    (e.g. ".github" vs ".git") is NOT excluded — that was the original bug.
    """
    hit = _EXCLUDED_DIRS.get(dir_name)
    if hit is None:
        return _NOT_EXCLUDED
    category, reason = hit
    return ExclusionResult(excluded=True, category=category, reason=reason, rule=f"excluded_dir:{dir_name}")


def should_skip_dir(dir_name: str) -> bool:
    """Convenience boolean wrapper for os.walk pruning."""
    return classify_dir_exclusion(dir_name).excluded


def path_exclusion(rel_path: str) -> ExclusionResult:
    """Decide whether a repository-relative PATH falls under any excluded directory.

    Checks each path segment against the exact-name exclusion set.
    """
    normalized = rel_path.replace("\\", "/")
    for segment in normalized.split("/"):
        result = classify_dir_exclusion(segment)
        if result.excluded:
            return result
    return _NOT_EXCLUDED


def walk_pruned(root_path: str | Path) -> Iterator[tuple[str, list[str], list[str]]]:
    """A drop-in ``os.walk`` replacement, safe by construction, for every stage.

    Every caller in this codebase used to run its own ``os.walk`` loop with its
    own directory-skip function — several of them using a buggy
    ``name.startswith(".")`` check that silently hid ``.github`` (see the
    ``.github`` note above), and none of them explicitly pruning directory
    symlinks. This is the single walker every stage now shares, so discovery,
    controls, readiness, and the structural scanner all see the same file set.

    Three things happen before each level is yielded:

    1. Exact-name exclusion via :func:`classify_dir_exclusion` — never a prefix
       check, so ``.github`` stays visible.
    2. Directory-symlink pruning. ``os.walk``'s default ``followlinks=False``
       already stops it from *recursing into* a symlinked directory, but the
       entry was still left in ``dirnames`` for downstream code to stumble into
       (e.g. a later ``.resolve()`` or ``.stat()`` that *does* follow it). This
       prunes it outright — checked via ``is_symlink()``, which inspects the
       link itself rather than its target, i.e. an ``lstat``-based check.
       ``followlinks`` is never passed as ``True`` here, deliberately.
    3. Both ``dirnames`` and ``filenames`` are sorted, so the same repository
       produces the same scan order on every filesystem/OS — required for the
       "same repo in, same report out" promise, and for truncation to drop the
       same findings first every time rather than whatever order the OS handed
       back.

    Callers still filter ``filenames`` for their own purposes (extension,
    doc-vs-code, etc.); this only owns the traversal and pruning.
    """
    from .scan_budget import ACTIVE
    budget = ACTIVE.get()
    root_path = Path(root_path)
    for dirpath, dirnames, filenames in os.walk(root_path):
        if budget and not budget.check():
            return
        dirpath_obj = Path(dirpath)
        pruned = []
        for d in dirnames:
            if classify_dir_exclusion(d).excluded:
                if budget:
                    budget.exclusions.add((dirpath_obj / d).relative_to(root_path).as_posix() + "/")
                continue
            if (dirpath_obj / d).is_symlink():
                if budget:
                    budget.exclusions.add((dirpath_obj / d).relative_to(root_path).as_posix() + "/ (symlink)")
                continue
            pruned.append(d)
        dirnames[:] = sorted(pruned)
        if budget:
            budget.discovered.update((dirpath_obj / name).relative_to(root_path).as_posix() for name in filenames)
        yield dirpath, dirnames, sorted(filenames)


def safe_regular_file_size(path: str | Path) -> int | None:
    """Return a file's size without ever following a symlink to get it.

    ``Path.stat()`` follows the final symlink component, so a size check
    against a symlink actually measures whatever it points at — including
    something outside the repository. ``lstat()`` measures the link itself.
    Combined with an explicit regular-file check, this is the one place every
    stage should get an untrusted path's size from before deciding whether to
    read it. Returns ``None`` for anything that isn't a regular file (symlink,
    FIFO, device, directory) or that can't be stat'd at all — callers should
    treat ``None`` the same as "skip this file", never as zero.
    """
    try:
        metadata = Path(path).lstat()
    except OSError:
        return None
    if not stat_module.S_ISREG(metadata.st_mode):
        return None
    return metadata.st_size
