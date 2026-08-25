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

from dataclasses import dataclass

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
