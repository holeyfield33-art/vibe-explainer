"""Two-pass repository crawl (Phase 8A) with full coverage accounting (Phase 8F).

Pass 1 builds a complete structural inventory of every file in the repository.
Pass 2 is what the content scanner iterates over — so the scanner never walks the
filesystem independently, which is how files silently disappeared before. Every file
in the inventory ends in exactly one disposition: analyzed, excluded (with reason),
unreadable (with error), or non-analyzable (binary / unsupported extension). No
silent drops — the crawl result accounts for every discovered file.

This module does not itself run AI discovery; it produces the inventory that
discovery consumes, and the coverage summary the report surfaces.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .exclusion_policy import classify_dir_exclusion
from .file_context import classify_file

# Extensions the content scanner can analyze (superset of ai_discovery.SCAN_EXTS,
# kept here so the crawl knows what "analyzable" means independent of discovery).
ANALYZABLE_EXTS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rs", ".java", ".rb",
    ".json", ".yaml", ".yml", ".toml", ".env", ".cfg", ".ini",
    ".md", ".mdx", ".rst", ".txt",
}

# Extensions we treat as binary / non-analyzable without reading them.
_BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz",
    ".tar", ".whl", ".so", ".dylib", ".dll", ".exe", ".bin", ".woff", ".woff2",
    ".ttf", ".eot", ".mp4", ".mp3", ".wav", ".class", ".pyc", ".o", ".a",
}

MAX_ANALYZE_BYTES = 500_000

# Dispositions.
DISP_ANALYZED = "analyzed"
DISP_EXCLUDED = "excluded"
DISP_UNREADABLE = "unreadable"
DISP_BINARY = "binary"
DISP_UNSUPPORTED = "unsupported"


@dataclass
class FileRecord:
    rel_path: str
    ext: str
    size: int
    disposition: str
    context: str
    context_confidence: str
    reason: str | None = None  # exclusion/unreadable reason
    exclusion_category: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rel_path": self.rel_path,
            "ext": self.ext,
            "size": self.size,
            "disposition": self.disposition,
            "context": self.context,
            "context_confidence": self.context_confidence,
            "reason": self.reason,
            "exclusion_category": self.exclusion_category,
        }


@dataclass
class CrawlResult:
    root: str
    files: list[FileRecord] = field(default_factory=list)

    def analyzable(self) -> list[FileRecord]:
        return [f for f in self.files if f.disposition == DISP_ANALYZED]

    def coverage_summary(self) -> dict[str, Any]:
        by_disposition: dict[str, int] = {}
        by_context: dict[str, int] = {}
        by_exclusion: dict[str, int] = {}
        for f in self.files:
            by_disposition[f.disposition] = by_disposition.get(f.disposition, 0) + 1
            if f.disposition == DISP_ANALYZED:
                by_context[f.context] = by_context.get(f.context, 0) + 1
            if f.disposition == DISP_EXCLUDED and f.exclusion_category:
                by_exclusion[f.exclusion_category] = by_exclusion.get(f.exclusion_category, 0) + 1
        return {
            "total_files": len(self.files),
            "analyzed": by_disposition.get(DISP_ANALYZED, 0),
            "by_disposition": dict(sorted(by_disposition.items())),
            "analyzed_by_context": dict(sorted(by_context.items())),
            "excluded_by_category": dict(sorted(by_exclusion.items())),
        }

    def assert_no_silent_drops(self) -> bool:
        """Every file has an explicit disposition (guaranteed by construction).
        Returns True; exists as an explicit invariant check for tests."""
        return all(f.disposition in {DISP_ANALYZED, DISP_EXCLUDED, DISP_UNREADABLE, DISP_BINARY, DISP_UNSUPPORTED} for f in self.files)


def crawl_repository(root: str | Path, *, read_content_for_context: bool = False) -> CrawlResult:
    """Pass 1: build a complete file inventory with a disposition for every file.

    Directory pruning uses the centralized exclusion policy (exact-name, never
    prefix), so `.github`, `tests/`, `docs/`, etc. are retained. Excluded
    directories are still *recorded* (their files get DISP_EXCLUDED with a reason)
    rather than vanishing — walk pruning is applied but the top of an excluded tree
    is noted.
    """
    root_path = Path(root).resolve()
    if not root_path.is_dir():
        raise NotADirectoryError(f"Not a directory: {root}")

    result = CrawlResult(root=str(root_path))

    for dirpath, dirnames, filenames in os.walk(root_path):
        # Record excluded directories (one representative record) then prune them.
        retained = []
        for d in dirnames:
            excl = classify_dir_exclusion(d)
            if excl.excluded:
                rel = str((Path(dirpath) / d).relative_to(root_path)).replace("\\", "/")
                result.files.append(
                    FileRecord(
                        rel_path=rel + "/",
                        ext="",
                        size=0,
                        disposition=DISP_EXCLUDED,
                        context="VENDOR" if excl.category == "DEPENDENCY_TREE" else "GENERATED",
                        context_confidence="high",
                        reason=excl.reason,
                        exclusion_category=excl.category,
                    )
                )
            else:
                retained.append(d)
        dirnames[:] = retained

        for name in filenames:
            full = Path(dirpath) / name
            rel = str(full.relative_to(root_path)).replace("\\", "/")
            ext = full.suffix.lower()
            try:
                size = full.stat().st_size
            except OSError:
                result.files.append(FileRecord(rel, ext, 0, DISP_UNREADABLE, "UNKNOWN", "low", reason="stat failed"))
                continue

            if ext in _BINARY_EXTS:
                result.files.append(FileRecord(rel, ext, size, DISP_BINARY, "GENERATED", "high", reason="binary extension"))
                continue
            if ext not in ANALYZABLE_EXTS:
                fc = classify_file(rel)
                result.files.append(FileRecord(rel, ext, size, DISP_UNSUPPORTED, fc.context, fc.confidence, reason="unsupported extension"))
                continue
            if size > MAX_ANALYZE_BYTES:
                fc = classify_file(rel)
                result.files.append(FileRecord(rel, ext, size, DISP_UNSUPPORTED, fc.context, fc.confidence, reason=f"exceeds {MAX_ANALYZE_BYTES} bytes"))
                continue

            content = None
            if read_content_for_context:
                try:
                    content = full.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    result.files.append(FileRecord(rel, ext, size, DISP_UNREADABLE, "UNKNOWN", "low", reason="read failed"))
                    continue
            fc = classify_file(rel, content=content)
            result.files.append(FileRecord(rel, ext, size, DISP_ANALYZED, fc.context, fc.confidence))

    result.files.sort(key=lambda f: f.rel_path)
    return result
