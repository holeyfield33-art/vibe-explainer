"""Cooperative, scan-wide budgets; reporting remains possible after exhaustion.

Context-local state lets every existing static reader/walker share the same limits
without global mutation or a second detector. No target code is executed.
"""
from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
import time

ACTIVE: ContextVar[ScanBudget | None] = ContextVar("scan_budget", default=None)


@dataclass
class ScanBudget:
    root: Path
    max_files: int = 20_000
    max_bytes: int = 200_000_000
    max_seconds: float = 120.0
    excluded_paths: set[str] = field(default_factory=set)
    started: float = field(default_factory=lambda: time.monotonic())
    reason: str | None = None
    discovered: set[str] = field(default_factory=set)
    inspected: set[str] = field(default_factory=set)
    bytes_inspected: int = 0
    skipped: dict[str, str] = field(default_factory=dict)
    exclusions: set[str] = field(default_factory=set)
    parse_failures: set[str] = field(default_factory=set)
    unsupported: set[str] = field(default_factory=set)

    def check(self) -> bool:
        if self.reason is None and time.monotonic() - self.started >= self.max_seconds:
            self.reason = f"time budget ({self.max_seconds}s) reached"
        return self.reason is None

    def relative(self, path: Path) -> str:
        return path.relative_to(self.root).as_posix()

    def admit(self, path: Path, size: int) -> bool:
        rel = self.relative(path)
        if rel in self.excluded_paths:
            self.skipped[rel] = "explicit exclusion"
            return False
        # Refuse intermediate symlinks as well as final symlinks. Repositories
        # must remain immutable during scanning (not a filesystem sandbox).
        if path.resolve().is_relative_to(self.root) is False or any(
            part.is_symlink() for part in (path, *path.parents) if part != self.root
        ):
            self.skipped[rel] = "symlink/outside root"
            return False
        if not self.check():
            return False
        if rel not in self.inspected:
            if len(self.inspected) >= self.max_files:
                self.reason = f"file count budget ({self.max_files}) reached"
                return False
            if self.bytes_inspected + size > self.max_bytes:
                self.reason = f"total byte budget ({self.max_bytes}) reached"
                return False
        return True

    def record_read(self, path: Path, size: int) -> None:
        rel = self.relative(path)
        if rel not in self.inspected:
            self.inspected.add(rel)
            self.bytes_inspected += size

    def snapshot(self) -> dict:
        return {
            "files_discovered": len(self.discovered),
            "files_inspected": len(self.inspected),
            "files_skipped": len(self.discovered - self.inspected),
            "bytes_inspected": self.bytes_inspected,
            "elapsed_seconds": round(time.monotonic() - self.started, 6),
            "budget_exhausted_reason": self.reason,
            "inventory_complete": self.reason is None,
            "exclusions_applied": sorted(self.exclusions | self.excluded_paths),
            "skipped_reasons": dict(sorted(self.skipped.items())),
            "parse_failures": sorted(self.parse_failures),
            "unsupported_extensions": sorted(self.unsupported),
            "scope_note": "Discovered counts cover visited directories only; inspected means content read, not every analysis stage completed. Absence of evidence outside inspected scope is not evidence of absence.",
        }


def within_budget() -> bool:
    budget = ACTIVE.get()
    return budget is None or budget.check()
