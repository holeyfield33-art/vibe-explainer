"""Reject stale affirmative assurance claims in release-facing material."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS = (ROOT / "README.md", ROOT / "SPEC.md", ROOT / "SECURITY.md", ROOT / "docs", ROOT / "examples")
STALE = re.compile(
    r"(?i)\b(?:consultant-grade|certification-grade|guaranteed secure|proof of security|"
    r"proven secure|maturity score(?:s)?)\b"
)
DISCLAIMERS = re.compile(
    r"(?i)\b(?:not|never|no|does not|do not|cannot|isn't|aren't|remove|replace|avoid|without)\b"
)
TEXT_EXTENSIONS = {".md", ".txt", ".rst", ".adoc", ".py", ".toml", ".yaml", ".yml"}


def check_product_boundary() -> list[str]:
    violations: list[str] = []
    files: list[Path] = []
    for target in TARGETS:
        if target.is_file():
            files.append(target)
        elif target.is_dir():
            files.extend(path for path in target.rglob("*") if path.is_file() and path.suffix.lower() in TEXT_EXTENSIONS)
    for path in sorted(files):
        for line_number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if STALE.search(line) and not DISCLAIMERS.search(line):
                violations.append(f"{path.relative_to(ROOT).as_posix()}:{line_number}: {line.strip()}")
    return violations


def main() -> int:
    violations = check_product_boundary()
    if violations:
        print("Product-boundary check failed:", file=sys.stderr)
        for violation in violations:
            print(f"  {violation}", file=sys.stderr)
        return 1
    print("Product-boundary check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
