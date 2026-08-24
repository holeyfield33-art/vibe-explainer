"""CLI entry point for vibe-explainer."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .integrate_vibe_check import load_vibe_check_report, summarize_vibe_findings
from .report import render_markdown
from .scanner import scan_repo


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vibe-explainer",
        description=(
            "Generate a short mental-model report for a (vibe-coded) repository "
            "so humans can orient and adopt it."
        ),
    )
    p.add_argument(
        "repo",
        nargs="?",
        default=".",
        help="Path to the repository root (default: current directory)",
    )
    p.add_argument(
        "--offline",
        action="store_true",
        help="Deterministic structural pass only (no LLM). Currently the only implemented mode.",
    )
    p.add_argument(
        "--vibe-check-report",
        metavar="PATH",
        help="Optional path to a vibe-check JSON report for grounded risk notes",
    )
    p.add_argument(
        "--out",
        "-o",
        metavar="PATH",
        help="Write the markdown report to this file instead of stdout",
    )
    p.add_argument(
        "--format",
        choices=("markdown",),
        default="markdown",
        help="Output format (only markdown is implemented in v0.1)",
    )
    p.add_argument(
        "--version",
        action="version",
        version=f"vibe-explainer {__version__}",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    repo = Path(args.repo).resolve()
    if not repo.is_dir():
        print(f"error: not a directory: {repo}", file=sys.stderr)
        return 2

    # Offline is currently the only implemented path; keep the flag for future LLM mode.
    offline = True if args.offline or True else True

    try:
        scan = scan_repo(repo)
    except Exception as exc:  # noqa: BLE001 — surface cleanly to CLI users
        print(f"error: scan failed: {exc}", file=sys.stderr)
        return 1

    vibe_notes: list[str] = []
    if args.vibe_check_report:
        report = load_vibe_check_report(args.vibe_check_report)
        if report is None:
            print(
                f"warning: could not load vibe-check report at {args.vibe_check_report}",
                file=sys.stderr,
            )
        else:
            vibe_notes = summarize_vibe_findings(report)

    md = render_markdown(scan, vibe_notes=vibe_notes, offline=offline)

    if args.out:
        out_path = Path(args.out)
        out_path.write_text(md, encoding="utf-8")
        print(f"Wrote {out_path}", file=sys.stderr)
    else:
        print(md)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
