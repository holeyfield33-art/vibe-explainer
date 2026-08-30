"""CLI entry point for vibe-explainer."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .integrate_vibe_check import load_vibe_check_report, summarize_vibe_findings
from .report import render_markdown
from .scanner import scan_repo


def _print_portable(output: str) -> None:
    """Print without crashing on legacy Windows console encodings."""
    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    portable = output.encode(encoding, errors="replace").decode(encoding)
    print(portable)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vibe-explainer",
        description=(
            "Generate a short mental-model report for a (vibe-coded) repository "
            "so humans can orient and adopt it. Use --security for an AI security "
            "assessment (inventory, attack surface, data flow, controls, risk, "
            "readiness) instead."
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
        help="Write the report to this file instead of stdout",
    )
    p.add_argument(
        "--format",
        choices=("markdown",),
        default="markdown",
        help="Output format for the default mental-model report (only markdown is implemented in v0.1)",
    )
    p.add_argument(
        "--security",
        action="store_true",
        help="Run the AI security assessment (discovery, attack surface, data flow, "
        "controls, risk, readiness) instead of the default mental-model report.",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="With --security, emit the full assessment as JSON instead of human-readable text.",
    )
    p.add_argument(
        "--consultant",
        action="store_true",
        help="With --security, emit a consultant-grade Markdown assessment report "
        "(suitable as a client deliverable) instead of the terminal summary.",
    )
    p.add_argument(
        "--version",
        action="version",
        version=f"vibe-explainer {__version__}",
    )
    return p


def _run_security_mode(repo: Path, as_json: bool, as_consultant: bool, out: str | None) -> int:
    from .ai_discovery import discover_ai
    from .attack_surface import build_attack_surface
    from .consultant_report import render_consultant_markdown
    from .controls import assess_controls
    from .dataflow import build_dataflow
    from .readiness import assess_readiness
    from .risk import assess_risks
    from .security_report import build_report, render_text

    try:
        discovery = discover_ai(repo)
        surface = build_attack_surface(discovery)
        dataflow = build_dataflow(discovery)
        controls = assess_controls(discovery, surface, dataflow)
        risks = assess_risks(discovery, surface, dataflow, controls)
        readiness = assess_readiness(discovery, surface, dataflow, controls, risks)
        report = build_report(discovery, surface, dataflow, controls, risks, readiness)
    except Exception as exc:  # noqa: BLE001 — surface cleanly, never a raw traceback
        print(f"Unable to analyze repository:\n{exc}", file=sys.stderr)
        return 1

    if as_json:
        output = report.to_json()
    elif as_consultant:
        output = render_consultant_markdown(report)
    else:
        output = render_text(report)

    if out:
        out_path = Path(out)
        out_path.write_text(output, encoding="utf-8")
        print(f"Wrote {out_path}", file=sys.stderr)
    else:
        _print_portable(output)

    # A HIGH/CRITICAL risk finding is a successful assessment result, not a tool
    # failure — exit 0 whenever the assessment itself completed.
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    repo = Path(args.repo).resolve()
    if not repo.is_dir():
        print(f"error: not a directory: {repo}", file=sys.stderr)
        return 2

    if args.security:
        return _run_security_mode(repo, args.json, args.consultant, args.out)

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
        _print_portable(md)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
