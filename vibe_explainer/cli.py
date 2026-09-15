"""CLI entry point for vibe-explainer."""

from __future__ import annotations

import argparse
import json
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
            "Generate an offline static AI repository evidence review. Results are "
            "heuristic leads for analyst validation, not vulnerability findings, "
            "control-effectiveness proof, compliance, or certification."
        ),
    )
    p.add_argument(
        "repo",
        nargs="?",
        default=".",
        help="Path to the repository root (default: current directory)",
    )
    p.add_argument(
        "--legacy-mental-model",
        action="store_true",
        help="Run the deprecated repository-orientation report instead of the AI evidence review.",
    )
    p.add_argument(
        "--vibe-check-report",
        metavar="PATH",
        help="With --legacy-mental-model, add grounded notes from a vibe-check JSON report.",
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
        help="With --legacy-mental-model, select its output format.",
    )
    p.add_argument(
        "--security",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit the complete evidence review as JSON.",
    )
    p.add_argument(
        "--report",
        "--consultant",
        dest="detailed_report",
        action="store_true",
        help="Emit detailed Markdown for analyst review. --consultant is a deprecated alias.",
    )
    p.add_argument(
        "--asi-catalog",
        metavar="PATH",
        help=(
            "Map the evidence review onto a local Agent Security Index "
            "export directory or attack-class JSON. No network fetch is performed."
        ),
    )
    p.add_argument(
        "--experimental-scoring",
        action="store_true",
        help=(
            "Include the legacy uncalibrated numeric scores, severity bands, and "
            "four-level process classification. Not suitable for assurance claims."
        ),
    )
    p.add_argument(
        "--version",
        action="version",
        version=f"vibe-explainer {__version__}",
    )
    return p


def _asi_text_summary(matrix: dict) -> str:
    summary = matrix["summary"]
    protocols = ", ".join(matrix.get("detected_protocols", [])) or "none detected"
    return "\n".join(
        [
            "",
            "AGENT SECURITY INDEX MATRIX",
            "---------------------------",
            f"Catalog: {matrix.get('catalog_version') or 'version not provided'}",
            f"Detected protocols: {protocols}",
            f"Evidence-linked classes: {summary['EVIDENCE_CHAIN']}",
            f"Control-gap classes: {summary['CONTROL_GAP']}",
            f"Control-evidence classes: {summary['CONTROL_EVIDENCE']}",
            f"Relevant but unassessed: {summary['RELEVANT_UNASSESSED']}",
            f"Not observed by this static mapping: {summary['NOT_OBSERVED']}",
            "Full row-level mapping is included when --json is used.",
        ]
    )


def _run_security_mode(
    repo: Path,
    as_json: bool,
    as_consultant: bool,
    out: str | None,
    asi_catalog: str | None = None,
    experimental_scoring: bool = False,
) -> int:
    from .ai_discovery import discover_ai
    from .attack_surface import build_attack_surface
    from .consultant_report import render_consultant_markdown
    from .controls import assess_controls
    from .dataflow import build_dataflow
    from .readiness import assess_readiness
    from .risk import assess_risks
    from .security_report import build_report, render_text

    try:
        excluded_paths: set[str] = set()
        if out:
            try:
                output_rel = Path(out).resolve().relative_to(repo.resolve())
                excluded_paths.add(str(output_rel).replace("\\", "/"))
            except ValueError:
                pass

        discovery = discover_ai(repo, excluded_paths=excluded_paths)
        surface = build_attack_surface(discovery)
        dataflow = build_dataflow(discovery)
        controls = assess_controls(discovery, surface, dataflow)
        risks = assess_risks(discovery, surface, dataflow, controls)
        readiness = assess_readiness(
            discovery, surface, dataflow, controls, risks, excluded_paths=excluded_paths
        )
        report = build_report(
            discovery,
            surface,
            dataflow,
            controls,
            risks,
            readiness,
            include_experimental_scoring=experimental_scoring,
        )

        asi_matrix = None
        if asi_catalog:
            from .asi_matrix import load_asi_catalog, map_report_to_asi

            catalog = load_asi_catalog(asi_catalog)
            asi_matrix = map_report_to_asi(report, catalog)
    except Exception as exc:  # noqa: BLE001 — surface cleanly, never a raw traceback
        print(f"Unable to analyze repository:\n{exc}", file=sys.stderr)
        return 1

    if as_json:
        payload = report.to_dict()
        if asi_matrix is not None:
            payload["asi_matrix"] = asi_matrix
        output = json.dumps(payload, indent=2, sort_keys=False, ensure_ascii=False)
    elif as_consultant:
        output = render_consultant_markdown(report)
        if asi_matrix is not None:
            output += _asi_text_summary(asi_matrix)
    else:
        output = render_text(report)
        if asi_matrix is not None:
            output += _asi_text_summary(asi_matrix)

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

    if args.vibe_check_report and not args.legacy_mental_model:
        print("error: --vibe-check-report requires --legacy-mental-model", file=sys.stderr)
        return 2

    if not args.legacy_mental_model:
        return _run_security_mode(
            repo,
            args.json,
            args.detailed_report,
            args.out,
            args.asi_catalog,
            args.experimental_scoring,
        )

    if args.json or args.detailed_report or args.asi_catalog or args.experimental_scoring:
        print(
            "error: --json, --report/--consultant, --asi-catalog, and "
            "--experimental-scoring cannot be used "
            "with --legacy-mental-model",
            file=sys.stderr,
        )
        return 2

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

    md = render_markdown(scan, vibe_notes=vibe_notes, offline=True)

    if args.out:
        out_path = Path(args.out)
        out_path.write_text(md, encoding="utf-8")
        print(f"Wrote {out_path}", file=sys.stderr)
    else:
        _print_portable(md)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
