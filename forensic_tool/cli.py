"""Command-line entry point for repeatable examination workflows."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .analysis.engine import AnalysisEngine
from .exporter import ExportError, export_segment
from .reporting import write_report
from .server import serve
from .storage import EvidenceStore


def _store(args: argparse.Namespace) -> EvidenceStore:
    return EvidenceStore(args.data_dir)


def _print(value) -> None:
    print(json.dumps(value, indent=2, sort_keys=True, default=str))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="forensic-tool",
        description="Sentinel read-only DVR/NVR forensic acquisition and recovery workstation",
    )
    parser.add_argument("--version", action="version", version=f"Sentinel {__version__}")
    parser.add_argument("--data-dir", default="data", help="case database and artifact directory (default: data)")
    commands = parser.add_subparsers(dest="command", required=True)

    serve_parser = commands.add_parser("serve", help="start the local browser workstation")
    serve_parser.add_argument("--host", default="0.0.0.0")
    serve_parser.add_argument("--port", type=int, default=8000)

    case = commands.add_parser("case", help="create, list, or inspect cases")
    case_sub = case.add_subparsers(dest="case_command", required=True)
    create = case_sub.add_parser("create")
    create.add_argument("title")
    create.add_argument("--investigator", default="")
    create.add_argument("--notes", default="")
    case_sub.add_parser("list")
    show = case_sub.add_parser("show")
    show.add_argument("case_id")

    acquire = commands.add_parser("acquire", help="copy a source image into immutable evidence storage")
    acquire.add_argument("image", type=Path)
    acquire.add_argument("--case", required=True, dest="case_id")
    acquire.add_argument("--name", default=None)
    acquire.add_argument("--source", default="disk-image")

    identify = commands.add_parser("identify", help="detect recorder family and filesystem signatures")
    identify.add_argument("evidence_id")

    recover = commands.add_parser("recover", help="parse or carve evidence")
    recover.add_argument("evidence_id")
    recover.add_argument("--mode", choices=["normal", "deleted", "lost_corrupted"], default="normal")

    timeline = commands.add_parser("timeline", help="show recovered segments in evidence order")
    timeline.add_argument("evidence_id")

    export = commands.add_parser("export", help="copy one segment as native bytes or optional MP4")
    export.add_argument("segment_id")
    export.add_argument("--format", choices=["native", "mp4"], default="native")

    report = commands.add_parser("report", help="write JSON, HTML, and PDF report artifacts")
    report.add_argument("case_id")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "serve":
        serve(args.host, args.port, args.data_dir)
        return 0

    store = _store(args)
    try:
        if args.command == "case":
            if args.case_command == "create":
                _print(store.create_case(args.title, args.investigator, args.notes))
            elif args.case_command == "list":
                _print(store.list_cases())
            else:
                _print(store.case_bundle(args.case_id))
        elif args.command == "acquire":
            _print(store.ingest_file(args.case_id, args.image, args.name, args.source))
        elif args.command == "identify":
            _print(AnalysisEngine(store).identify(args.evidence_id))
        elif args.command == "recover":
            _print(AnalysisEngine(store).recover(args.evidence_id, args.mode))
        elif args.command == "timeline":
            _print(AnalysisEngine(store).timeline(args.evidence_id))
        elif args.command == "export":
            _print(export_segment(store, args.segment_id, args.format))
        elif args.command == "report":
            _print(write_report(store, args.case_id))
        return 0
    except (KeyError, FileNotFoundError, ValueError, ExportError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
