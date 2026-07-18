from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .model import Severity
from .reporters import render_html, render_json, render_text
from .scanner import audit_repository


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="release-ready", description="Audit a repository before publishing it.")
    parser.add_argument("target", nargs="?", default=".", help="repository directory (default: current directory)")
    parser.add_argument("--format", choices=("text", "json", "html"), default="text", help="report format")
    parser.add_argument("--output", type=Path, help="write the report to a file instead of stdout")
    parser.add_argument("--fail-on", choices=("error", "warning", "never"), default="error", help="finding level that produces a non-zero exit")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        audit = audit_repository(Path(args.target))
    except (OSError, ValueError) as exc:
        print(f"release-ready: {exc}", file=sys.stderr)
        return 2
    renderer = {"text": render_text, "json": render_json, "html": render_html}[args.format]
    report = renderer(audit)
    if args.output:
        args.output.write_text(report + ("\n" if args.format != "html" else ""), encoding="utf-8")
        print(f"Wrote {args.format} report to {args.output}")
    else:
        print(report)
    if args.fail_on == "never":
        return 0
    if audit.errors:
        return 1
    if args.fail_on == "warning" and audit.warnings:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
