from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .baselines import compare, load_baseline, write_baseline
from .model import Severity
from .reporters import render_comparison, render_html, render_json, render_text
from .scanner import audit_repository


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="release-ready", description="Audit a repository before publishing it.")
    parser.add_argument("target", nargs="?", default=".", help="repository directory (default: current directory)")
    parser.add_argument("--format", choices=("text", "json", "html"), default="text", help="report format")
    parser.add_argument("--output", type=Path, help="write the report to a file instead of stdout")
    parser.add_argument("--fail-on", choices=("error", "warning", "never"), default="error", help="finding level that produces a non-zero exit")
    parser.add_argument("--baseline", type=Path, help="compare with a version 1 finding baseline")
    parser.add_argument("--write-baseline", type=Path, help="save current non-pass findings to a new file")
    parser.add_argument("--new-only", action="store_true", help="apply failure threshold only to new findings (requires --baseline)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.new_only and not args.baseline:
            raise ValueError("--new-only requires --baseline")
        destinations = [path.resolve() for path in (args.output, args.write_baseline) if path]
        if len(set(destinations)) != len(destinations):
            raise ValueError("Report and baseline destinations must differ")
        if args.baseline and args.baseline.resolve() in destinations:
            raise ValueError("Outputs must not replace the input baseline")
        if args.write_baseline and args.write_baseline.exists():
            raise ValueError("Baseline output already exists")
        if (args.baseline or args.write_baseline) and args.output and args.output.exists():
            raise ValueError("Baseline-mode report output already exists")
        previous = load_baseline(args.baseline) if args.baseline else None
        audit = audit_repository(Path(args.target))
        comparison = compare(audit, previous) if previous is not None else None
        renderer = {"text": render_text, "json": render_json, "html": render_html}[args.format]
        report = render_comparison(audit, comparison, args.format) if comparison else renderer(audit)
        if args.output:
            mode = "x" if args.baseline or args.write_baseline else "w"
            with args.output.open(mode, encoding="utf-8") as handle:
                handle.write(report + ("\n" if args.format != "html" else ""))
            print(f"Wrote {args.format} report to {args.output}")
        else:
            print(report)
        if args.write_baseline:
            write_baseline(args.write_baseline, audit)
    except (OSError, ValueError) as exc:
        print(f"release-ready: {exc}", file=sys.stderr)
        return 2
    findings = comparison.new_findings(audit) if args.new_only and comparison else audit.findings
    if args.fail_on == "never":
        return 0
    if any(item.severity is Severity.ERROR for item in findings):
        return 1
    if args.fail_on == "warning" and any(item.severity is Severity.WARNING for item in findings):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
