from __future__ import annotations

import html
import json

from .baselines import Comparison
from .model import Audit


def render_text(audit: Audit) -> str:
    lines = [f"Release readiness: {audit.score}/100", f"Files scanned: {audit.files_scanned}", ""]
    if audit.uninspected_paths:
        lines.append(f"Content inspection skipped {len(audit.uninspected_paths)} bounded/non-text/unreadable file(s).")
    for item in audit.findings:
        location = f" {item.path}" if item.path else ""
        if item.line:
            location += f":{item.line}"
        lines.append(f"{item.severity.value.upper():7}{location}")
        lines.append(f"        {item.message}")
    return "\n".join(lines)


def render_json(audit: Audit) -> str:
    return json.dumps(audit.to_dict(), indent=2, ensure_ascii=False)


def render_html(audit: Audit) -> str:
    rows = []
    for item in audit.findings:
        location = item.path or "Repository"
        if item.line:
            location += f":{item.line}"
        rows.append(
            f'<tr class="{item.severity.value}"><td>{html.escape(item.severity.value.upper())}</td>'
            f"<td>{html.escape(location)}</td><td>{html.escape(item.message)}</td></tr>"
        )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Release readiness report</title><style>
body{{font:16px/1.55 system-ui,sans-serif;margin:0;background:#f5f2ec;color:#24201c}}main{{max-width:1050px;margin:auto;padding:3rem 1rem}}
h1{{font-size:clamp(2rem,6vw,4rem);margin:.2rem 0}}.score{{font-size:1.2rem;color:#64594e}}table{{width:100%;table-layout:fixed;border-collapse:collapse;background:white}}
th,td{{overflow-wrap:anywhere;word-break:normal;padding:.8rem;text-align:left;border-bottom:1px solid #ddd;vertical-align:top}}th{{background:#2f2924;color:white}}.error td:first-child{{color:#a51d1d;font-weight:700}}.warning td:first-child{{color:#8a5a00;font-weight:700}}.pass td:first-child{{color:#176a3a;font-weight:700}}
</style></head><body><main><p>Repository audit</p><h1>Release readiness</h1><p class="score">Score: {audit.score}/100 · {audit.files_scanned} files scanned · {len(audit.uninspected_paths)} content inspection skips</p>
<table><thead><tr><th>Status</th><th>Location</th><th>Finding</th></tr></thead><tbody>{''.join(rows)}</tbody></table></main></body></html>"""


def render_comparison(audit: Audit, comparison: Comparison, format: str) -> str:
    """Append value-free baseline status while retaining the complete current audit."""
    if format == "json":
        data = audit.to_dict()
        data["comparison"] = comparison.to_dict()
        return json.dumps(data, indent=2, ensure_ascii=False)
    summary = f"New: {len(comparison.new)} · Unchanged: {len(comparison.unchanged)} · Resolved: {len(comparison.resolved)} · Unverified: {len(comparison.unverified)}"
    rows = []
    for state, records in comparison.to_dict().items():
        for record in records:
            location = record["path"] or "Repository"
            if record["line"]:
                location += f":{record['line']}"
            rows.append((state, record["rule"], record["severity"], location))
    if format == "html":
        table = "".join("<tr>" + "".join(f"<td>{html.escape(value)}</td>" for value in row) + "</tr>" for row in rows)
        section = f'<h2>Baseline comparison</h2><p>{summary}</p><table><thead><tr><th>Change</th><th>Rule</th><th>Severity</th><th>Location</th></tr></thead><tbody>{table}</tbody></table>'
        return render_html(audit).replace("</main>", section + "</main>")
    lines = [render_text(audit), "", "Baseline comparison", summary]
    lines.extend(f"{state.upper()} {severity.upper()} {rule} {location}" for state, rule, severity, location in rows)
    return "\n".join(lines)
