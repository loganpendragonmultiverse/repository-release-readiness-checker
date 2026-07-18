from __future__ import annotations

import html
import json

from .model import Audit


def render_text(audit: Audit) -> str:
    lines = [f"Release readiness: {audit.score}/100", f"Files scanned: {audit.files_scanned}", ""]
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
h1{{font-size:clamp(2rem,6vw,4rem);margin:.2rem 0}}.score{{font-size:1.2rem;color:#64594e}}table{{width:100%;border-collapse:collapse;background:white}}
th,td{{padding:.8rem;text-align:left;border-bottom:1px solid #ddd;vertical-align:top}}th{{background:#2f2924;color:white}}.error td:first-child{{color:#a51d1d;font-weight:700}}.warning td:first-child{{color:#8a5a00;font-weight:700}}.pass td:first-child{{color:#176a3a;font-weight:700}}
</style></head><body><main><p>Repository audit</p><h1>Release readiness</h1><p class="score">Score: {audit.score}/100 · {audit.files_scanned} files scanned</p>
<table><thead><tr><th>Status</th><th>Location</th><th>Finding</th></tr></thead><tbody>{''.join(rows)}</tbody></table></main></body></html>"""
