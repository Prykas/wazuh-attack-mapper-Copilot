import json
import csv
from typing import List, Dict, Any
from pathlib import Path
import html
import datetime


def report_to_json(suggestions: List[Dict[str, Any]], out_path: str):
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({"generated_at": datetime.datetime.utcnow().isoformat() + "Z", "results": suggestions}, f, indent=2)


def report_to_csv(suggestions: List[Dict[str, Any]], out_path: str):
    keys = ["technique", "technique_name", "confidence", "justification", "evidence"]
    with open(out_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=keys)
        writer.writeheader()
        for s in suggestions:
            row = s.copy()
            row["evidence"] = ";".join(s.get("evidence", []))
            writer.writerow(row)


def report_to_markdown(suggestions: List[Dict[str, Any]], out_path: str, title: str = "Wazuh ATT&CK Mapper Report"):
    lines = [f"# {title}", "", f"Generated at: {datetime.datetime.utcnow().isoformat()}Z", "", "## Suggestions", ""]
    for s in suggestions:
        lines.append(f"### {s['technique']} — {s.get('technique_name','')}")
        lines.append(f"- Confidence: {s['confidence']}%")
        lines.append(f"- Justification: {s.get('justification','')}")
        lines.append(f"- Evidence:")
        for e in s.get("evidence", []):
            lines.append(f"  - {e}")
        lines.append("")
    content = "\n".join(lines)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(content)


def report_to_html(suggestions: List[Dict[str, Any]], out_path: str, title: str = "Wazuh ATT&CK Mapper Report"):
    now = datetime.datetime.utcnow().isoformat() + "Z"
    rows = []
    for s in suggestions:
        ev = "<br>".join(html.escape(e) for e in s.get("evidence", []))
        rows.append(f"<tr><td>{html.escape(s['technique'])}</td><td>{html.escape(str(s.get('technique_name','')))}</td><td>{s['confidence']}</td><td>{html.escape(s.get('justification',''))}</td><td>{ev}</td></tr>")
    html_content = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>{html.escape(title)}</title>
<style>table{{border-collapse:collapse}}td,th{{border:1px solid #ccc;padding:6px}}</style>
</head>
<body>
<h1>{html.escape(title)}</h1>
<p>Generated at: {now}</p>
<table>
<thead><tr><th>Technique</th><th>Name</th><th>Confidence</th><th>Justification</th><th>Evidence</th></tr></thead>
<tbody>
{''.join(rows)}
</tbody>
</table>
</body>
</html>"""
    Path(out_path).write_text(html_content, encoding="utf-8")
