import argparse
import os
from .parsers import parse_alert_json, parse_wazuh_rule_xml
from .mapping import AttackMapper
from .reports import report_to_json, report_to_csv, report_to_markdown, report_to_html


def main():
    parser = argparse.ArgumentParser(description="Wazuh ATT&CK Mapper — parse alerts/rules and suggest MITRE ATT&CK techniques")
    parser.add_argument("path", help="Path to alert JSON or rule XML")
    parser.add_argument("--mapping", help="Optional mapping JSON to override defaults", default=None)
    parser.add_argument("--outdir", help="Output directory", default="out")
    parser.add_argument("--formats", help="Comma-separated output formats: json,csv,md,html", default="json,md,html")
    args = parser.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    mapper = AttackMapper(mapping_file=args.mapping) if args.mapping else AttackMapper()

    path = args.path
    if path.lower().endswith(".json"):
        alerts = parse_alert_json(path)
        all_results = []
        for idx, alert in enumerate(alerts):
            suggestions = mapper.map_event(alert)
            summary = {
                "source": path,
                "index": idx,
                "alert": alert,
                "suggestions": suggestions,
            }
            all_results.append(summary)
    elif path.lower().endswith(".xml"):
        rule = parse_wazuh_rule_xml(path)
        # create synthetic alert to feed mapper (rule context)
        synthetic = {
            "rule": {"id": rule.get("id"), "description": rule.get("description")},
            "full_log": rule.get("description", ""),
        }
        suggestions = mapper.map_event(synthetic, rule=rule)
        all_results = [{"source": path, "rule": rule, "suggestions": suggestions}]
    else:
        raise SystemExit("Unsupported file type. Provide .json or .xml")

    # flatten suggestions for reporting
    flattened = []
    for item in all_results:
        for s in item["suggestions"]:
            entry = s.copy()
            entry["source"] = item["source"]
            flattened.append(entry)

    formats = [f.strip() for f in args.formats.split(",") if f.strip()]
    out_base = os.path.splitext(os.path.basename(path))[0]
    if "json" in formats:
        report_to_json(flattened, os.path.join(args.outdir, f"{out_base}.results.json"))
    if "csv" in formats:
        report_to_csv(flattened, os.path.join(args.outdir, f"{out_base}.results.csv"))
    if "md" in formats or "markdown" in formats:
        report_to_markdown(flattened, os.path.join(args.outdir, f"{out_base}.results.md"))
    if "html" in formats:
        report_to_html(flattened, os.path.join(args.outdir, f"{out_base}.results.html"))

    # Print short console summary
    for item in all_results:
        print(f"Source: {item['source']}")
        if "rule" in item:
            print(f"Rule: {item['rule'].get('id')}")
        for s in item["suggestions"][:10]:
            print(f"- Suggested ATT&CK: {s['technique']} ({s.get('technique_name')}) Confidence: {s['confidence']}%")
    print(f"Reports written to {args.outdir}")


if __name__ == '__main__':
    main()
