import os
import tempfile
from src.wazuh_mapper.reports import report_to_json, report_to_csv, report_to_markdown, report_to_html

SUGGESTIONS = [
    {"technique": "T1110", "technique_name": "Brute Force", "confidence": 85, "justification": "Matched 2 items", "evidence": ["keyword:failed password", "regex:failed password for"], "source": "examples/alerts.json"}
]


def test_reports_write():
    td = tempfile.mkdtemp()
    jsonp = os.path.join(td, "out.json")
    csvp = os.path.join(td, "out.csv")
    mdp = os.path.join(td, "out.md")
    htmlp = os.path.join(td, "out.html")
    report_to_json(SUGGESTIONS, jsonp)
    report_to_csv(SUGGESTIONS, csvp)
    report_to_markdown(SUGGESTIONS, mdp)
    report_to_html(SUGGESTIONS, htmlp)
    assert os.path.exists(jsonp)
    assert os.path.exists(csvp)
    assert os.path.exists(mdp)
    assert os.path.exists(htmlp)
