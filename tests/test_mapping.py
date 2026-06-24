import os
from src.wazuh_mapper.parsers import parse_alert_json, parse_wazuh_rule_xml
from src.wazuh_mapper.mapping import AttackMapper

HERE = os.path.dirname(__file__)
ALERTS = os.path.join(HERE, "..", "examples", "alerts.json")
RULE = os.path.join(HERE, "..", "examples", "rule5710.xml")


def test_mapping_alert():
    alerts = parse_alert_json(ALERTS)
    mapper = AttackMapper()
    suggestions = mapper.map_event(alerts[0])
    assert any(s["technique"].startswith("T1110") or s["technique"] == "T1087" for s in suggestions)


def test_mapping_rule_context():
    rule = parse_wazuh_rule_xml(RULE)
    mapper = AttackMapper()
    suggestions = mapper.map_event({"rule": {"id": rule["id"], "description": rule["description"]}}, rule=rule)
    assert any(s["technique"] == "T1110" for s in suggestions)
