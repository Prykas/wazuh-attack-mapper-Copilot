import os
from src.wazuh_mapper.parsers import parse_alert_json, parse_wazuh_rule_xml

HERE = os.path.dirname(__file__)
ALERTS = os.path.join(HERE, "..", "examples", "alerts.json")
RULE = os.path.join(HERE, "..", "examples", "rule5710.xml")


def test_parse_alerts():
    alerts = parse_alert_json(ALERTS)
    assert isinstance(alerts, list)
    assert len(alerts) >= 1
    a = alerts[0]
    assert "rule" in a
    assert "full_log" in a


def test_parse_rule():
    rule = parse_wazuh_rule_xml(RULE)
    assert rule["id"] == "5710"
    assert "login" in rule["description"].lower()
    assert "ssh" in [g.lower() for g in rule["groups"]]
