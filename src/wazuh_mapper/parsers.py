import json
import xml.etree.ElementTree as ET
from typing import Dict, Any, List, Union


def parse_alert_json(path: str) -> List[Dict[str, Any]]:
    """
    Parse a Wazuh alert JSON file. Supports a single object or an array of alerts.
    Returns a list of alert dicts.
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return data
    raise ValueError("Unsupported JSON structure for alerts")


def _find_text(elem: ET.Element, tag: str) -> Union[str, None]:
    node = elem.find(tag)
    if node is None:
        return None
    return (node.text or "").strip()


def parse_wazuh_rule_xml(path: str) -> Dict[str, Any]:
    """
    Parse a single Wazuh rule XML file and return structured data.
    Expected to find <rule id="..."> with children like <description>, <groups>, etc.
    """
    tree = ET.parse(path)
    root = tree.getroot()

    # Rule may be the root or inside <rules> ... <rule>
    rule_elem = None
    if root.tag == "rule":
        rule_elem = root
    else:
        rule_elem = root.find(".//rule")
    if rule_elem is None:
        raise ValueError("No <rule> element found in XML")

    rule_id = rule_elem.get("id")
    description = _find_text(rule_elem, "description") or ""
    groups = []
    for g in rule_elem.findall("group"):
        if g.text:
            groups.append(g.text.strip())

    frequency = _find_text(rule_elem, "frequency")
    correlation = []
    for c in rule_elem.findall("correlation"):
        if c.text:
            correlation.append(c.text.strip())

    # Extract tags/mitre if present
    mitre_tags = []
    for tag in rule_elem.findall("mitre"):
        # custom tag name could vary; try to gather text
        if tag.text:
            mitre_tags.append(tag.text.strip())
    # fallback: some rules use <tag> or <tags>
    for t in rule_elem.findall(".//tag"):
        if t.text and t.text.strip().upper().startswith("T"):
            mitre_tags.append(t.text.strip())

    return {
        "id": rule_id,
        "description": description,
        "groups": groups,
        "frequency": frequency,
        "correlation": correlation,
        "mitre": list(set(mitre_tags)),
    }
