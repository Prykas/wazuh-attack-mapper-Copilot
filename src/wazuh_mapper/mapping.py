import json
import re
from typing import Dict, Any, List, Optional
from pathlib import Path


DEFAULT_MAPPING = {
    # technique: {keywords: [...], regex: [...], description: "..."}
    "T1110": {
        "name": "Brute Force",
        "keywords": ["failed password", "invalid user", "authentication failure", "authentication failed", "login failed", "brute force", "failed login"],
        "regex": [r"failed password for", r"authentication failure", r"invalid user", r"password for invalid user"],
    },
    "T1110.001": {
        "name": "Password Guessing",
        "keywords": ["password guess", "guessing password", "password spraying", "spray"],
        "regex": [r"password spraying", r"password guess"],
    },
    "T1110.003": {
        "name": "Password Spraying",
        "keywords": ["password spraying", "spray", "sprayed"],
        "regex": [r"password spraying", r"password-spray"],
    },
    "T1087": {
        "name": "Account Discovery",
        "keywords": ["user list", "enumerat", "list users", "getent", "id ", "whoami", "user enumeration", "failed user"],
        "regex": [r"enumerat", r"user(s)? enumeration", r"getent", r"whoami"],
    },
    "T1078": {
        "name": "Valid Accounts",
        "keywords": ["valid user", "valid account", "successful login", "accepted password", "session opened for user"],
        "regex": [r"accepted password for", r"session opened for user", r"successful login"],
    },
    "T1021.004": {
        "name": "SSH",
        "keywords": ["sshd", "ssh", "openssh", "ssh connection", "ssh login"],
        "regex": [r"sshd", r"ssh"],
    },
}


class AttackMapper:
    def __init__(self, mapping_file: Optional[str] = None):
        if mapping_file:
            self.mappings = self._load_from_file(mapping_file)
        else:
            self.mappings = DEFAULT_MAPPING

    def _load_from_file(self, path: str) -> Dict[str, Any]:
        p = Path(path)
        with p.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return data

    def map_event(self, alert: Dict[str, Any], rule: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Map an alert and optional rule to ATT&CK techniques.
        Returns a list of suggestions with confidence and evidence.
        """
        text_sources = []
        evidence = []
        # Gather candidate text fields
        for k in ("full_log", "log", "description", "rule.description"):
            if k == "rule.description":
                rd = None
                if alert.get("rule") and isinstance(alert["rule"], dict):
                    rd = alert["rule"].get("description")
                if rd:
                    text_sources.append(rd)
            else:
                v = alert.get(k)
                if v:
                    text_sources.append(str(v))
        # include top-level fields
        for v in alert.values():
            if isinstance(v, str):
                text_sources.append(v)
        # include rule fields if provided
        if rule:
            for field in ("description", "groups", "correlation", "mitre"):
                val = rule.get(field)
                if isinstance(val, list):
                    text_sources.extend([str(x) for x in val])
                elif isinstance(val, str):
                    text_sources.append(val)

        combined_text = "\n".join(text_sources).lower()

        suggestions = []
        for tid, spec in self.mappings.items():
            score = 0
            matches = []
            # keyword matches
            for kw in spec.get("keywords", []):
                if kw.lower() in combined_text:
                    score += 10
                    matches.append(f"keyword:{kw}")
            # regex matches
            for rx in spec.get("regex", []):
                try:
                    if re.search(rx, combined_text, re.IGNORECASE):
                        score += 15
                        matches.append(f"regex:{rx}")
                except re.error:
                    continue
            # rule-provided MITRE tag increases confidence
            if rule and "mitre" in rule and tid in [m.upper() for m in rule.get("mitre", [])]:
                score += 50
                matches.append("rule_mitre_tag")

            # heuristics: if rule id matches known suspicious ids (optional)
            # Normalize score to 0-100
            base_confidence = min(100, score)
            if score > 0:
                # Compose justification text
                justification = f"Matched {len(matches)} evidence items"
                suggestions.append(
                    {
                        "technique": tid,
                        "technique_name": spec.get("name"),
                        "confidence": base_confidence,
                        "justification": justification,
                        "evidence": matches,
                    }
                )

        # sort by confidence desc
        suggestions.sort(key=lambda x: x["confidence"], reverse=True)
        return suggestions
