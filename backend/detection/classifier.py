"""
Real-Time Attack Classification
===============================
Takes raw alerts and enriches them with standardized classifications,
MITRE ATT&CK mappings, and severity ratings.
"""

from typing import Any

CLASSIFICATION_RULES = [
    {
        "keywords": ["brute force", "multiple failed", "login", "ssh connection attempts"],
        "classification": "Brute Force",
        "mitre_technique": "T1110",
        "mitre_tactic": "Credential Access",
        "severity": "high"
    },
    {
        "keywords": ["sql injection", "union select", "drop table"],
        "classification": "SQL Injection",
        "mitre_technique": "T1190",
        "mitre_tactic": "Initial Access",
        "severity": "critical"
    },
    {
        "keywords": ["port scan", "reconnaissance", "distinct ports"],
        "classification": "Network Scanning",
        "mitre_technique": "T1046",
        "mitre_tactic": "Discovery",
        "severity": "medium"
    },
    {
        "keywords": ["dns", "tunneling", "any query"],
        "classification": "DNS Tunneling / Amplification",
        "mitre_technique": "T1071",
        "mitre_tactic": "Command and Control",
        "severity": "high"
    },
    {
        "keywords": ["cleartext", "ftp", "telnet"],
        "classification": "Cleartext Protocol Usage",
        "mitre_technique": "T1040",
        "mitre_tactic": "Credential Access",
        "severity": "medium"
    },
    {
        "keywords": ["malicious", "threat feed", "botnet", "beaconing"],
        "classification": "Malware Beaconing / C2",
        "mitre_technique": "T1071",
        "mitre_tactic": "Command and Control",
        "severity": "high"
    },
    {
        "keywords": ["dos", "volume", "flood", "impact"],
        "classification": "Denial of Service",
        "mitre_technique": "T1498",
        "mitre_tactic": "Impact",
        "severity": "high"
    },
    {
        "keywords": ["exfiltration"],
        "classification": "Data Exfiltration",
        "mitre_technique": "T1048",
        "mitre_tactic": "Exfiltration",
        "severity": "high"
    }
]

class AlertClassifier:
    def classify(self, alert: dict[str, Any]) -> dict[str, Any]:
        """Enriches the alert dictionary in-place and returns it."""
        title = alert.get("title", "").lower()
        desc = alert.get("description", "").lower()
        combined = f"{title} {desc}"

        matched = False
        for rule in CLASSIFICATION_RULES:
            if any(kw in combined for kw in rule["keywords"]):
                alert["classification"] = rule["classification"]
                if not alert.get("mitre_technique"):
                    alert["mitre_technique"] = rule["mitre_technique"]
                if not alert.get("mitre_tactic"):
                    alert["mitre_tactic"] = rule["mitre_tactic"]
                # Override severity with the rule's severity if it's more severe
                alert["severity"] = rule["severity"]
                matched = True
                break

        if not matched:
            alert["classification"] = "Suspicious Activity"
            
        return alert

classifier = AlertClassifier()
