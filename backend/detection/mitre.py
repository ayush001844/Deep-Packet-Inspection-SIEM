"""
MITRE ATT&CK Mapping
====================
Provides metadata and mapping for MITRE ATT&CK Enterprise tactics and techniques.
Used to enrich IDS and Sigma rules.
"""

from __future__ import annotations

from typing import Any, Optional

TACTICS = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command and Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
}

TECHNIQUES = {
    "T1110": {"name": "Brute Force", "tactics": ["TA0006"]},
    "T1046": {"name": "Network Service Discovery", "tactics": ["TA0007"]},
    "T1071": {"name": "Application Layer Protocol", "tactics": ["TA0011"]},
    "T1190": {"name": "Exploit Public-Facing Application", "tactics": ["TA0001"]},
    "T1059": {"name": "Command and Scripting Interpreter", "tactics": ["TA0002"]},
    "T1040": {"name": "Network Sniffing", "tactics": ["TA0006", "TA0007"]},
    "T1566": {"name": "Phishing", "tactics": ["TA0001"]},
    "T1078": {"name": "Valid Accounts", "tactics": ["TA0001", "TA0003", "TA0004", "TA0005"]},
    "T1021": {"name": "Remote Services", "tactics": ["TA0008"]},
    "T1090": {"name": "Proxy", "tactics": ["TA0011"]},
}

def get_mitre_info(technique_id: str) -> dict[str, Any]:
    """Retrieve full MITRE information for a technique ID."""
    tech = TECHNIQUES.get(technique_id)
    if not tech:
        return {
            "technique_id": technique_id,
            "technique_name": "Unknown Technique",
            "tactics": []
        }
        
    tactic_names = [TACTICS.get(t, t) for t in tech["tactics"]]
    
    return {
        "technique_id": technique_id,
        "technique_name": tech["name"],
        "tactics": tactic_names,
        "tactic_ids": tech["tactics"]
    }
