"""
MITRE ATT&CK Mapping
====================
Maps internal alert names to MITRE ATT&CK Tactics and Techniques.
"""

MITRE_MAPPING = {
    "Port Scan": {
        "tactic": "TA0043: Reconnaissance",
        "technique": "T1046: Network Service Discovery",
        "url": "https://attack.mitre.org/techniques/T1046/"
    },
    "High Volume Traffic": {
        "tactic": "TA0040: Impact",
        "technique": "T1498: Network Denial of Service",
        "url": "https://attack.mitre.org/techniques/T1498/"
    },
    "Threat Feed Hit": {
        "tactic": "TA0011: Command and Control",
        "technique": "T1071: Application Layer Protocol",
        "url": "https://attack.mitre.org/techniques/T1071/"
    },
    "Suspicious Protocol Usage": {
        "tactic": "TA0008: Lateral Movement",
        "technique": "T1021: Remote Services",
        "url": "https://attack.mitre.org/techniques/T1021/"
    },
    "Data Exfiltration": {
        "tactic": "TA0010: Exfiltration",
        "technique": "T1048: Exfiltration Over Alternative Protocol",
        "url": "https://attack.mitre.org/techniques/T1048/"
    }
}

def get_mitre_mapping(alert_title: str) -> dict:
    """Returns MITRE mapping for a given alert title, or empty dict if none."""
    # Try exact match
    if alert_title in MITRE_MAPPING:
        return MITRE_MAPPING[alert_title]
    
    # Try substring match
    for key, mapping in MITRE_MAPPING.items():
        if key.lower() in alert_title.lower():
            return mapping
            
    return {}
