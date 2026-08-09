"""
MITRE ATT&CK Navigator (Upgrade 7)
====================================
Generates a full ATT&CK Enterprise matrix with detection coverage heatmap
based on alerts stored in the database.

Provides:
    - Full 12-tactic matrix with techniques mapped to each
    - Detection counts per technique (from alert history)
    - Coverage statistics
"""

from __future__ import annotations

from typing import Any

from backend.db.database import get_session, Alert


# ---------------------------------------------------------------------------
# Full MITRE ATT&CK Enterprise Matrix
# ---------------------------------------------------------------------------

TACTICS_ORDER = [
    ("TA0043", "Reconnaissance"),
    ("TA0042", "Resource Development"),
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"),
    ("TA0005", "Defense Evasion"),
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0011", "Command and Control"),
    ("TA0010", "Exfiltration"),
    ("TA0040", "Impact"),
]

# Comprehensive technique-to-tactic mapping
FULL_TECHNIQUES = {
    # Reconnaissance
    "T1595": {"name": "Active Scanning", "tactics": ["TA0043"]},
    "T1592": {"name": "Gather Victim Host Information", "tactics": ["TA0043"]},
    "T1589": {"name": "Gather Victim Identity Information", "tactics": ["TA0043"]},

    # Resource Development
    "T1583": {"name": "Acquire Infrastructure", "tactics": ["TA0042"]},
    "T1588": {"name": "Obtain Capabilities", "tactics": ["TA0042"]},

    # Initial Access
    "T1190": {"name": "Exploit Public-Facing Application", "tactics": ["TA0001"]},
    "T1566": {"name": "Phishing", "tactics": ["TA0001"]},
    "T1078": {"name": "Valid Accounts", "tactics": ["TA0001", "TA0003", "TA0004", "TA0005"]},
    "T1199": {"name": "Trusted Relationship", "tactics": ["TA0001"]},
    "T1133": {"name": "External Remote Services", "tactics": ["TA0001", "TA0003"]},

    # Execution
    "T1059": {"name": "Command and Scripting Interpreter", "tactics": ["TA0002"]},
    "T1203": {"name": "Exploitation for Client Execution", "tactics": ["TA0002"]},
    "T1047": {"name": "Windows Management Instrumentation", "tactics": ["TA0002"]},
    "T1053": {"name": "Scheduled Task/Job", "tactics": ["TA0002", "TA0003", "TA0004"]},

    # Persistence
    "T1098": {"name": "Account Manipulation", "tactics": ["TA0003"]},
    "T1136": {"name": "Create Account", "tactics": ["TA0003"]},
    "T1543": {"name": "Create or Modify System Process", "tactics": ["TA0003", "TA0004"]},

    # Privilege Escalation
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactics": ["TA0004"]},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactics": ["TA0004", "TA0005"]},

    # Defense Evasion
    "T1070": {"name": "Indicator Removal", "tactics": ["TA0005"]},
    "T1027": {"name": "Obfuscated Files or Information", "tactics": ["TA0005"]},
    "T1562": {"name": "Impair Defenses", "tactics": ["TA0005"]},
    "T1036": {"name": "Masquerading", "tactics": ["TA0005"]},

    # Credential Access
    "T1110": {"name": "Brute Force", "tactics": ["TA0006"]},
    "T1003": {"name": "OS Credential Dumping", "tactics": ["TA0006"]},
    "T1040": {"name": "Network Sniffing", "tactics": ["TA0006", "TA0007"]},
    "T1555": {"name": "Credentials from Password Stores", "tactics": ["TA0006"]},
    "T1557": {"name": "Adversary-in-the-Middle", "tactics": ["TA0006", "TA0009"]},

    # Discovery
    "T1046": {"name": "Network Service Discovery", "tactics": ["TA0007"]},
    "T1082": {"name": "System Information Discovery", "tactics": ["TA0007"]},
    "T1083": {"name": "File and Directory Discovery", "tactics": ["TA0007"]},
    "T1018": {"name": "Remote System Discovery", "tactics": ["TA0007"]},
    "T1135": {"name": "Network Share Discovery", "tactics": ["TA0007"]},

    # Lateral Movement
    "T1021": {"name": "Remote Services", "tactics": ["TA0008"]},
    "T1570": {"name": "Lateral Tool Transfer", "tactics": ["TA0008"]},
    "T1080": {"name": "Taint Shared Content", "tactics": ["TA0008"]},

    # Collection
    "T1560": {"name": "Archive Collected Data", "tactics": ["TA0009"]},
    "T1005": {"name": "Data from Local System", "tactics": ["TA0009"]},
    "T1114": {"name": "Email Collection", "tactics": ["TA0009"]},

    # Command and Control
    "T1071": {"name": "Application Layer Protocol", "tactics": ["TA0011"]},
    "T1090": {"name": "Proxy", "tactics": ["TA0011"]},
    "T1105": {"name": "Ingress Tool Transfer", "tactics": ["TA0011"]},
    "T1573": {"name": "Encrypted Channel", "tactics": ["TA0011"]},
    "T1571": {"name": "Non-Standard Port", "tactics": ["TA0011"]},

    # Exfiltration
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactics": ["TA0010"]},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactics": ["TA0010"]},
    "T1567": {"name": "Exfiltration Over Web Service", "tactics": ["TA0010"]},

    # Impact
    "T1498": {"name": "Network Denial of Service", "tactics": ["TA0040"]},
    "T1499": {"name": "Endpoint Denial of Service", "tactics": ["TA0040"]},
    "T1486": {"name": "Data Encrypted for Impact", "tactics": ["TA0040"]},
    "T1485": {"name": "Data Destruction", "tactics": ["TA0040"]},
    "T1565": {"name": "Data Manipulation", "tactics": ["TA0040"]},
}


class MitreNavigator:
    """Generates ATT&CK matrix data with detection coverage from alerts."""

    def get_detection_counts(self) -> dict[str, int]:
        """Count how many times each technique was triggered in alerts."""
        session = get_session()
        try:
            alerts = session.query(Alert.mitre_technique).filter(
                Alert.mitre_technique.isnot(None),
                Alert.mitre_technique != "",
            ).all()

            counts: dict[str, int] = {}
            for (technique,) in alerts:
                if technique:
                    counts[technique] = counts.get(technique, 0) + 1
            return counts
        finally:
            session.close()

    def get_matrix(self) -> dict[str, Any]:
        """
        Generate the full ATT&CK matrix with detection heatmap data.

        Returns:
            {
                "tactics": [...],
                "matrix": {
                    "tactic_id": [
                        {"id": "T1190", "name": "...", "count": 5, "heat": "high"},
                        ...
                    ]
                },
                "total_techniques": int,
                "detected_techniques": int,
            }
        """
        counts = self.get_detection_counts()

        # Build matrix: tactic_id -> list of techniques
        matrix: dict[str, list[dict[str, Any]]] = {}
        for tactic_id, tactic_name in TACTICS_ORDER:
            matrix[tactic_id] = []

        for tech_id, tech_info in FULL_TECHNIQUES.items():
            count = counts.get(tech_id, 0)
            heat = self._heat_level(count)
            entry = {
                "id": tech_id,
                "name": tech_info["name"],
                "count": count,
                "heat": heat,
            }
            for tactic_id in tech_info["tactics"]:
                if tactic_id in matrix:
                    matrix[tactic_id].append(entry)

        # Sort each tactic's techniques: detected first, then alphabetically
        for tactic_id in matrix:
            matrix[tactic_id].sort(key=lambda t: (-t["count"], t["name"]))

        total = len(FULL_TECHNIQUES)
        detected = sum(1 for t in FULL_TECHNIQUES if counts.get(t, 0) > 0)

        return {
            "tactics": [{"id": tid, "name": tname} for tid, tname in TACTICS_ORDER],
            "matrix": matrix,
            "total_techniques": total,
            "detected_techniques": detected,
            "coverage_percent": round(detected / total * 100, 1) if total else 0,
        }

    def get_coverage(self) -> dict[str, Any]:
        """Get per-tactic coverage statistics."""
        counts = self.get_detection_counts()

        tactic_stats = []
        for tactic_id, tactic_name in TACTICS_ORDER:
            techniques_in_tactic = [
                tid for tid, info in FULL_TECHNIQUES.items()
                if tactic_id in info["tactics"]
            ]
            total = len(techniques_in_tactic)
            detected = sum(1 for t in techniques_in_tactic if counts.get(t, 0) > 0)
            hit_count = sum(counts.get(t, 0) for t in techniques_in_tactic)

            tactic_stats.append({
                "tactic_id": tactic_id,
                "tactic_name": tactic_name,
                "total_techniques": total,
                "detected_techniques": detected,
                "coverage_percent": round(detected / total * 100, 1) if total else 0,
                "total_hits": hit_count,
            })

        total_all = len(FULL_TECHNIQUES)
        detected_all = sum(1 for t in FULL_TECHNIQUES if counts.get(t, 0) > 0)

        return {
            "overall": {
                "total_techniques": total_all,
                "detected_techniques": detected_all,
                "coverage_percent": round(detected_all / total_all * 100, 1) if total_all else 0,
            },
            "tactics": tactic_stats,
        }

    @staticmethod
    def _heat_level(count: int) -> str:
        """Map detection count to a heat level for visualization."""
        if count == 0:
            return "none"
        elif count <= 2:
            return "low"
        elif count <= 10:
            return "medium"
        elif count <= 25:
            return "high"
        else:
            return "critical"


# Global singleton
mitre_navigator = MitreNavigator()
