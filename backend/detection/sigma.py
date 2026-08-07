"""
Sigma Engine Scaffolding
========================
Sigma is a generic signature format for SIEM systems.
Here we implement a lightweight rule matcher that evaluates
parsed packet dictionaries against Sigma-like key-value conditions.
"""

from __future__ import annotations

from typing import Any, Optional

class SigmaRule:
    def __init__(self, rule_id: str, name: str, conditions: dict[str, Any], severity: str = "medium"):
        self.rule_id = rule_id
        self.name = name
        self.conditions = conditions
        self.severity = severity

    def match(self, record: dict[str, Any]) -> bool:
        """
        Evaluate if a parsed packet record matches all conditions.
        Handles nested keys via dot notation (e.g., 'http.method').
        """
        for key, expected_val in self.conditions.items():
            # Check if condition is a layer-specific check
            if key.startswith("layer."):
                layer_type, field = key.split(".", 1)[1].split(".", 1)
                found = False
                for layer in record.get("layers", []):
                    if layer.get("layer") == layer_type:
                        if layer.get(field) == expected_val:
                            found = True
                            break
                if not found:
                    return False
            else:
                # Top level field
                if record.get(key) != expected_val:
                    return False
                    
        return True

class SigmaEngine:
    def __init__(self):
        # Sample Sigma-like rules for structured log inspection
        self.rules = [
            SigmaRule(
                rule_id="SIGMA-001",
                name="Suspicious DNS TXT Query",
                conditions={
                    "protocol": "DNS",
                    "layer.DNS.type": "query",
                    "layer.DNS.query_type": "TXT"
                },
                severity="low"
            ),
            SigmaRule(
                rule_id="SIGMA-002",
                name="Suspicious User-Agent (Nmap)",
                conditions={
                    "protocol": "HTTP",
                    "layer.HTTP.direction": "request",
                    "layer.HTTP.user_agent": "nmap tool"
                },
                severity="medium"
            )
        ]
        print(f"[Sigma] Initialized engine with {len(self.rules)} rules.")

    def evaluate_record(self, record: dict[str, Any]) -> list[dict[str, Any]]:
        alerts = []
        for rule in self.rules:
            if rule.match(record):
                alerts.append({
                    "title": f"Sigma Match: {rule.name}",
                    "description": f"Log event matched Sigma rule {rule.rule_id}",
                    "severity": rule.severity,
                    "source": "sigma_engine",
                    "mitre_technique": "",
                    "mitre_tactic": "",
                    "src_ip": record.get("src_ip", ""),
                    "dst_ip": record.get("dst_ip", ""),
                    "cvss_score": 4.0 if rule.severity == "medium" else 2.0,
                    "cvss_vector": "",
                    "rule_id": rule.rule_id,
                })
        return alerts

sigma_engine = SigmaEngine()
