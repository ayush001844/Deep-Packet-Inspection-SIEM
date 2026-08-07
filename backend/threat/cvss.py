"""
CVSS 3.1 Scoring Engine
=======================
Calculates CVSS Base Scores for generated alerts.
For a network IDS, many alerts fall under similar vectors.
This provides a simple calculator for those vectors.
"""

from __future__ import annotations

# Standard CVSS 3.1 metrics weightings
# Base Score = RoundUp(Minimum(1.08 * Impact + Exploitability, 10))

METRICS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},  # Attack Vector
    "AC": {"L": 0.77, "H": 0.44},                        # Attack Complexity
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},             # Privileges Required
    "UI": {"N": 0.85, "R": 0.62},                        # User Interaction
    "S":  {"U": 6.42, "C": 7.52},                        # Scope (Impact multiplier)
    "C":  {"H": 0.56, "L": 0.22, "N": 0.0},              # Confidentiality
    "I":  {"H": 0.56, "L": 0.22, "N": 0.0},              # Integrity
    "A":  {"H": 0.56, "L": 0.22, "N": 0.0},              # Availability
}

def calculate_cvss_base(vector: str) -> float:
    """
    Calculate CVSS 3.1 Base Score from a vector string.
    e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    """
    if not vector.startswith("CVSS:3.1/"):
        return 0.0

    parts = vector.replace("CVSS:3.1/", "").split("/")
    parsed = {}
    for p in parts:
        if ":" in p:
            k, v = p.split(":", 1)
            parsed[k] = v

    try:
        # Exploitability Subscore (ESS)
        av = METRICS["AV"][parsed.get("AV", "N")]
        ac = METRICS["AC"][parsed.get("AC", "L")]
        pr_scope = "U" if parsed.get("S", "U") == "U" else "C"
        # PR has different weights based on Scope in official CVSS,
        # but for simplicity we use the base weight
        pr = METRICS["PR"][parsed.get("PR", "N")]
        ui = METRICS["UI"][parsed.get("UI", "N")]
        
        ess = 8.22 * av * ac * pr * ui

        # Impact Subscore (ISS)
        c = METRICS["C"][parsed.get("C", "N")]
        i = METRICS["I"][parsed.get("I", "N")]
        a = METRICS["A"][parsed.get("A", "N")]
        
        iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
        
        if iss <= 0:
            return 0.0
            
        scope = parsed.get("S", "U")
        if scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02)**15)
            
        # Base Score
        if scope == "U":
            base = min(impact + ess, 10.0)
        else:
            base = min(1.08 * (impact + ess), 10.0)
            
        # Round up to 1 decimal
        import math
        return math.ceil(base * 10) / 10.0
        
    except (KeyError, ValueError):
        return 0.0

def get_severity_from_score(score: float) -> str:
    """Return severity label for CVSS score."""
    if score >= 9.0: return "critical"
    if score >= 7.0: return "high"
    if score >= 4.0: return "medium"
    if score > 0.0: return "low"
    return "info"
