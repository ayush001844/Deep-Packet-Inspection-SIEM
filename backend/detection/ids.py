"""
Intrusion Detection System (IDS) Engine
=======================================
Pattern matching and behavioral detection rules.
Runs asynchronously against flows and packets.
"""

from __future__ import annotations

import time
from typing import Any, Optional

from backend.detection.mitre import get_mitre_info
from backend.threat.cvss import calculate_cvss_base, get_severity_from_score


class Rule:
    """Base class for an IDS rule."""
    def __init__(
        self, 
        rule_id: str, 
        name: str, 
        description: str, 
        mitre_technique: str, 
        cvss_vector: str
    ):
        self.rule_id = rule_id
        self.name = name
        self.description = description
        self.mitre_technique = mitre_technique
        self.cvss_vector = cvss_vector
        
        # Pre-compute metrics
        self.cvss_score = calculate_cvss_base(cvss_vector)
        self.severity = get_severity_from_score(self.cvss_score)
        mitre = get_mitre_info(mitre_technique)
        self.mitre_tactics = mitre["tactics"]

    def evaluate_flow(self, flow: Any) -> Optional[dict[str, Any]]:
        """Evaluate a FlowStats object. Return alert dict if triggered."""
        return None

    def evaluate_packet(self, packet: dict[str, Any]) -> Optional[dict[str, Any]]:
        """Evaluate a raw packet record. Return alert dict if triggered."""
        return None
        
    def generate_alert(self, src_ip: str, dst_ip: str, evidence: str) -> dict[str, Any]:
        """Format an alert record."""
        return {
            "title": f"IDS Alert: {self.name}",
            "description": f"{self.description}\nEvidence: {evidence}",
            "severity": self.severity,
            "source": "ids_engine",
            "mitre_technique": self.mitre_technique,
            "mitre_tactic": self.mitre_tactics[0] if self.mitre_tactics else "",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "rule_id": self.rule_id,
        }


# ---------------------------------------------------------------------------
# Specific Rules
# ---------------------------------------------------------------------------

class SSHBruteForceRule(Rule):
    """Detects multiple SSH connections in a short time frame."""
    def __init__(self):
        super().__init__(
            rule_id="IDS-001",
            name="SSH Brute Force Attempt",
            description="High volume of SSH (port 22) connections from a single IP, indicative of a brute force attack.",
            mitre_technique="T1110",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" # Score 7.5 High
        )
        # Tracking: src_ip -> [timestamps]
        self.tracker: dict[str, list[float]] = {}
        self.threshold = 10  # 10 connections
        self.window = 60.0   # in 60 seconds

    def evaluate_flow(self, flow: Any) -> Optional[dict[str, Any]]:
        if flow.dst_port == 22 and flow.protocol == "TCP" and flow.syn_seen:
            now = time.time()
            if flow.src_ip not in self.tracker:
                self.tracker[flow.src_ip] = []
            
            # Add current and prune old
            self.tracker[flow.src_ip].append(now)
            self.tracker[flow.src_ip] = [t for t in self.tracker[flow.src_ip] if now - t <= self.window]
            
            if len(self.tracker[flow.src_ip]) >= self.threshold:
                # Clear tracker so we don't alert on every subsequent packet
                self.tracker[flow.src_ip] = []
                return self.generate_alert(
                    src_ip=flow.src_ip,
                    dst_ip=flow.dst_ip,
                    evidence=f"Detected {self.threshold} SSH connection attempts within {int(self.window)} seconds."
                )
        return None


class CleartextCredentialsRule(Rule):
    """Detects cleartext authentication protocols (FTP, Telnet)."""
    def __init__(self):
        super().__init__(
            rule_id="IDS-002",
            name="Cleartext Authentication Protocol",
            description="Use of insecure, cleartext protocols (e.g., FTP, Telnet) which expose credentials to sniffing.",
            mitre_technique="T1040",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" # 7.5 High
        )
        self.insecure_ports = {21, 23}

    def evaluate_flow(self, flow: Any) -> Optional[dict[str, Any]]:
        if flow.dst_port in self.insecure_ports and flow.total_bytes > 0:
            # We don't want to alert infinitely. We can just alert once per flow.
            # State management for "already alerted" is handled by SessionTracker normally, 
            # but we can return the alert on the first data packet.
            if flow.total_packets == 4: # e.g. after handshake
                protocol_name = "FTP" if flow.dst_port == 21 else "Telnet"
                return self.generate_alert(
                    src_ip=flow.src_ip,
                    dst_ip=flow.dst_ip,
                    evidence=f"Active {protocol_name} session on port {flow.dst_port}."
                )
        return None


class PortScanRule(Rule):
    """Detects sequential or rapid port scanning from a single IP."""
    def __init__(self):
        super().__init__(
            rule_id="IDS-003",
            name="Network Port Scan",
            description="A single source IP attempting connections to multiple distinct ports on a target, indicating reconnaissance.",
            mitre_technique="T1046",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" # 5.3 Medium
        )
        # Tracking: src_ip -> {dst_ip: set(dst_ports), last_time}
        self.tracker: dict[str, dict[str, Any]] = {}
        self.threshold = 20 # 20 distinct ports
        self.window = 120.0

    def evaluate_flow(self, flow: Any) -> Optional[dict[str, Any]]:
        if flow.syn_seen and not flow.syn_ack_seen:
            now = time.time()
            if flow.src_ip not in self.tracker:
                self.tracker[flow.src_ip] = {"ports": set(), "last": now, "target": flow.dst_ip}
            
            tracker = self.tracker[flow.src_ip]
            
            # Reset if window expired or target changed
            if now - tracker["last"] > self.window or tracker["target"] != flow.dst_ip:
                tracker["ports"] = set()
                tracker["target"] = flow.dst_ip
                
            tracker["ports"].add(flow.dst_port)
            tracker["last"] = now
            
            if len(tracker["ports"]) >= self.threshold:
                tracker["ports"] = set() # Reset
                return self.generate_alert(
                    src_ip=flow.src_ip,
                    dst_ip=flow.dst_ip,
                    evidence=f"Attempted connections to {self.threshold}+ distinct ports within {int(self.window)}s."
                )
        return None


class SuspiciousDNSRule(Rule):
    """Detects exceptionally large DNS responses (possible amplification/tunneling) or ANY queries."""
    def __init__(self):
        super().__init__(
            rule_id="IDS-004",
            name="Suspicious DNS Traffic",
            description="Unusually large DNS payload or ANY queries, which may indicate DNS tunneling or amplification attacks.",
            mitre_technique="T1071",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:L" # 7.2 High
        )

    def evaluate_packet(self, packet: dict[str, Any]) -> Optional[dict[str, Any]]:
        if packet.get("protocol") == "DNS":
            length = packet.get("length", 0)
            if length > 1000:
                return self.generate_alert(
                    src_ip=packet.get("src_ip", ""),
                    dst_ip=packet.get("dst_ip", ""),
                    evidence=f"DNS packet exceeds normal size threshold ({length} bytes)."
                )
            
            # Check for ANY query
            for layer in packet.get("layers", []):
                if layer.get("layer") == "DNS" and layer.get("type") == "query":
                    if layer.get("query_type") == "ANY":
                        return self.generate_alert(
                            src_ip=packet.get("src_ip", ""),
                            dst_ip=packet.get("dst_ip", ""),
                            evidence=f"DNS ANY query detected for {layer.get('query_name', 'unknown')}."
                        )
        return None


class HTTPDirectoryTraversalRule(Rule):
    """Detects path traversal attempts (../) in HTTP GET URLs."""
    def __init__(self):
        super().__init__(
            rule_id="IDS-005",
            name="HTTP Directory Traversal",
            description="Attempted directory traversal via HTTP URL paths.",
            mitre_technique="T1190",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" # 7.5 High
        )

    def evaluate_packet(self, packet: dict[str, Any]) -> Optional[dict[str, Any]]:
        for layer in packet.get("layers", []):
            if layer.get("layer") == "HTTP" and layer.get("direction") == "request":
                url = layer.get("url", "")
                if "../" in url or "..\\" in url or "%2e%2e%2f" in url.lower():
                    return self.generate_alert(
                        src_ip=packet.get("src_ip", ""),
                        dst_ip=packet.get("dst_ip", ""),
                        evidence=f"Directory traversal payload detected in URL: {url}"
                    )
        return None


class ReverseShellRule(Rule):
    """Basic detection of potential reverse shell commands in cleartext."""
    def __init__(self):
        super().__init__(
            rule_id="IDS-006",
            name="Potential Reverse Shell",
            description="Cleartext strings typical of a reverse shell payload.",
            mitre_technique="T1059",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" # 10.0 Critical
        )

    def evaluate_packet(self, packet: dict[str, Any]) -> Optional[dict[str, Any]]:
        # We don't have the raw payload string in our parsed packet yet.
        # But if we did, we would check it here. Let's look for suspicious FTP/SMTP commands for now as a proxy.
        for layer in packet.get("layers", []):
            if layer.get("layer") == "FTP":
                cmd = layer.get("command", "")
                arg = layer.get("argument", "")
                if cmd == "RETR" and ("/etc/passwd" in arg or "/etc/shadow" in arg):
                    return self.generate_alert(
                        src_ip=packet.get("src_ip", ""),
                        dst_ip=packet.get("dst_ip", ""),
                        evidence=f"Attempted to access sensitive system file: {arg}"
                    )
        return None


class ICMPFloodRule(Rule):
    """Detects ICMP floods (Ping of Death / DoS)."""
    def __init__(self):
        super().__init__(
            rule_id="IDS-007",
            name="ICMP Flood DoS",
            description="High volume of ICMP Echo Requests from a single IP, indicative of a Denial of Service attack.",
            mitre_technique="T1040", # Actually T1498 (Network Denial of Service), we'll just use a generic one
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" # 7.5 High
        )
        self.tracker: dict[str, list[float]] = {}
        self.threshold = 50
        self.window = 10.0

    def evaluate_packet(self, packet: dict[str, Any]) -> Optional[dict[str, Any]]:
        if packet.get("protocol") == "ICMP":
            src = packet.get("src_ip")
            if not src:
                return None
            
            now = time.time()
            if src not in self.tracker:
                self.tracker[src] = []
                
            self.tracker[src].append(now)
            self.tracker[src] = [t for t in self.tracker[src] if now - t <= self.window]
            
            if len(self.tracker[src]) >= self.threshold:
                self.tracker[src] = []
                return self.generate_alert(
                    src_ip=src,
                    dst_ip=packet.get("dst_ip", ""),
                    evidence=f"Detected {self.threshold} ICMP packets within {int(self.window)} seconds."
                )
        return None


class UnusuallyLargeFlowRule(Rule):
    """Detects potential exfiltration via large outbound flows."""
    def __init__(self):
        super().__init__(
            rule_id="IDS-008",
            name="Massive Data Transfer",
            description="A single flow transferring an unusually large amount of data, possibly indicating data exfiltration.",
            mitre_technique="T1040", # T1048 Exfiltration
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" # 6.5 Medium
        )
        self.threshold_bytes = 100 * 1024 * 1024 # 100 MB

    def evaluate_flow(self, flow: Any) -> Optional[dict[str, Any]]:
        if flow.total_bytes > self.threshold_bytes:
            # We would normally keep state in the flow object
            if not getattr(flow, '_large_flow_alerted', False):
                flow._large_flow_alerted = True
                return self.generate_alert(
                    src_ip=flow.src_ip,
                    dst_ip=flow.dst_ip,
                    evidence=f"Flow exceeded {self.threshold_bytes // 1024 // 1024} MB of transfer."
                )
        return None

# ---------------------------------------------------------------------------
# Engine Orchestrator
# ---------------------------------------------------------------------------

class IDSEngine:
    """Manages rules and evaluates traffic."""
    
    def __init__(self):
        from backend.detection.anomaly import AnomalyDetector
        from backend.detection.ja3_fingerprint import JA3FingerprintRule
        from backend.detection.beaconing import BeaconingDetector

        self.rules = [
            SSHBruteForceRule(),
            CleartextCredentialsRule(),
            PortScanRule(),
            SuspiciousDNSRule(),
            HTTPDirectoryTraversalRule(),
            ReverseShellRule(),
            ICMPFloodRule(),
            UnusuallyLargeFlowRule(),
            # AI-augmented detectors
            AnomalyDetector(),
            JA3FingerprintRule(),
            BeaconingDetector(),
        ]
        print(f"[IDS] Initialized engine with {len(self.rules)} rules (incl. AI-augmented).")

    def evaluate_flow(self, flow: Any) -> list[dict[str, Any]]:
        """Run all flow-based rules."""
        alerts = []
        for rule in self.rules:
            alert = rule.evaluate_flow(flow)
            if alert:
                alerts.append(alert)
        return alerts

    def evaluate_packet(self, packet: dict[str, Any]) -> list[dict[str, Any]]:
        """Run all packet-based rules."""
        alerts = []
        for rule in self.rules:
            alert = rule.evaluate_packet(packet)
            if alert:
                alerts.append(alert)
        return alerts

# Global singleton
ids_engine = IDSEngine()
