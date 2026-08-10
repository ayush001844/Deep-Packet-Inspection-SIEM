"""
Session / Flow Tracker
======================
Maintains a table of network flows (keyed by 5-tuple) and tracks
TCP state transitions, byte counts, and per-flow metadata.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional

from backend.threat.feeds import threat_feeds
from backend.threat.geoip import get_location


@dataclass
class FlowStats:
    """Statistics for a single network flow."""
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str  # "TCP", "UDP", etc.

    # Counters
    packets_fwd: int = 0   # src → dst
    packets_rev: int = 0   # dst → src
    bytes_fwd: int = 0
    bytes_rev: int = 0

    # Timing
    first_seen: float = 0.0
    last_seen: float = 0.0

    # TCP state
    tcp_state: str = "NEW"        # NEW → SYN_SENT → ESTABLISHED → FIN_WAIT → CLOSED
    syn_seen: bool = False
    syn_ack_seen: bool = False
    fin_seen: bool = False
    rst_seen: bool = False

    # Application layer
    app_protocol: str = ""        # HTTP, TLS, DNS, SSH, …
    sni: str = ""
    http_host: str = ""

    # TCP flags aggregated across the flow
    tcp_flags: list[str] = field(default_factory=list)

    # Threat Intelligence
    src_geo: dict[str, Any] = field(default_factory=dict)
    dst_geo: dict[str, Any] = field(default_factory=dict)
    src_threat: dict[str, Any] = field(default_factory=dict)
    dst_threat: dict[str, Any] = field(default_factory=dict)

    # Detection
    is_suspicious: bool = False
    alerts: list[str] = field(default_factory=list)

    @property
    def duration(self) -> float:
        if self.first_seen and self.last_seen:
            return self.last_seen - self.first_seen
        return 0.0

    @property
    def total_packets(self) -> int:
        return self.packets_fwd + self.packets_rev

    @property
    def total_bytes(self) -> int:
        return self.bytes_fwd + self.bytes_rev

    def to_dict(self) -> dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "app_protocol": self.app_protocol,
            "sni": self.sni,
            "http_host": self.http_host,
            "packets_fwd": self.packets_fwd,
            "packets_rev": self.packets_rev,
            "bytes_fwd": self.bytes_fwd,
            "bytes_rev": self.bytes_rev,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration": round(self.duration, 3),
            "tcp_state": self.tcp_state,
            "src_geo": self.src_geo,
            "dst_geo": self.dst_geo,
            "src_threat": self.src_threat,
            "dst_threat": self.dst_threat,
            "is_suspicious": self.is_suspicious,
            "alerts": self.alerts,
            "tcp_flags": self.tcp_flags,
            "packets": self.total_packets,
        }


def _flow_key(src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: str) -> str:
    """Create a canonical flow key (bidirectional)."""
    fwd = (src_ip, src_port, dst_ip, dst_port, proto)
    rev = (dst_ip, dst_port, src_ip, src_port, proto)
    # Always use the lexicographically smaller direction as the key
    canonical = min(fwd, rev)
    return f"{canonical[0]}:{canonical[1]}-{canonical[2]}:{canonical[3]}/{canonical[4]}"


class SessionTracker:
    """
    Maintains a flow table and updates it with each packet.
    Thread-safe via the GIL (adequate for a single-process FastAPI app).
    """

    def __init__(self, max_flows: int = 100_000):
        self._flows: dict[str, FlowStats] = {}
        self._max_flows = max_flows
        self._total_packets = 0

    # ── Public API ──────────────────────────────────────────────────────

    def update(self, pkt_record: dict[str, Any]) -> Optional[FlowStats]:
        """
        Update the flow table with a parsed packet record (from protocol_parser).
        Returns the updated FlowStats object or None for non-IP packets.
        """
        src_ip = pkt_record.get("src_ip", "")
        dst_ip = pkt_record.get("dst_ip", "")
        src_port = pkt_record.get("src_port", 0)
        dst_port = pkt_record.get("dst_port", 0)
        proto = pkt_record.get("protocol", "")

        if not src_ip or not dst_ip:
            return None

        self._total_packets += 1
        key = _flow_key(src_ip, dst_ip, src_port, dst_port, proto)
        now = pkt_record.get("timestamp", time.time())
        pkt_len = pkt_record.get("length", 0)

        # Get or create flow
        flow = self._flows.get(key)
        if flow is None:
            # Evict oldest flow if at capacity
            if len(self._flows) >= self._max_flows:
                oldest_key = min(self._flows, key=lambda k: self._flows[k].last_seen)
                del self._flows[oldest_key]

            flow = FlowStats(
                flow_id=key,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
                first_seen=now,
            )
            
            # Fast threat intel check on new flow
            t_src = threat_feeds.check_ip(src_ip)
            if t_src["is_malicious"]:
                flow.src_threat = t_src
                flow.is_suspicious = True
                flow.alerts.append(f"Source IP {src_ip} in threat feeds: {', '.join(t_src['feeds_hit'])}")
                
            t_dst = threat_feeds.check_ip(dst_ip)
            if t_dst["is_malicious"]:
                flow.dst_threat = t_dst
                flow.is_suspicious = True
                flow.alerts.append(f"Target IP {dst_ip} in threat feeds: {', '.join(t_dst['feeds_hit'])}")
                
            self._flows[key] = flow

        flow.last_seen = now

        # Determine direction
        is_forward = (src_ip == flow.src_ip and src_port == flow.src_port)
        if is_forward:
            flow.packets_fwd += 1
            flow.bytes_fwd += pkt_len
        else:
            flow.packets_rev += 1
            flow.bytes_rev += pkt_len

        # TCP state tracking
        if proto == "TCP":
            self._update_tcp_state(flow, pkt_record)

        # Update application-layer info
        sni = pkt_record.get("sni", "")
        if sni and not flow.sni:
            flow.sni = sni

        app = pkt_record.get("protocol", "")
        if app and app not in ("TCP", "UDP") and not flow.app_protocol:
            flow.app_protocol = app

        # Check HTTP host from layers
        for layer in pkt_record.get("layers", []):
            if layer.get("layer") == "HTTP" and layer.get("host"):
                flow.http_host = layer["host"]
                break

        return flow

    def get_flows(self) -> list[dict[str, Any]]:
        """Return all active flows as dicts, sorted by last_seen descending."""
        flows = sorted(
            self._flows.values(),
            key=lambda f: f.last_seen,
            reverse=True,
        )
        return [f.to_dict() for f in flows]

    def get_flow(self, flow_id: str) -> Optional[dict[str, Any]]:
        flow = self._flows.get(flow_id)
        return flow.to_dict() if flow else None

    def get_stats(self) -> dict[str, Any]:
        """Return aggregate statistics."""
        active = len(self._flows)
        total_bytes = sum(f.total_bytes for f in self._flows.values())
        tcp_count = sum(1 for f in self._flows.values() if f.protocol == "TCP")
        udp_count = sum(1 for f in self._flows.values() if f.protocol == "UDP")

        # Protocol distribution
        proto_counts: dict[str, int] = {}
        for f in self._flows.values():
            p = f.app_protocol or f.protocol
            proto_counts[p] = proto_counts.get(p, 0) + f.total_packets

        # Top talkers (by bytes)
        ip_bytes: dict[str, int] = {}
        for f in self._flows.values():
            ip_bytes[f.src_ip] = ip_bytes.get(f.src_ip, 0) + f.bytes_fwd
            ip_bytes[f.dst_ip] = ip_bytes.get(f.dst_ip, 0) + f.bytes_rev

        top_talkers = sorted(ip_bytes.items(), key=lambda x: x[1], reverse=True)[:10]

        return {
            "active_flows": active,
            "total_packets": self._total_packets,
            "total_bytes": total_bytes,
            "tcp_flows": tcp_count,
            "udp_flows": udp_count,
            "protocol_distribution": proto_counts,
            "top_talkers": [{"ip": ip, "bytes": b} for ip, b in top_talkers],
        }

    def clear(self) -> None:
        self._flows.clear()
        self._total_packets = 0

    # ── Internal ────────────────────────────────────────────────────────

    def _update_tcp_state(self, flow: FlowStats, pkt: dict[str, Any]) -> None:
        """Simple TCP state machine."""
        flags: list[str] = []
        for layer in pkt.get("layers", []):
            if layer.get("layer") == "TCP":
                flags = layer.get("flags", [])
                flow.tcp_flags.extend(flags)
                break

        if "SYN" in flags and "ACK" not in flags:
            flow.syn_seen = True
            flow.tcp_state = "SYN_SENT"
        elif "SYN" in flags and "ACK" in flags:
            flow.syn_ack_seen = True
            if flow.syn_seen:
                flow.tcp_state = "ESTABLISHED"
        elif "ACK" in flags and flow.syn_seen and flow.syn_ack_seen:
            flow.tcp_state = "ESTABLISHED"
        elif "FIN" in flags:
            flow.fin_seen = True
            flow.tcp_state = "FIN_WAIT"
        elif "RST" in flags:
            flow.rst_seen = True
            flow.tcp_state = "RESET"

        if flow.fin_seen and flow.tcp_state == "FIN_WAIT":
            # Simplified: after FIN we consider it closing
            flow.tcp_state = "CLOSING"
