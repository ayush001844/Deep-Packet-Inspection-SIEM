"""
PCAP File Analyser
==================
Upload and analyse .pcap / .pcapng files.  Returns protocol statistics,
endpoint information, session summaries, and individual packet records.
"""

from __future__ import annotations

import os
import time
from collections import Counter
from typing import Any

from scapy.all import rdpcap, PcapReader as ScapyPcapReader

from backend.dpi.protocol_parser import parse_packet
from backend.dpi.session_tracker import SessionTracker


def analyse_pcap(filepath: str, max_packets: int = 0) -> dict[str, Any]:
    """
    Analyse a PCAP file and return comprehensive results.

    Parameters
    ----------
    filepath    : Path to a .pcap or .pcapng file
    max_packets : Maximum packets to process (0 = all)

    Returns
    -------
    dict with keys: packets, sessions, stats, protocol_hierarchy, endpoints, conversations
    """
    if not os.path.exists(filepath):
        return {"error": f"File not found: {filepath}"}

    tracker = SessionTracker()
    packets: list[dict[str, Any]] = []
    protocol_counter: Counter = Counter()
    endpoint_bytes: dict[str, dict[str, int]] = {}  # ip -> {sent, recv}
    conversation_bytes: dict[str, int] = {}

    start = time.time()
    pkt_id = 0

    try:
        # Use PcapReader for streaming (memory-efficient for large files)
        with ScapyPcapReader(filepath) as reader:
            for raw_pkt in reader:
                pkt_id += 1
                if max_packets > 0 and pkt_id > max_packets:
                    break

                record = parse_packet(raw_pkt, packet_id=pkt_id)
                packets.append(record)

                # Update flow tracker
                tracker.update(record)

                # Protocol counts
                proto = record.get("protocol", "Unknown")
                protocol_counter[proto] += 1

                # Endpoint tracking
                src = record.get("src_ip", "")
                dst = record.get("dst_ip", "")
                pkt_len = record.get("length", 0)

                if src:
                    if src not in endpoint_bytes:
                        endpoint_bytes[src] = {"sent": 0, "recv": 0, "packets": 0}
                    endpoint_bytes[src]["sent"] += pkt_len
                    endpoint_bytes[src]["packets"] += 1

                if dst:
                    if dst not in endpoint_bytes:
                        endpoint_bytes[dst] = {"sent": 0, "recv": 0, "packets": 0}
                    endpoint_bytes[dst]["recv"] += pkt_len

                # Conversation tracking
                if src and dst:
                    conv_key = f"{min(src, dst)} ↔ {max(src, dst)}"
                    conversation_bytes[conv_key] = conversation_bytes.get(conv_key, 0) + pkt_len

    except Exception as e:
        return {"error": f"Failed to parse PCAP: {str(e)}"}

    elapsed = time.time() - start

    # Build protocol hierarchy
    total_pkts = sum(protocol_counter.values())
    protocol_hierarchy = []
    for proto, count in protocol_counter.most_common():
        protocol_hierarchy.append({
            "protocol": proto,
            "count": count,
            "percentage": round(count / total_pkts * 100, 1) if total_pkts > 0 else 0,
        })

    # Top endpoints
    endpoints = []
    for ip, stats in sorted(endpoint_bytes.items(), key=lambda x: x[1]["sent"] + x[1]["recv"], reverse=True)[:20]:
        endpoints.append({
            "ip": ip,
            "sent_bytes": stats["sent"],
            "recv_bytes": stats["recv"],
            "total_bytes": stats["sent"] + stats["recv"],
            "packets": stats["packets"],
        })

    # Top conversations
    conversations = []
    for conv, total in sorted(conversation_bytes.items(), key=lambda x: x[1], reverse=True)[:20]:
        conversations.append({"conversation": conv, "total_bytes": total})

    # Session summaries
    sessions = tracker.get_flows()
    flow_stats = tracker.get_stats()

    # DNS queries summary
    dns_queries: list[dict[str, str]] = []
    for pkt in packets:
        for layer in pkt.get("layers", []):
            if layer.get("layer") == "DNS" and layer.get("type") == "query":
                dns_queries.append({
                    "query": layer.get("query_name", ""),
                    "type": layer.get("query_type", ""),
                    "timestamp": pkt.get("timestamp", 0),
                })

    # HTTP requests summary
    http_requests: list[dict[str, Any]] = []
    for pkt in packets:
        for layer in pkt.get("layers", []):
            if layer.get("layer") == "HTTP" and layer.get("direction") == "request":
                http_requests.append({
                    "method": layer.get("method", ""),
                    "url": layer.get("url", ""),
                    "host": layer.get("host", ""),
                    "user_agent": layer.get("user_agent", ""),
                    "src_ip": pkt.get("src_ip", ""),
                    "dst_ip": pkt.get("dst_ip", ""),
                    "timestamp": pkt.get("timestamp", 0),
                })

    # TLS connections
    tls_connections: list[dict[str, Any]] = []
    for pkt in packets:
        for layer in pkt.get("layers", []):
            if layer.get("layer") == "TLS":
                tls_connections.append({
                    "sni": layer.get("sni", ""),
                    "tls_version": layer.get("tls_version", ""),
                    "cipher_suite_count": layer.get("cipher_suite_count", 0),
                    "alpn": layer.get("alpn", []),
                    "src_ip": pkt.get("src_ip", ""),
                    "dst_ip": pkt.get("dst_ip", ""),
                    "timestamp": pkt.get("timestamp", 0),
                })

    return {
        "file": os.path.basename(filepath),
        "total_packets": pkt_id,
        "analysis_time_seconds": round(elapsed, 3),
        "packets": packets[:500],  # Cap for API response size
        "sessions": sessions[:100],
        "stats": flow_stats,
        "protocol_hierarchy": protocol_hierarchy,
        "endpoints": endpoints,
        "conversations": conversations,
        "dns_queries": dns_queries[:100],
        "http_requests": http_requests[:100],
        "tls_connections": tls_connections[:100],
    }
