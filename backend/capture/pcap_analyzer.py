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
from backend.ml.predictor import predictor as ml_predictor
from backend.detection.ids import ids_engine
from backend.db.database import save_alert
from backend.detection.risk_scoring import risk_scorer
from backend.detection.classifier import classifier
from backend.firewall import firewall


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
    
    # Run ML and IDS on all completed flows from the PCAP
    pcap_alerts = []  # Collect all alerts for threat summary
    for flow in tracker._flows.values():
        # Run IDS rules
        flow_alerts = ids_engine.evaluate_flow(flow)
        for alert_data in flow_alerts:
            alert_data = classifier.classify(alert_data)
            save_alert(**alert_data)
            pcap_alerts.append(alert_data)
            
        # Run ML Inference
        if ml_predictor.is_loaded and getattr(flow, 'total_packets', 0) > 3:
            ml_result = ml_predictor.predict_flow(flow)
            
            # Format prediction for the dashboard feed
            # (We import recent_ml_alerts dynamically to avoid circular import)
            from backend.main import recent_ml_alerts
            recent_ml_alerts.append({
                "timestamp": time.time(),
                "src_ip": flow.src_ip,
                "dst_ip": flow.dst_ip,
                "attack_type": ml_result["attack"],
                "confidence": ml_result["confidence"],
                "is_attack": ml_result["is_attack"]
            })
            
            if ml_result["is_attack"] and ml_result["confidence"] > 0.85:
                if not getattr(flow, '_ml_alerted', False):
                    flow._ml_alerted = True
                    ml_alert = {
                        "title": f"ML Detection: {ml_result['attack']}",
                        "description": f"[From PCAP] AI model detected anomalous flow pattern indicative of {ml_result['attack']}. Confidence: {ml_result['confidence']*100:.1f}%\n" +
                                       f"Packets: {flow.total_packets}, Bytes: {flow.total_bytes}, Duration: {getattr(flow, 'duration', 0.0):.2f}s",
                        "severity": ml_result["severity"].lower(),
                        "source": "ml_ensemble",
                        "src_ip": flow.src_ip,
                        "dst_ip": flow.dst_ip,
                        "cvss_score": 8.0,
                        "raw_data": ml_result
                    }
                    ml_alert = classifier.classify(ml_alert)
                    save_alert(**ml_alert)
                    pcap_alerts.append(ml_alert)
                    risk_scorer.add_factor(flow.src_ip, "ml_high_confidence")

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

    # ── Threat Intelligence Summary ──
    suspicious_count = len(pcap_alerts)
    critical_count = sum(1 for a in pcap_alerts if a.get("severity") == "critical")
    high_count = sum(1 for a in pcap_alerts if a.get("severity") == "high")

    # Build risk indicators from alerts
    risk_indicators = []
    seen_classifications = set()
    for a in pcap_alerts:
        cls = a.get("classification", "")
        if cls and cls not in seen_classifications:
            seen_classifications.add(cls)
            risk_indicators.append({
                "classification": cls,
                "mitre_technique": a.get("mitre_technique", ""),
                "mitre_tactic": a.get("mitre_tactic", ""),
                "severity": a.get("severity", "medium"),
                "title": a.get("title", ""),
            })

    # Determine overall threat verdict
    if critical_count > 0:
        threat_verdict = "Critical Threat Detected"
    elif high_count > 2:
        threat_verdict = "Possible Botnet / C2 Activity"
    elif high_count > 0:
        threat_verdict = "Suspicious Activity Detected"
    elif suspicious_count > 0:
        threat_verdict = "Low-Level Anomalies Found"
    else:
        threat_verdict = "Clean Traffic"

    # Top talkers with threat assessment
    top_talkers = []
    alert_ips = Counter()
    for a in pcap_alerts:
        src = a.get("src_ip", "")
        if src:
            alert_ips[src] += 1

    for ep in endpoints[:5]:
        ip = ep["ip"]
        alert_count = alert_ips.get(ip, 0)
        if alert_count > 2:
            verdict = "Malicious"
        elif alert_count > 0:
            verdict = "Suspicious"
        else:
            verdict = "Clean"
        top_talkers.append({
            **ep,
            "alert_count": alert_count,
            "threat_verdict": verdict,
        })

    threat_summary = {
        "threat_verdict": threat_verdict,
        "suspicious_count": suspicious_count,
        "critical_count": critical_count,
        "high_count": high_count,
        "risk_indicators": risk_indicators,
        "top_talkers": top_talkers,
        "alerts": [
            {
                "title": a.get("title", ""),
                "severity": a.get("severity", ""),
                "classification": a.get("classification", ""),
                "mitre_technique": a.get("mitre_technique", ""),
                "src_ip": a.get("src_ip", ""),
                "dst_ip": a.get("dst_ip", ""),
            }
            for a in pcap_alerts[:20]
        ],
    }

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
        "threat_summary": threat_summary,
    }
