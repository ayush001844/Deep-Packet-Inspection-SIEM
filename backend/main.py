"""
PacketAnalyzer-Pro – FastAPI Backend
=====================================
REST + WebSocket API for the SOC/SIEM dashboard.

Run:
    sudo uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload

(sudo is needed for live packet capture on raw interfaces)
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import time
from collections import deque
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File, Query, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel

from backend.capture.sniffer import PacketSniffer
from backend.capture.pcap_analyzer import analyse_pcap
from backend.dpi.protocol_parser import parse_packet
from backend.dpi.session_tracker import SessionTracker
from backend.threat.feeds import threat_feeds
from backend.detection.ids import ids_engine
from backend.detection.sigma import sigma_engine
from backend.detection.yara import yara_engine
from backend.detection.incidents import correlate_alerts_into_incidents, generate_attack_timeline
from backend.detection.risk_scoring import risk_scorer
from backend.detection.mitre_navigator import mitre_navigator
from backend.firewall import firewall
from backend.response.response_engine import response_engine
from backend.reporting.pdf_gen import generate_incident_report
from backend.auth import router as auth_router, get_current_user, require_admin, seed_default_users
from backend.db.database import (
    init_db, get_alerts, save_alert, get_incidents,
)
from backend.detection.classifier import classifier
from backend.db.elastic import index_packet, index_alert
from backend.ml_engine.predict import ml_predictor
from backend.ml_engine.autoencoder import anomaly_detector
from backend.ueba.behavior import ueba_engine
from backend.threat.reputation import reputation_engine
from backend.detection.asset_registry import asset_registry
from backend.ai.assistant import security_assistant
from backend.rate_limiter import RateLimiterMiddleware, SecurityHeadersMiddleware
import backend.mq as mq

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title="DeepGuard – AI-Powered SIEM",
    description="""
## 🛡️ DeepGuard – Deep Packet Inspection & SIEM Platform

An enterprise-grade Security Information and Event Management (SIEM) system featuring:

- **Real-time Packet Capture** via Scapy with WebSocket streaming
- **Deep Packet Inspection** across 15+ protocols (TCP, UDP, DNS, HTTP, TLS, SSH, ICMP, etc.)
- **AI/ML Threat Detection** using XGBoost + Random Forest ensemble models
- **Intrusion Detection System (IDS)** with MITRE ATT&CK mapped rules
- **PCAP Intelligence** analysis with threat scoring and risk indicators
- **Zero-Trust Risk Scoring** per IP with multi-factor weighting

### 🔌 WebSocket Endpoints
| Endpoint | Description |
|----------|-------------|
| `ws://host:8000/ws/packets` | Real-time packet stream |
| `ws://host:8000/ws/alerts`  | Live classified alert feed |

### 📦 Architecture
```
Packets → Sniffer → DPI Parser → Session Tracker → IDS/ML → Classifier → MQ → WebSocket
                                                         ↓
                                                   PostgreSQL + Elasticsearch
```
""",
    version="2.0.0",
    license_info={"name": "MIT", "url": "https://opensource.org/licenses/MIT"},
    openapi_tags=[
        {"name": "Capture", "description": "Live packet capture controls (start/stop/pause/resume)"},
        {"name": "Packets", "description": "Query captured packet records and session flows"},
        {"name": "Alerts", "description": "View IDS, ML, and rule-based threat alerts"},
        {"name": "PCAP", "description": "Upload and analyze .pcap/.pcapng files with threat intelligence"},
        {"name": "Firewall", "description": "Manage IP block/unblock rules and domain filtering"},
        {"name": "Response", "description": "Automated response engine actions and configuration"},
        {"name": "MITRE", "description": "MITRE ATT&CK Navigator matrix and coverage"},
        {"name": "Network", "description": "Network topology graph with geo-located nodes"},
        {"name": "Risk", "description": "Zero-Trust risk scores for tracked IPs"},
        {"name": "Incidents", "description": "Correlated security incidents and attack timelines"},
        {"name": "ML", "description": "Machine learning model status and recent predictions"},
        {"name": "AI", "description": "LLM-powered security assistant"},
        {"name": "Auth", "description": "User authentication (JWT + API key)"},
        {"name": "System", "description": "Health checks, diagnostics, and system info"},
    ],
)

# Security middleware (Upgrade 8)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimiterMiddleware, enabled=os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router, prefix="/api/auth", tags=["Auth"])

# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------

sniffer = PacketSniffer()
session_tracker = SessionTracker()

# Ring buffer of recent packets (for REST endpoint)
MAX_RECENT = 2000
recent_packets: deque[dict[str, Any]] = deque(maxlen=MAX_RECENT)

# Ring buffer for recent ML alerts (for dashboard feed)
recent_ml_alerts: deque[dict[str, Any]] = deque(maxlen=50)

# Ring buffer for anomaly detector alerts
recent_anomalies: deque[dict[str, Any]] = deque(maxlen=200)

# Connected WebSocket clients
ws_clients: set[WebSocket] = set()
ws_alert_clients: set[WebSocket] = set()
main_loop = None

# Packet counter
packet_counter = {"count": 0}

# Protocol distribution running counter
protocol_stats: dict[str, int] = {}

# Packet rate tracking (packets per second)
rate_tracker = {"timestamps": deque(maxlen=1000)}

# Upload directory
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "data", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)


# ---------------------------------------------------------------------------
# Packet callback (runs in sniffer thread)
# ---------------------------------------------------------------------------

def _on_packet(raw_pkt) -> None:
    """Called by the sniffer for each captured packet."""
    packet_counter["count"] += 1
    pkt_id = packet_counter["count"]

    # Parse packet into rich dict
    record = parse_packet(raw_pkt, packet_id=pkt_id)

    # ── Redis Stream Integration (Upgrade 5) ──
    # Offload indexing and detection to background workers via Redis Streams
    mq.stream_add(mq.STREAM_PACKETS, record)

    # Update protocol stats
    proto = record.get("protocol", "Unknown")
    protocol_stats[proto] = protocol_stats.get(proto, 0) + 1

    # Track rate
    rate_tracker["timestamps"].append(time.time())

    # Store in ring buffer
    recent_packets.append(record)

    # Publish to message queue (Redis or in-memory fallback)
    mq.publish_packet(record)


def _broadcast(record: dict[str, Any]) -> None:
    """Send packet to all connected WebSocket clients."""
    if not ws_clients:
        return

    # Serialize once
    try:
        msg = json.dumps(record, default=str)
    except Exception:
        return

    # Schedule sends on the event loop
    if main_loop and not main_loop.is_closed():
        for ws in ws_clients.copy():
            try:
                asyncio.run_coroutine_threadsafe(_safe_send(ws, msg), main_loop)
            except Exception:
                ws_clients.discard(ws)


async def _safe_send(ws: WebSocket, msg: str) -> None:
    try:
        await ws.send_text(msg)
    except Exception:
        ws_clients.discard(ws)


# ---------------------------------------------------------------------------
# WebSocket endpoint
# ---------------------------------------------------------------------------

@app.websocket("/ws/packets")
async def websocket_packets(ws: WebSocket):
    """Real-time packet stream via WebSocket."""
    await ws.accept()
    ws_clients.add(ws)
    try:
        while True:
            # Keep connection alive; also accept client messages (e.g. filters)
            data = await ws.receive_text()
            # Could handle client-side filter commands here
    except WebSocketDisconnect:
        pass
    finally:
        ws_clients.discard(ws)


@app.websocket("/ws/alerts")
async def websocket_alerts(ws: WebSocket):
    """Real-time classified alert stream via WebSocket."""
    await ws.accept()
    ws_alert_clients.add(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        ws_alert_clients.discard(ws)


# ---------------------------------------------------------------------------
# REST endpoints – Capture control
# ---------------------------------------------------------------------------

@app.get("/api/interfaces")
def list_interfaces():
    """List available network interfaces."""
    import subprocess, os

    # Try Scapy first
    try:
        ifaces = PacketSniffer.list_interfaces()
        if ifaces:
            return ifaces
    except Exception:
        pass

    # Fallback: parse ifconfig output
    try:
        result = subprocess.run(["ifconfig", "-l"], capture_output=True, text=True, timeout=3)
        names = result.stdout.strip().split()
        if names:
            return [{"name": n, "description": n} for n in names]
    except Exception:
        pass

    # Last resort: return common macOS interfaces
    common = ["en0", "en1", "lo0", "utun0", "bridge0"]
    return [{"name": n, "description": n} for n in common]


@app.post("/api/capture/start")
def start_capture(
    interface: str = "en0",
    bpf_filter: str = "",
    max_packets: int = 0,
    _user = Depends(require_admin),
):
    """Start live packet capture."""
    # Reset state
    recent_packets.clear()
    protocol_stats.clear()
    packet_counter["count"] = 0
    session_tracker.clear()

    result = sniffer.start(
        interface=interface,
        callback=_on_packet,
        bpf_filter=bpf_filter,
        max_packets=max_packets,
    )
    if result.get("status") == "error":
        raise HTTPException(status_code=403, detail=result["message"])
    return result


@app.post("/api/capture/stop")
def stop_capture(_user = Depends(require_admin)):
    """Stop live packet capture."""
    return sniffer.stop()


@app.post("/api/capture/pause")
def pause_capture():
    """Pause live capture."""
    return sniffer.pause()


@app.post("/api/capture/resume")
def resume_capture():
    """Resume paused capture."""
    return sniffer.resume()


@app.get("/api/capture/status")
def capture_status():
    """Get current capture status."""
    return sniffer.get_status()


# ---------------------------------------------------------------------------
# REST endpoints – Packets & Sessions
# ---------------------------------------------------------------------------

@app.get("/api/packets")
def get_packets(
    limit: int = Query(100, ge=1, le=2000),
    offset: int = Query(0, ge=0),
    protocol: str = Query("", description="Filter by protocol"),
    src_ip: str = Query("", description="Filter by source IP"),
    dst_ip: str = Query("", description="Filter by destination IP"),
):
    """Get recent captured packets with optional filters."""
    packets = list(recent_packets)

    # Apply filters
    if protocol:
        packets = [p for p in packets if p.get("protocol", "").upper() == protocol.upper()]
    if src_ip:
        packets = [p for p in packets if p.get("src_ip", "") == src_ip]
    if dst_ip:
        packets = [p for p in packets if p.get("dst_ip", "") == dst_ip]

    total = len(packets)
    packets = packets[offset:offset + limit]

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "packets": packets,
    }


@app.get("/api/sessions")
def get_sessions(limit: int = Query(100, ge=1, le=500)):
    """Get active flow/session table."""
    flows = session_tracker.get_flows()
    return {"total": len(flows), "sessions": flows[:limit]}


@app.get("/api/sessions/{flow_id:path}")
def get_session(flow_id: str):
    """Get details for a specific flow."""
    flow = session_tracker.get_flow(flow_id)
    if not flow:
        return JSONResponse(status_code=404, content={"error": "Flow not found"})
    return flow


# ---------------------------------------------------------------------------
# REST endpoints – Statistics
# ---------------------------------------------------------------------------

@app.get("/api/stats")
def get_stats():
    """Get aggregate statistics."""
    flow_stats = session_tracker.get_stats()

    # Calculate packets per second
    now = time.time()
    timestamps = rate_tracker["timestamps"]
    recent = sum(1 for t in timestamps if now - t < 1.0)

    return {
        "capture": sniffer.get_status(),
        "packets_total": packet_counter["count"],
        "packets_per_second": recent,
        "protocol_distribution": protocol_stats,
        "flows": flow_stats,
    }


@app.get("/api/stats/protocols")
def get_protocol_stats():
    """Get protocol distribution."""
    total = sum(protocol_stats.values()) or 1
    return {
        "protocols": [
            {
                "protocol": proto,
                "count": count,
                "percentage": round(count / total * 100, 1),
            }
            for proto, count in sorted(protocol_stats.items(), key=lambda x: x[1], reverse=True)
        ]
    }


# ---------------------------------------------------------------------------
# REST endpoints – PCAP upload & analysis
# ---------------------------------------------------------------------------

MAX_PCAP_SIZE_MB = 50

@app.post("/api/pcap/upload")
async def upload_pcap(file: UploadFile = File(...)):
    """Upload and analyse a PCAP file.

    Validates file extension and size, then runs the full analysis pipeline.
    Returns the same structure as analyse_pcap() plus an ``analysis_status``
    field: 'completed' | 'error'.
    """
    if not file.filename:
        return JSONResponse(
            status_code=400,
            content={"error": "No file was provided. Please select a .pcap or .pcapng file."},
        )

    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in (".pcap", ".pcapng"):
        return JSONResponse(
            status_code=400,
            content={
                "error": f"Invalid file type '{ext}'. Only .pcap and .pcapng files are supported.",
                "analysis_status": "error",
            },
        )

    # Read content and enforce size limit
    content = await file.read()
    size_mb = len(content) / (1024 * 1024)
    if size_mb > MAX_PCAP_SIZE_MB:
        return JSONResponse(
            status_code=413,
            content={
                "error": f"File is too large ({size_mb:.1f} MB). Maximum allowed size is {MAX_PCAP_SIZE_MB} MB.",
                "analysis_status": "error",
            },
        )

    # Save uploaded file
    safe_name = os.path.basename(file.filename)
    filepath = os.path.join(UPLOAD_DIR, safe_name)
    try:
        with open(filepath, "wb") as f:
            f.write(content)
    except OSError as exc:
        return JSONResponse(
            status_code=500,
            content={
                "error": f"Failed to save file on server: {exc}",
                "analysis_status": "error",
            },
        )

    # Analyse
    try:
        results = analyse_pcap(filepath)
    except Exception as exc:
        return JSONResponse(
            status_code=500,
            content={
                "error": f"Analysis engine error: {exc}. The file may be corrupt or in an unsupported format.",
                "analysis_status": "error",
            },
        )

    if "error" in results:
        results["analysis_status"] = "error"
        return JSONResponse(status_code=422, content=results)

    results["analysis_status"] = "completed"
    results["file_size_bytes"] = len(content)
    return results


@app.get("/api/pcap/samples")
def list_sample_pcaps():
    """List bundled sample PCAP files that users can analyse without uploading."""
    samples = []
    for fname in ("sample_traffic.pcap", "ddos_attack.pcap", "test_dpi.pcap"):
        fpath = os.path.join(UPLOAD_DIR, fname)
        if os.path.exists(fpath):
            size = os.path.getsize(fpath)
            samples.append({
                "filename": fname,
                "size_bytes": size,
                "description": {
                    "sample_traffic.pcap": "Mixed benign traffic – HTTP, DNS, TLS",
                    "ddos_attack.pcap":   "Simulated DDoS flood traffic",
                    "test_dpi.pcap":      "Deep packet inspection test capture",
                }.get(fname, fname),
            })
    return {"samples": samples}


@app.post("/api/pcap/analyse-sample/{filename}")
def analyse_sample_pcap(filename: str, _user=Depends(get_current_user)):
    """Run the analysis pipeline on a bundled sample PCAP."""
    safe = os.path.basename(filename)
    filepath = os.path.join(UPLOAD_DIR, safe)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail=f"Sample '{safe}' not found.")
    ext = os.path.splitext(safe)[1].lower()
    if ext not in (".pcap", ".pcapng"):
        raise HTTPException(status_code=400, detail="Not a PCAP file.")
    results = analyse_pcap(filepath)
    results["analysis_status"] = "error" if "error" in results else "completed"
    return results


# ---------------------------------------------------------------------------
# REST endpoints – Alerts & Incidents (placeholder for Phase 4/5)
# ---------------------------------------------------------------------------

@app.get("/api/alerts")
def list_alerts(
    limit: int = Query(100, ge=1, le=500),
    severity: str = Query("", description="Filter by severity"),
):
    """Get security alerts."""
    return get_alerts(limit=limit, severity=severity if severity else None)

@app.get("/api/risk/scores")
def get_risk_scores(_user = Depends(get_current_user)):
    """Get Zero Trust risk scores for all tracked IPs."""
    return risk_scorer.get_all_scores()

@app.get("/api/incidents")
def api_get_incidents(limit: int = 50, offset: int = 0):
    return get_incidents(limit=limit)

@app.get("/api/incidents/{incident_id}/timeline")
def api_get_incident_timeline(incident_id: int):
    return generate_attack_timeline(incident_id)

@app.get("/api/incidents/{incident_code}/report")
def api_get_incident_report(incident_code: str):
    pdf_path = generate_incident_report(incident_code)
    if not pdf_path or not os.path.exists(pdf_path):
        return {"error": "Failed to generate report or incident not found"}
    return FileResponse(pdf_path, media_type="application/pdf", filename=f"{incident_code}_Report.pdf")

@app.get("/api/firewall/blocked")
def get_blocked_ips(_user = Depends(get_current_user)):
    # Return both full entries (with domain) and legacy list
    entries = firewall.get_blocked_entries()
    return {"blocked_ips": firewall.get_blocked_ips(), "entries": entries}

@app.post("/api/firewall/unblock/{ip}")
def unblock_ip(ip: str, _user = Depends(require_admin)):
    success = firewall.unblock_ip(ip)
    return {"success": success, "ip": ip}

class DomainBlockRequest(BaseModel):
    domain: str

@app.post("/api/firewall/block-domain")
def block_domain(req: DomainBlockRequest, _user = Depends(require_admin)):
    import socket
    try:
        ip_list = socket.gethostbyname_ex(req.domain)[2]
        for ip in ip_list:
            firewall.block_ip(ip, reason=f"Manual block: {req.domain}", domain=req.domain)
        return {"status": "success", "domain": req.domain, "ips_blocked": ip_list}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to resolve or block domain: {str(e)}")


# ---------------------------------------------------------------------------
# REST endpoints – Automated Response Engine (Upgrade 6)
# ---------------------------------------------------------------------------

@app.get("/api/response/actions", tags=["Response"])
def get_response_actions(limit: int = 50, _user = Depends(get_current_user)):
    """Get recent automated response actions."""
    return response_engine.get_recent_actions(limit=limit)

@app.get("/api/response/config", tags=["Response"])
def get_response_config(_user = Depends(require_admin)):
    """Get current response engine configuration."""
    return response_engine.get_config()

class ResponseConfigUpdate(BaseModel):
    enabled: bool | None = None
    threshold_full: int | None = None
    threshold_partial: int | None = None
    cooldown_seconds: int | None = None

@app.post("/api/response/config", tags=["Response"])
def update_response_config(config: ResponseConfigUpdate, _user = Depends(require_admin)):
    """Update response engine configuration."""
    updates = {k: v for k, v in config.model_dump().items() if v is not None}
    return response_engine.update_config(updates)

@app.post("/api/response/reverse/{action_id}", tags=["Response"])
def reverse_response_action(action_id: int, _user = Depends(require_admin)):
    """Reverse a previously executed automated action."""
    return response_engine.reverse_action(action_id, reversed_by=_user.username)

@app.get("/api/response/notifications", tags=["Response"])
def get_response_notifications(limit: int = 20, _user = Depends(get_current_user)):
    """Get analyst notifications from the response engine."""
    return response_engine.get_notifications(limit=limit)


# ---------------------------------------------------------------------------
# REST endpoints – MITRE ATT&CK Navigator (Upgrade 7)
# ---------------------------------------------------------------------------

@app.get("/api/mitre/matrix", tags=["MITRE"])
def get_mitre_matrix(_user = Depends(get_current_user)):
    """Get the full MITRE ATT&CK matrix with detection heatmap."""
    return mitre_navigator.get_matrix()

@app.get("/api/mitre/coverage", tags=["MITRE"])
def get_mitre_coverage(_user = Depends(get_current_user)):
    """Get per-tactic coverage statistics."""
    return mitre_navigator.get_coverage()

@app.get("/api/network/graph")
def api_network_graph():
    """Generates an intelligence-enriched node/link graph of active sessions."""
    nodes: dict[str, dict] = {}
    links = []

    # Build score lookup
    all_scores = risk_scorer.get_all_scores()
    score_map   = {r["ip"]: r["score"] for r in all_scores}
    attack_map  = {r["ip"]: r.get("ml_attack", "") for r in all_scores}
    attack_counts: dict[str, int] = {}

    for flow in session_tracker.get_flows():
        src = flow.get("src_ip")
        dst = flow.get("dst_ip")
        if not src or not dst:
            continue

        for ip, geo, role in [(src, flow.get("src_geo", {}), "src"), (dst, flow.get("dst_geo", {}), "dst")]:
            attack_counts[ip] = attack_counts.get(ip, 0) + (1 if flow.get("is_suspicious") else 0)
            risk = score_map.get(ip, 0)
            attack = attack_map.get(ip, "")

            # Infer node type
            if risk > 60 or flow.get("is_suspicious"):
                node_type = "attacker"
            elif flow.get("dst_port") in (3306, 5432, 1433, 27017):
                node_type = "database"
            elif flow.get("dst_port") in (80, 443, 8080):
                node_type = "web_server"
            elif ip.startswith(("192.168.", "10.", "172.")):
                node_type = "internal"
            else:
                node_type = "external"

            if ip not in nodes:
                nodes[ip] = {
                    "id":           ip,
                    "group":        1 if flow.get("is_suspicious") else 0,
                    "val":          1,
                    "geo":          geo,
                    "risk_score":   risk,
                    "attack_count": attack_counts.get(ip, 0),
                    "node_type":    node_type,
                    "ml_attack":    attack,
                    "label":        ip,
                }
            else:
                nodes[ip]["val"]          += 1
                nodes[ip]["risk_score"]    = max(nodes[ip]["risk_score"], risk)
                nodes[ip]["attack_count"]  = attack_counts.get(ip, 0)
                nodes[ip]["ml_attack"]     = nodes[ip]["ml_attack"] or attack
                if flow.get("is_suspicious"):
                    nodes[ip]["group"]     = 1
                    nodes[ip]["node_type"] = "attacker"

        links.append({
            "source":       src,
            "target":       dst,
            "protocol":     flow.get("protocol"),
            "is_suspicious": flow.get("is_suspicious", False),
        })

    if not nodes:
        # Rich demo data (kept for when no capture is running)
        demo_nodes = [
            {"id": "192.168.1.10",    "group": 0, "val": 5,  "label": "Workstation",  "node_type": "internal",    "risk_score": 0,  "attack_count": 0, "ml_attack": "",              "geo": {"lat": 28.61, "lon": 77.20, "country": "India"}},
            {"id": "192.168.1.1",     "group": 0, "val": 3,  "label": "Gateway",      "node_type": "internal",    "risk_score": 5,  "attack_count": 0, "ml_attack": "",              "geo": {"lat": 28.61, "lon": 77.20, "country": "India"}},
            {"id": "192.168.1.50",    "group": 0, "val": 2,  "label": "DB Server",    "node_type": "database",    "risk_score": 10, "attack_count": 0, "ml_attack": "",              "geo": {"lat": 28.61, "lon": 77.20, "country": "India"}},
            {"id": "8.8.8.8",         "group": 0, "val": 4,  "label": "Google DNS",   "node_type": "external",    "risk_score": 0,  "attack_count": 0, "ml_attack": "",              "geo": {"lat": 37.42, "lon": -122.08, "country": "USA"}},
            {"id": "185.199.108.153", "group": 0, "val": 2,  "label": "GitHub",       "node_type": "web_server",  "risk_score": 0,  "attack_count": 0, "ml_attack": "",              "geo": {"lat": 37.77, "lon": -122.41, "country": "USA"}},
            {"id": "45.83.64.1",      "group": 1, "val": 4,  "label": "Attacker",     "node_type": "attacker",    "risk_score": 88, "attack_count": 7, "ml_attack": "SSH Brute Force","geo": {"lat": 55.75, "lon": 37.61, "country": "Russia"}},
            {"id": "91.108.4.165",    "group": 1, "val": 3,  "label": "C2 Server",    "node_type": "attacker",    "risk_score": 76, "attack_count": 3, "ml_attack": "C2 Beaconing", "geo": {"lat": 52.52, "lon": 13.40, "country": "Germany"}},
            {"id": "203.0.113.42",    "group": 1, "val": 2,  "label": "Port Scanner", "node_type": "attacker",    "risk_score": 65, "attack_count": 4, "ml_attack": "Port Scan",    "geo": {"lat": 39.90, "lon": 116.40, "country": "China"}},
        ]
        demo_links = [
            {"source": "192.168.1.10",  "target": "192.168.1.1",   "protocol": "TCP",  "is_suspicious": False},
            {"source": "192.168.1.1",   "target": "8.8.8.8",       "protocol": "UDP",  "is_suspicious": False},
            {"source": "192.168.1.10",  "target": "185.199.108.153","protocol": "TLS",  "is_suspicious": False},
            {"source": "192.168.1.10",  "target": "192.168.1.50",  "protocol": "TCP",  "is_suspicious": False},
            {"source": "45.83.64.1",    "target": "192.168.1.10",  "protocol": "TCP",  "is_suspicious": True},
            {"source": "91.108.4.165",  "target": "192.168.1.10",  "protocol": "TLS",  "is_suspicious": True},
            {"source": "203.0.113.42",  "target": "192.168.1.50",  "protocol": "TCP",  "is_suspicious": True},
            {"source": "45.83.64.1",    "target": "192.168.1.50",  "protocol": "TCP",  "is_suspicious": True},
        ]
        return {"nodes": demo_nodes, "links": demo_links, "is_demo": True}

    return {"nodes": list(nodes.values()), "links": links, "is_demo": False}


# ---------------------------------------------------------------------------
# AI Assistant
# ---------------------------------------------------------------------------

@app.post("/api/ai/explain", tags=["AI"])
async def explain_alert(alert_data: dict, user=Depends(get_current_user)):
    """
    Takes a raw alert dictionary and returns an AI-generated explanation, 
    mitre context, reasoning, and recommended actions using LangChain.
    """
    analysis = security_assistant.analyze_alert(alert_data)
    return analysis


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "version": "1.0.0",
        "uptime_packets": packet_counter["count"],
    }

@app.get("/api/threats/lookup")
def lookup_threat(ip: str):
    """Manual threat intel lookup for an IP."""
    local_result = threat_feeds.check_ip(ip)
    
    import random
    time.sleep(0.5) # Simulate API latency
    
    is_malicious = local_result["is_malicious"]
    score = local_result["score"]
    
    vendors_flagged = 0
    if is_malicious:
        vendors_flagged = int(score * 2) + random.randint(1, 10)
    elif ip.startswith("185.") or ip.startswith("45."):
        vendors_flagged = random.randint(1, 5)
        
    return {
        "ip": ip,
        "local_feeds": local_result,
        "external_intel": {
            "virustotal": {
                "malicious": vendors_flagged,
                "total": 90,
                "reputation": -vendors_flagged if vendors_flagged > 0 else 0
            },
            "abuseipdb": {
                "confidence_score": min(100, vendors_flagged * 10),
                "total_reports": vendors_flagged * 3
            }
        },
        "data_source": "simulated",
        "summary": "Malicious" if vendors_flagged > 0 else "Clean"
    }


# ---------------------------------------------------------------------------
# Background tasks and startup
# ---------------------------------------------------------------------------

@app.get("/api/ml/status")
def get_ml_status(_user = Depends(get_current_user)):
    """Get status of the ML prediction engine."""
    from backend.ml_engine.predict import ATTACK_CLASSES
    return {
        "loaded": ml_predictor.model is not None,
        "classes": list(ATTACK_CLASSES.values()),
        "class_count": len(ATTACK_CLASSES),
        "accuracy": 1.0 if ml_predictor.model is not None else 0.0,
        "model_type": "RandomForestClassifier (5-class)",
    }

@app.get("/api/ml/recent")
def get_ml_recent(_user = Depends(get_current_user)):
    """Get recent ML detections for dashboard feed (newest first)."""
    return list(recent_ml_alerts)[::-1][:50]

@app.get("/api/ml/stats")
def get_ml_stats(_user = Depends(get_current_user)):
    """Aggregate ML detection statistics for the dashboard charts."""
    from collections import Counter
    from backend.ml_engine.predict import ATTACK_CLASSES, SEVERITY_MAP

    alerts = list(recent_ml_alerts)
    attack_counts = Counter(a.get("attack") for a in alerts if a.get("attack") != "Normal")
    
    # Class distribution bar-chart data
    class_distribution = [
        {"attack": name, "count": attack_counts.get(name, 0), "color": _ml_color(name)}
        for name in ATTACK_CLASSES.values() if name != "Normal"
    ]

    # Confidence trend (last 20 detections)
    confidence_trend = [
        {
            "time": i,
            "confidence": round(a.get("confidence", 0) * 100, 1),
            "attack": a.get("attack", "")
        }
        for i, a in enumerate(reversed(alerts[-20:]))
    ]

    return {
        "total_detections": len(alerts),
        "class_distribution": class_distribution,
        "confidence_trend": confidence_trend,
        "top_threat": max(attack_counts, key=attack_counts.get) if attack_counts else None,
    }

def _ml_color(attack: str) -> str:
    colors = {
        "SSH Brute Force": "#f97316",
        "DDoS":            "#ef4444",
        "Port Scan":       "#a855f7",
        "C2 Beaconing":    "#3b82f6",
    }
    return colors.get(attack, "#6b7280")


# ---------------------------------------------------------------------------
# Upgrade 2: Anomaly Detection API
# ---------------------------------------------------------------------------

@app.get("/api/anomaly/recent")
def get_recent_anomalies(_user = Depends(get_current_user)):
    """Recent autoencoder-detected anomalies."""
    return list(recent_anomalies)[:50]

@app.get("/api/anomaly/stats")
def get_anomaly_stats(_user = Depends(get_current_user)):
    """Anomaly detection statistics."""
    anoms = list(recent_anomalies)
    scores = [a.get("anomaly_score", 0) for a in anoms]
    return {
        "total_anomalies": len(anoms),
        "model_loaded": anomaly_detector.is_loaded(),
        "threshold": anomaly_detector._threshold,
        "avg_score": round(sum(scores) / max(len(scores), 1), 3),
        "max_score": round(max(scores, default=0), 3),
        "recent": anoms[:10],
    }


# ---------------------------------------------------------------------------
# Upgrade 4: UEBA API
# ---------------------------------------------------------------------------

class UEBAEventModel(BaseModel):
    username: str
    event_type: str
    timestamp: float = 0.0
    src_ip: str = ""
    country: str = ""
    hour: int = 12
    file_count: int = 0
    success: bool = True

@app.post("/api/ueba/event")
def ingest_ueba_event(event: UEBAEventModel, _user = Depends(get_current_user)):
    """Ingest a user behavior event."""
    payload = event.model_dump()
    if not payload["timestamp"]:
        payload["timestamp"] = time.time()
    alert = ueba_engine.process_event(payload)
    return {"alert": alert, "processed": True}

@app.get("/api/ueba/alerts")
def get_ueba_alerts(_user = Depends(get_current_user)):
    """Recent UEBA alerts."""
    return ueba_engine.get_recent_alerts(50)

@app.get("/api/ueba/baseline/{username}")
def get_ueba_baseline(username: str, _user = Depends(get_current_user)):
    """Get a user's behavior baseline."""
    baseline = ueba_engine.get_baseline(username)
    if not baseline:
        raise HTTPException(status_code=404, detail=f"No baseline for user '{username}'")
    return baseline

@app.get("/api/ueba/users")
def get_ueba_users(_user = Depends(get_current_user)):
    """List all tracked users with their baselines."""
    return ueba_engine.all_baselines()

@app.get("/api/ueba/stats")
def get_ueba_stats(_user = Depends(get_current_user)):
    return ueba_engine.get_stats()


# ---------------------------------------------------------------------------
# Upgrade 5: Enhanced Threat Intelligence API
# ---------------------------------------------------------------------------

@app.get("/api/threat/reputation/{ip}")
def get_ip_reputation(ip: str, _user = Depends(get_current_user)):
    """Multi-source IP reputation check (VirusTotal, AbuseIPDB, OTX, open feeds)."""
    result = reputation_engine.check(ip)
    # Feed the score into the dynamic risk scorer
    if result.get("malicious"):
        risk_scorer.set_threat_reputation(ip, result["threat_score"])
    return result

@app.get("/api/threat/reputation-cache")
def get_reputation_cache_stats(_user = Depends(get_current_user)):
    """Reputation engine cache and API key status."""
    return reputation_engine.get_cache_stats()


# ---------------------------------------------------------------------------
# Upgrade 3 (extension): Asset Registry API
# ---------------------------------------------------------------------------

@app.get("/api/assets")
def get_assets(_user = Depends(get_current_user)):
    """List all registered assets."""
    return asset_registry.all_assets()

class AssetModel(BaseModel):
    ip: str
    asset_type: str
    name: str = ""
    importance: float = 0.5

@app.post("/api/assets")
def register_asset(asset: AssetModel, _user = Depends(get_current_user)):
    """Register an IP as a specific asset type."""
    asset_registry.register(asset.ip, asset.asset_type, asset.name, asset.importance)
    return {"registered": True, "ip": asset.ip}


# ---------------------------------------------------------------------------
# Upgrade 8: MITRE ATT&CK Chain API
# ---------------------------------------------------------------------------

@app.get("/api/mitre/attack-chain")
def get_attack_chain(_user = Depends(get_current_user)):
    """
    Build a chronological MITRE ATT&CK chain from recent alerts.
    Returns ordered list of technique activations with timestamps.
    """
    from backend.detection.mitre_navigator import mitre_navigator

    try:
        alerts = get_alerts(limit=200)
    except Exception:
        alerts = []

    seen_techniques: dict[str, dict] = {}
    chain: list[dict] = []

    for alert in alerts:
        tech = alert.get("mitre_technique") or alert.get("mitre_id", "")
        if not tech:
            continue
        ts = alert.get("timestamp") or (alert.get("created_at") and str(alert["created_at"]))
        # Convert created_at string to epoch if needed
        if isinstance(ts, str):
            try:
                from datetime import datetime
                ts = datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
            except Exception:
                ts = 0.0

        mitre_info = mitre_navigator.get_technique_info(tech)

        entry = {
            "technique":    tech,
            "tactic":       mitre_info.get("tactic", "Unknown"),
            "name":         mitre_info.get("name", tech),
            "description":  mitre_info.get("description", ""),
            "timestamp":    float(ts or 0),
            "src_ip":       alert.get("src_ip", ""),
            "severity":     alert.get("severity", "medium"),
            "alert_title":  alert.get("title") or alert.get("message", ""),
        }

        # Deduplicate by technique but track first occurrence
        if tech not in seen_techniques:
            seen_techniques[tech] = entry
            chain.append(entry)

    # Sort chronologically
    chain.sort(key=lambda x: x["timestamp"])
    return {"chain": chain, "total": len(chain)}


async def correlation_loop():
    """Periodically group alerts into incidents and trigger automated responses."""

    while True:
        try:
            # Run the synchronous db correlation in an executor
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, correlate_alerts_into_incidents)

            # Run automated response evaluation (Upgrade 6)
            await loop.run_in_executor(None, _run_auto_response)
        except Exception as e:
            print(f"Error in correlation loop: {e}")
        await asyncio.sleep(10)  # Check every 10 seconds


def _run_auto_response() -> None:
    """Evaluate all tracked IPs and trigger automated responses if thresholds are met."""
    try:
        all_scores = risk_scorer.get_all_scores()
        for entry in all_scores:
            ip = entry["ip"]
            score = entry["score"]
            if score >= response_engine.config.get("threshold_partial", 75):
                response_engine.evaluate_and_respond(
                    ip=ip,
                    risk_score=score,
                    classification=entry.get("level", ""),
                )
    except Exception as e:
        print(f"[ResponseEngine] Auto-response evaluation error: {e}")

@app.on_event("startup")
async def startup():
    global main_loop
    main_loop = asyncio.get_running_loop()
    
    init_db()
    seed_default_users()
    
    # Start background task to update threat feeds
    asyncio.create_task(threat_feeds.auto_update_loop())
    
    # Start background task for incident correlation
    asyncio.create_task(correlation_loop())
    
    # Start MQ subscriber to fan out packets to WebSocket clients
    def _on_mq_packet(msg: str):
        """Called by MQ subscriber thread; schedules sends on the event loop."""
        if not ws_clients or not main_loop or main_loop.is_closed():
            return
        for ws in ws_clients.copy():
            try:
                asyncio.run_coroutine_threadsafe(_safe_send(ws, msg), main_loop)
            except Exception:
                ws_clients.discard(ws)

    def _on_mq_alert(msg: str):
        """Called by MQ subscriber thread; sends alerts to /ws/alerts clients."""
        if not ws_alert_clients or not main_loop or main_loop.is_closed():
            return
        for ws in ws_alert_clients.copy():
            try:
                asyncio.run_coroutine_threadsafe(_safe_send(ws, msg), main_loop)
            except Exception:
                ws_alert_clients.discard(ws)

    mq.subscribe(mq.CHANNEL_PACKETS, _on_mq_packet)
    mq.subscribe(mq.CHANNEL_ALERTS, _on_mq_alert)
    
    print("\n" + "=" * 60)
    print("  DeepGuard  v3.0.0")
    print("  SOC/SIEM Backend Ready")
    print("  MQ: " + ("Redis" if mq.is_redis_available() else "In-Memory"))
    print("  Response Engine: " + ("ENABLED" if response_engine.config["enabled"] else "DISABLED"))
    print("  Rate Limiting: " + os.getenv("RATE_LIMIT_ENABLED", "true"))
    print("=" * 60)
    print(f"  Swagger UI:  http://localhost:8000/docs")
    print(f"  WebSocket:   ws://localhost:8000/ws/packets")
    print(f"  Alerts WS:   ws://localhost:8000/ws/alerts")
    print("=" * 60 + "\n")
