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
from backend.firewall import firewall
from backend.reporting.pdf_gen import generate_incident_report
from backend.auth import router as auth_router, get_current_user, require_admin, seed_default_users
from backend.db.database import (
    init_db, get_alerts, save_alert, get_incidents,
)
from backend.detection.classifier import classifier
from backend.db.elastic import index_packet, index_alert
from backend.ml.predictor import predictor as ml_predictor
from backend.ai.assistant import security_assistant
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
        {"name": "Network", "description": "Network topology graph with geo-located nodes"},
        {"name": "Risk", "description": "Zero-Trust risk scores for tracked IPs"},
        {"name": "Incidents", "description": "Correlated security incidents and attack timelines"},
        {"name": "ML", "description": "Machine learning model status and recent predictions"},
        {"name": "AI", "description": "LLM-powered security assistant"},
        {"name": "Auth", "description": "User authentication (JWT-based)"},
        {"name": "System", "description": "Health checks, diagnostics, and system info"},
    ],
)

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

@app.post("/api/pcap/upload")
async def upload_pcap(file: UploadFile = File(...)):
    """Upload and analyse a PCAP file."""
    if not file.filename:
        return JSONResponse(status_code=400, content={"error": "No file provided"})

    # Save uploaded file
    filepath = os.path.join(UPLOAD_DIR, file.filename)
    with open(filepath, "wb") as f:
        content = await file.read()
        f.write(content)

    # Analyse
    results = analyse_pcap(filepath)
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

@app.get("/api/network/graph")
def api_network_graph():
    """Generates a node/link graph of current active sessions for visualization."""
    nodes = {}
    links = []
    
    # Build graph from active sessions
    for flow in session_tracker.get_flows():
        src = flow.get("src_ip")
        dst = flow.get("dst_ip")
        if not src or not dst:
            continue
            
        if src not in nodes:
            nodes[src] = {
                "id": src, 
                "group": 1 if flow.get("is_suspicious") else 0, 
                "val": 1,
                "geo": flow.get("src_geo", {})
            }
        else:
            nodes[src]["val"] += 1
            if flow.get("is_suspicious"): nodes[src]["group"] = 1
            
        if dst not in nodes:
            nodes[dst] = {
                "id": dst, 
                "group": 1 if flow.get("is_suspicious") else 0, 
                "val": 1,
                "geo": flow.get("dst_geo", {})
            }
        else:
            nodes[dst]["val"] += 1
            if flow.get("is_suspicious"): nodes[dst]["group"] = 1
            
        # Create link
        links.append({
            "source": src,
            "target": dst,
            "protocol": flow.get("protocol"),
            "is_suspicious": flow.get("is_suspicious", False)
        })

    # If no live sessions, return realistic demo data so map is always visible
    if not nodes:
        demo_nodes = [
            {"id": "192.168.1.10", "group": 0, "val": 5, "label": "Local Host", "geo": {"lat": 28.6139, "lon": 77.2090, "country": "India"}},
            {"id": "192.168.1.1",  "group": 0, "val": 3, "label": "Gateway",    "geo": {"lat": 28.6139, "lon": 77.2090, "country": "India"}},
            {"id": "8.8.8.8",      "group": 0, "val": 4, "label": "Google DNS",  "geo": {"lat": 37.4220, "lon": -122.0841, "country": "United States"}},
            {"id": "142.250.195.46","group": 0, "val": 2, "label": "Google",     "geo": {"lat": 37.4220, "lon": -122.0841, "country": "United States"}},
            {"id": "172.217.24.142","group": 1, "val": 2, "label": "YouTube",    "geo": {"lat": 37.4220, "lon": -122.0841, "country": "United States"}},
            {"id": "1.1.1.1",      "group": 0, "val": 2, "label": "Cloudflare", "geo": {"lat": 33.4484, "lon": -112.0740, "country": "United States"}},
            {"id": "104.21.45.87", "group": 0, "val": 1, "label": "CDN Node",   "geo": {"lat": 51.5074, "lon": -0.1278,   "country": "United Kingdom"}},
            {"id": "185.199.108.153","group": 0, "val": 1, "label": "GitHub",   "geo": {"lat": 37.7749, "lon": -122.4194, "country": "United States"}},
            {"id": "91.108.4.165", "group": 1, "val": 1, "label": "Telegram",   "geo": {"lat": 52.5200, "lon": 13.4050,  "country": "Germany"}},
        ]
        demo_links = [
            {"source": "192.168.1.10", "target": "192.168.1.1",  "protocol": "TCP",  "is_suspicious": False},
            {"source": "192.168.1.1",  "target": "8.8.8.8",      "protocol": "UDP",  "is_suspicious": False},
            {"source": "192.168.1.10", "target": "8.8.8.8",      "protocol": "UDP",  "is_suspicious": False},
            {"source": "192.168.1.10", "target": "142.250.195.46","protocol": "TCP", "is_suspicious": False},
            {"source": "192.168.1.10", "target": "172.217.24.142","protocol": "TLS", "is_suspicious": True},
            {"source": "192.168.1.10", "target": "1.1.1.1",      "protocol": "ICMP", "is_suspicious": False},
            {"source": "192.168.1.10", "target": "104.21.45.87", "protocol": "TCP",  "is_suspicious": False},
            {"source": "192.168.1.10", "target": "185.199.108.153","protocol": "TLS","is_suspicious": False},
            {"source": "192.168.1.10", "target": "91.108.4.165", "protocol": "TCP",  "is_suspicious": True},
        ]
        return {"nodes": demo_nodes, "links": demo_links, "is_demo": True}

    return {
        "nodes": list(nodes.values()),
        "links": links,
        "is_demo": False
    }


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
    return {
        "loaded": ml_predictor.is_loaded,
        "classes": ml_predictor.classes,
        "accuracy": getattr(ml_predictor, 'accuracy', 0.0)
    }

@app.get("/api/ml/recent")
def get_ml_recent(_user = Depends(get_current_user)):
    """Get recent ML predictions for dashboard feed."""
    return list(recent_ml_alerts)[::-1][:20]

async def correlation_loop():
    """Periodically group alerts into incidents."""
    while True:
        try:
            # Run the synchronous db correlation in an executor
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, correlate_alerts_into_incidents)
        except Exception as e:
            print(f"Error in correlation loop: {e}")
        await asyncio.sleep(10)  # Check every 10 seconds

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
    print("  PacketAnalyzer-Pro  v2.0.0")
    print("  SOC/SIEM Backend Ready")
    print("  MQ: " + ("Redis" if mq.is_redis_available() else "In-Memory"))
    print("=" * 60)
    print(f"  Swagger UI:  http://localhost:8000/docs")
    print(f"  WebSocket:   ws://localhost:8000/ws/packets")
    print(f"  Alerts WS:   ws://localhost:8000/ws/alerts")
    print("=" * 60 + "\n")
