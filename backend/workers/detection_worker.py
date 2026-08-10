import os
import time
import sys
import uuid
import asyncio

# Ensure backend modules can be imported
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend import mq
from backend.dpi.session_tracker import SessionTracker
from backend.detection.ids import ids_engine
from backend.detection.classifier import classifier
from backend.ml_engine.predict import ml_predictor
from backend.db.elastic import index_packet, index_alert
from backend.db.database import save_alert, init_db
from backend.threat.geoip import get_location
from backend.detection.risk_scoring import risk_scorer
from backend.firewall import firewall

session_tracker = SessionTracker()
worker_id = f"worker-{uuid.uuid4().hex[:6]}"

def get_geo(ip: str) -> dict:
    try:
        geo = get_location(ip)
        if geo:
            return {"lat": geo.get("latitude"), "lon": geo.get("longitude"), "country": geo.get("country")}
    except Exception:
        pass
    return {}

def process_packet(record: dict) -> None:
    """
    Worker function to process a single packet from the Redis Stream.
    """
    try:
        # 1. Store raw packet to ElasticSearch
        index_packet(record)

        # 2. Reconstruct session
        flow = session_tracker.update(record)
        
        # 3. GeoIP Lookup for the map UI
        src_geo = get_geo(flow.src_ip)
        dst_geo = get_geo(flow.dst_ip)
        
        # Helper to enrich and dispatch alert
        def dispatch_alert(alert: dict):
            # Attach Geo Data for Upgrade 3
            if src_geo: alert["src_geo"] = src_geo
            if dst_geo: alert["dst_geo"] = dst_geo
            
            # Async DB saves in a synchronous wrapper (fire and forget)
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                
            loop.run_until_complete(save_alert(alert))
            index_alert(alert)
            mq.publish_alert(alert)

        # ── Detection Phase ──
        # IDS engine
        ids_alert = ids_engine.detect(record, flow)
        if ids_alert:
            dispatch_alert(ids_alert)
            risk_scorer.add_factor(flow.src_ip, "ids_alert")
            firewall.block_ip(flow.src_ip, reason=f"IDS Alert: {ids_alert['title']}")
            
        # ML Engine (per-session prediction)
        flow_data = flow.to_dict()
        ml_alert_data = ml_predictor.predict(flow_data)
        if ml_alert_data:
            if not getattr(flow, '_ml_alerted', False):
                flow._ml_alerted = True
                ml_alert = {
                    "title": f"ML Detection: {ml_alert_data['attack']}",
                    "description": f"AI model detected anomalous flow pattern indicative of {ml_alert_data['attack']}. Confidence: {ml_alert_data['confidence']*100:.1f}%\n" +
                                   f"Packets: {flow.total_packets}, Bytes: {flow.total_bytes}, Duration: {getattr(flow, 'duration', 0.0):.2f}s",
                    "severity": ml_alert_data["severity"].lower(),
                    "source": "ml_ensemble",
                    "src_ip": flow.src_ip,
                    "dst_ip": flow.dst_ip,
                    "timestamp": time.time(),
                    "mitre_technique": "T1562", 
                    "mitre_tactic": "Defense Evasion",
                    "classification": "Machine Learning"
                }
                dispatch_alert(ml_alert)
                risk_scorer.add_factor(flow.src_ip, "ml_high_confidence")
                if ml_result['confidence'] > 0.95:
                    firewall.block_ip(flow.src_ip, reason=f"ML Auto-Block ({ml_result['attack']})")
                    
        # Suspicious flow threshold alert
        if getattr(flow, 'is_suspicious', False) and not getattr(flow, '_alerted', False):
            flow._alerted = True
            heuristic_alert = {
                "title": "Suspicious Flow Detected",
                "description": f"Flow generated {flow.total_packets} packets and {flow.total_bytes} bytes in {getattr(flow, 'duration', 0.0):.2f}s.",
                "severity": "medium",
                "source": "heuristics",
                "src_ip": flow.src_ip,
                "dst_ip": flow.dst_ip,
                "timestamp": time.time(),
                "mitre_technique": "T1046",
                "mitre_tactic": "Discovery",
                "classification": "Anomaly"
            }
            dispatch_alert(heuristic_alert)
            risk_scorer.add_factor(flow.src_ip, "suspicious_flow")

    except Exception as e:
        print(f"[Worker] Error processing packet: {e}")


def main():
    print(f"🚀 Starting Detection Worker ({worker_id})")
    print(f"Connecting to Redis Stream: {mq.STREAM_PACKETS}")
    
    # Init database if needed
    asyncio.run(init_db())

    # Wait for Redis
    while not mq.is_redis_available():
        print("Waiting for Redis...")
        time.sleep(2)

    mq.stream_consume(mq.STREAM_PACKETS, "detection_group", worker_id, process_packet)
    
    # Keep main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"Worker {worker_id} stopping...")

if __name__ == "__main__":
    main()
