"""
Elasticsearch Integration for SIEM Logging
==========================================
Handles indexing of packets and alerts into Elasticsearch.
"""
from datetime import datetime
import os
import threading
from typing import Any
from elasticsearch import Elasticsearch

# Default to elasticsearch service in docker, or localhost if running natively
ES_HOST = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")

# Set timeout and max retries for resilience
es = Elasticsearch([ES_HOST], request_timeout=10, max_retries=3, retry_on_timeout=True)

def _index_async(index_name: str, document: dict[str, Any]):
    try:
        es.index(index=index_name, document=document)
    except Exception as e:
        # Silently fail or log to file in production to avoid console spam
        pass

def index_packet(packet: dict[str, Any]) -> None:
    """Index a single packet into Elasticsearch (fire and forget)."""
    try:
        pkt_doc = packet.copy()
        if "timestamp" not in pkt_doc:
            pkt_doc["timestamp"] = datetime.utcnow().isoformat()
        else:
            if isinstance(pkt_doc["timestamp"], (float, int)):
                pkt_doc["timestamp"] = datetime.utcfromtimestamp(pkt_doc["timestamp"]).isoformat()
        
        index_name = f"packets-{datetime.utcnow().strftime('%Y.%m.%d')}"
        # Use a background thread for fire-and-forget to avoid blocking the packet pipeline
        threading.Thread(target=_index_async, args=(index_name, pkt_doc), daemon=True).start()
    except Exception as e:
        pass

def index_alert(alert: dict[str, Any]) -> None:
    """Index a security alert into Elasticsearch."""
    try:
        alert_doc = alert.copy()
        if "timestamp" in alert_doc and isinstance(alert_doc["timestamp"], (float, int)):
            alert_doc["timestamp"] = datetime.utcfromtimestamp(alert_doc["timestamp"]).isoformat()
        elif "created_at" in alert_doc:
            if hasattr(alert_doc["created_at"], "isoformat"):
                alert_doc["timestamp"] = alert_doc["created_at"].isoformat()
            else:
                alert_doc["timestamp"] = alert_doc["created_at"]
        else:
            alert_doc["timestamp"] = datetime.utcnow().isoformat()
            
        index_name = f"alerts-{datetime.utcnow().strftime('%Y.%m.%d')}"
        threading.Thread(target=_index_async, args=(index_name, alert_doc), daemon=True).start()
    except Exception as e:
        pass
