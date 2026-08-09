"""
Redis Pub/Sub & Streams Message Queue
=====================================
Decouples packet production from WebSocket fan-out and Detection Workers.
"""

from __future__ import annotations

import json
import os
import threading
from typing import Any, Callable

_redis_available = False
_redis_client = None

try:
    import redis
    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    _redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    _redis_client.ping()
    _redis_available = True
    print(f"[MQ] Redis connected at {REDIS_URL}")
except Exception as e:
    print(f"[MQ] Redis unavailable ({e}), using in-memory fallback")
    _redis_available = False


# ── Channels & Streams ──
CHANNEL_PACKETS = "siem:packets"      # PubSub for live UI feed
CHANNEL_ALERTS = "siem:alerts"        # PubSub for live UI feed
STREAM_PACKETS = "siem:packet_stream" # Redis Stream for workers

# ── In-memory fallback subscribers ──
_memory_subscribers: dict[str, list[Callable]] = {
    CHANNEL_PACKETS: [],
    CHANNEL_ALERTS: [],
}

# ---------------------------------------------------------------------------
# Pub/Sub
# ---------------------------------------------------------------------------

def publish(channel: str, data: dict[str, Any]) -> None:
    """Publish a message to a channel."""
    try:
        msg = json.dumps(data, default=str)
    except Exception:
        return

    if _redis_available and _redis_client:
        try:
            _redis_client.publish(channel, msg)
            return
        except Exception:
            pass

    # In-memory fallback
    for callback in _memory_subscribers.get(channel, []):
        try:
            callback(msg)
        except Exception:
            pass


def publish_packet(record: dict[str, Any]) -> None:
    publish(CHANNEL_PACKETS, record)


def publish_alert(alert: dict[str, Any]) -> None:
    publish(CHANNEL_ALERTS, alert)


def subscribe(channel: str, callback: Callable[[str], None]) -> None:
    if _redis_available and _redis_client:
        def _listener():
            try:
                pubsub = _redis_client.pubsub()
                pubsub.subscribe(channel)
                for message in pubsub.listen():
                    if message["type"] == "message":
                        try:
                            callback(message["data"])
                        except Exception:
                            pass
            except Exception as e:
                print(f"[MQ] Redis subscriber error: {e}")

        t = threading.Thread(target=_listener, daemon=True)
        t.start()
    else:
        _memory_subscribers.setdefault(channel, []).append(callback)


# ---------------------------------------------------------------------------
# Streams (For Detection Workers)
# ---------------------------------------------------------------------------

def stream_add(stream: str, data: dict[str, Any]) -> None:
    """Add a message to a Redis stream."""
    if _redis_available and _redis_client:
        try:
            msg = json.dumps(data, default=str)
            _redis_client.xadd(stream, {"payload": msg}, maxlen=10000)
        except Exception as e:
            print(f"[MQ] Stream publish error: {e}")

def stream_consume(stream: str, group: str, consumer: str, callback: Callable[[dict], None]) -> None:
    """Consume from a Redis stream using a consumer group."""
    if not _redis_available or not _redis_client:
        print("[MQ] Redis not available. Stream consumer cannot start.")
        return
        
    try:
        _redis_client.xgroup_create(stream, group, id="0", mkstream=True)
    except redis.exceptions.ResponseError as e:
        if "BUSYGROUP" not in str(e):
            print(f"[MQ] Group create error: {e}")

    def _worker_loop():
        print(f"[MQ] Worker {consumer} listening on stream {stream}...")
        while True:
            try:
                # Read 10 messages at a time, block for 5 seconds
                messages = _redis_client.xreadgroup(group, consumer, {stream: ">"}, count=10, block=5000)
                if not messages:
                    continue
                    
                for stream_name, msg_list in messages:
                    for message_id, msg_data in msg_list:
                        payload = msg_data.get("payload")
                        if payload:
                            try:
                                data = json.loads(payload)
                                callback(data)
                            except Exception as e:
                                print(f"[MQ] Worker processing error: {e}")
                        # Acknowledge the message
                        _redis_client.xack(stream, group, message_id)
            except Exception as e:
                import time
                time.sleep(2)
                
    t = threading.Thread(target=_worker_loop, daemon=True)
    t.start()

def is_redis_available() -> bool:
    return _redis_available
