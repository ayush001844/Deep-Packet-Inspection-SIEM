"""
Redis Pub/Sub Message Queue
============================
Decouples packet production from WebSocket fan-out.
Falls back gracefully to in-memory if Redis is unavailable.
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


# ── Channels ──
CHANNEL_PACKETS = "siem:packets"
CHANNEL_ALERTS = "siem:alerts"

# ── In-memory fallback subscribers ──
_memory_subscribers: dict[str, list[Callable]] = {
    CHANNEL_PACKETS: [],
    CHANNEL_ALERTS: [],
}


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
    """Publish a parsed packet record."""
    publish(CHANNEL_PACKETS, record)


def publish_alert(alert: dict[str, Any]) -> None:
    """Publish a classified alert."""
    publish(CHANNEL_ALERTS, alert)


def subscribe(channel: str, callback: Callable[[str], None]) -> None:
    """
    Subscribe to a channel. The callback receives raw JSON strings.
    For Redis mode, this runs a blocking listener in a background thread.
    For in-memory mode, the callback is called inline during publish().
    """
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


def is_redis_available() -> bool:
    return _redis_available
