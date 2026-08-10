"""
Asset Registry
==============
Maps IP addresses to asset types and importance weights for dynamic risk scoring.

Asset importance scale (0.0–1.0):
  1.0  = Database / Production server  → any attack is critical
  0.8  = Web server / API gateway
  0.6  = Internal workstation
  0.4  = Guest / BYOD device
  0.2  = Honeypot / sandbox
"""
from __future__ import annotations

import os
import json
import logging

logger = logging.getLogger(__name__)

# Default well-known port → asset type heuristics
PORT_ASSET_HINTS = {
    3306: ("database", 1.0),
    5432: ("database", 1.0),
    1433: ("database", 1.0),
    27017: ("database", 1.0),
    6379: ("database", 0.9),  # Redis
    80:   ("web_server", 0.8),
    443:  ("web_server", 0.8),
    8080: ("web_server", 0.7),
    22:   ("server", 0.7),
    21:   ("server", 0.7),
    25:   ("mail_server", 0.8),
    53:   ("dns_server", 0.75),
}

# Default IP → asset mapping (can be overridden via ASSET_REGISTRY_FILE)
_DEFAULT_REGISTRY: dict[str, dict] = {
    "127.0.0.1":   {"type": "localhost",   "importance": 0.5, "name": "Loopback"},
    "10.0.0.1":    {"type": "gateway",     "importance": 0.9, "name": "Default Gateway"},
    "192.168.1.1": {"type": "gateway",     "importance": 0.9, "name": "Home Router"},
}

ASSET_TYPE_IMPORTANCE = {
    "database":    1.0,
    "web_server":  0.8,
    "mail_server": 0.8,
    "dns_server":  0.75,
    "server":      0.7,
    "gateway":     0.9,
    "workstation": 0.5,
    "laptop":      0.4,
    "mobile":      0.3,
    "guest":       0.2,
    "honeypot":    0.1,
    "unknown":     0.5,
}


class AssetRegistry:
    def __init__(self):
        self._registry: dict[str, dict] = dict(_DEFAULT_REGISTRY)
        self._load_from_file()

    def _load_from_file(self):
        path = os.environ.get("ASSET_REGISTRY_FILE", "")
        if path and os.path.exists(path):
            try:
                with open(path) as f:
                    self._registry.update(json.load(f))
                logger.info(f"[AssetRegistry] Loaded {len(self._registry)} assets from {path}")
            except Exception as e:
                logger.warning(f"[AssetRegistry] Could not load file: {e}")

    def get(self, ip: str, dst_port: int = 0) -> dict:
        """
        Return asset info for an IP. If not registered, infer from dest port.
        """
        if ip in self._registry:
            entry = dict(self._registry[ip])
            entry.setdefault("importance", ASSET_TYPE_IMPORTANCE.get(entry.get("type", "unknown"), 0.5))
            return entry

        # Port-based heuristic
        if dst_port and dst_port in PORT_ASSET_HINTS:
            asset_type, importance = PORT_ASSET_HINTS[dst_port]
            return {"type": asset_type, "importance": importance, "name": ip}

        return {"type": "unknown", "importance": 0.5, "name": ip}

    def get_importance(self, ip: str, dst_port: int = 0) -> float:
        return self.get(ip, dst_port)["importance"]

    def register(self, ip: str, asset_type: str, name: str = "", importance: float | None = None):
        self._registry[ip] = {
            "type": asset_type,
            "importance": importance if importance is not None else ASSET_TYPE_IMPORTANCE.get(asset_type, 0.5),
            "name": name or ip,
        }

    def all_assets(self) -> list[dict]:
        return [
            {"ip": ip, **info}
            for ip, info in self._registry.items()
        ]


asset_registry = AssetRegistry()
