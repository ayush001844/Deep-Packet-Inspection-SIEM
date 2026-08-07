"""
Open Source Threat Intelligence Feeds
=====================================
Downloads and caches open-source IP blocklists and threat feeds.
"""

from __future__ import annotations

import asyncio
import os
import time
from typing import Optional, Any
import requests

FEEDS = {
    "cins_army": {
        "url": "http://cinsscore.com/list/ci-badguys.txt",
        "description": "CINS Army List - Poor reputation IPs",
        "type": "ip",
    },
    "emerging_threats": {
        "url": "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
        "description": "Emerging Threats - Known compromised hosts",
        "type": "ip",
    },
    "blocklist_de": {
        "url": "https://lists.blocklist.de/lists/all.txt",
        "description": "Blocklist.de - Attacks reported by Fail2Ban",
        "type": "ip",
    }
}

class ThreatFeeds:
    """Manager for open source threat feeds."""
    
    def __init__(self):
        self.malicious_ips: dict[str, set[str]] = {
            "cins_army": set(),
            "emerging_threats": set(),
            "blocklist_de": set(),
        }
        self.last_update = 0.0
        self.update_interval = 3600 * 12  # 12 hours
        self.is_updating = False

    def get_stats(self) -> dict[str, Any]:
        """Return counts of IPs in the feeds."""
        return {
            name: len(ips) for name, ips in self.malicious_ips.items()
        }

    def check_ip(self, ip: str) -> dict[str, Any]:
        """
        Check if an IP is in any of the threat feeds.
        Returns a dict with 'is_malicious', 'feeds_hit', 'score'.
        """
        if not ip:
            return {"is_malicious": False, "feeds_hit": [], "score": 0}

        hits = []
        for feed_name, ip_set in self.malicious_ips.items():
            if ip in ip_set:
                hits.append(feed_name)

        if not hits:
            return {"is_malicious": False, "feeds_hit": [], "score": 0}

        # Simple scoring mechanism based on how many lists it appears on
        # Score 0-10
        base_score = 6.0
        extra = len(hits) * 2.0
        final_score = min(10.0, base_score + extra)

        return {
            "is_malicious": True,
            "feeds_hit": hits,
            "score": round(final_score, 1),
            "severity": "high" if final_score >= 8.0 else "medium",
        }

    def update_feeds_sync(self):
        """Synchronously download and parse all feeds. Good for initial startup."""
        print("[ThreatIntel] Updating open source threat feeds...")
        start = time.time()
        total_ips = 0

        for name, info in FEEDS.items():
            try:
                resp = requests.get(info["url"], timeout=10)
                if resp.status_code == 200:
                    ips = set()
                    for line in resp.text.splitlines():
                        line = line.strip()
                        # Ignore comments and empty lines
                        if line and not line.startswith("#"):
                            ips.add(line)
                    self.malicious_ips[name] = ips
                    total_ips += len(ips)
                    print(f"[ThreatIntel] Loaded {len(ips)} IPs from {name}")
                else:
                    print(f"[ThreatIntel] Failed to fetch {name} (HTTP {resp.status_code})")
            except Exception as e:
                print(f"[ThreatIntel] Error fetching {name}: {e}")

        self.last_update = time.time()
        elapsed = time.time() - start
        print(f"[ThreatIntel] Update complete in {elapsed:.2f}s. Total unique IPs tracked: {total_ips}")

    async def update_feeds_async(self):
        """Asynchronous update loop for background tasks."""
        if self.is_updating:
            return
        
        self.is_updating = True
        try:
            # Run the synchronous HTTP requests in an executor
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self.update_feeds_sync)
        finally:
            self.is_updating = False

    async def auto_update_loop(self):
        """Background loop to periodically update feeds."""
        while True:
            now = time.time()
            if now - self.last_update > self.update_interval:
                await self.update_feeds_async()
            await asyncio.sleep(60)

# Global singleton
threat_feeds = ThreatFeeds()
