"""
Multi-Source IP Reputation Engine
====================================
Checks IPs against:
  1. VirusTotal API        (VIRUSTOTAL_API_KEY)
  2. AbuseIPDB API         (ABUSEIPDB_API_KEY)
  3. AlienVault OTX API    (OTX_API_KEY)
  4. Existing open feeds   (always active, no key required)

API keys are read from environment variables. If a key is missing, that
source is silently skipped — the system works fine with just open feeds.

Results are cached for 24 hours per IP.
"""
from __future__ import annotations

import os
import time
import logging
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)

CACHE_TTL = 86400  # 24 hours


class ReputationEngine:
    def __init__(self):
        self._cache: dict[str, dict] = {}      # ip → {result, expires}
        self._vt_key   = os.environ.get("VIRUSTOTAL_API_KEY", "")
        self._abuse_key = os.environ.get("ABUSEIPDB_API_KEY", "")
        self._otx_key  = os.environ.get("OTX_API_KEY", "")

    def _cached(self, ip: str) -> Optional[dict]:
        entry = self._cache.get(ip)
        if entry and time.time() < entry["expires"]:
            return entry["result"]
        return None

    def _store(self, ip: str, result: dict):
        self._cache[ip] = {"result": result, "expires": time.time() + CACHE_TTL}

    def check(self, ip: str) -> dict[str, Any]:
        """
        Full multi-source reputation check.
        Returns:
        {
          "ip": "1.2.3.4",
          "malicious": true,
          "confidence": 0.87,          # 0–1
          "threat_score": 0.87,        # 0–1 (for risk scoring)
          "reports": 43,
          "sources": ["virustotal", "abuseipdb"],
          "details": { ... }
        }
        """
        if not ip or ip.startswith(("10.", "192.168.", "172.", "127.")):
            return self._clean(ip)

        cached = self._cached(ip)
        if cached:
            return cached

        results = {}

        # 1. VirusTotal
        if self._vt_key:
            results["virustotal"] = self._check_virustotal(ip)

        # 2. AbuseIPDB
        if self._abuse_key:
            results["abuseipdb"] = self._check_abuseipdb(ip)

        # 3. AlienVault OTX
        if self._otx_key:
            results["otx"] = self._check_otx(ip)

        # 4. Always check open feeds
        from backend.threat.feeds import threat_feeds
        feed_result = threat_feeds.check_ip(ip)
        if feed_result.get("is_malicious"):
            results["open_feeds"] = {
                "malicious": True,
                "reports": len(feed_result.get("feeds_hit", [])),
                "sources": feed_result.get("feeds_hit", []),
            }

        # Aggregate
        aggregated = self._aggregate(ip, results)
        self._store(ip, aggregated)
        return aggregated

    def _clean(self, ip: str) -> dict:
        return {
            "ip": ip, "malicious": False, "confidence": 0.0,
            "threat_score": 0.0, "reports": 0, "sources": [], "details": {},
        }

    def _aggregate(self, ip: str, results: dict) -> dict:
        if not results:
            return self._clean(ip)

        total_confidence = 0.0
        total_reports = 0
        malicious_sources = []

        for source, data in results.items():
            if data.get("malicious"):
                malicious_sources.append(source)
                # Confidence contribution per source
                conf = data.get("confidence", 0.5)
                total_confidence += conf
                total_reports += data.get("reports", 1)

        is_malicious = len(malicious_sources) > 0
        confidence = min(1.0, total_confidence / max(len(results), 1))

        return {
            "ip":           ip,
            "malicious":    is_malicious,
            "confidence":   round(confidence, 3),
            "threat_score": round(confidence, 3),
            "reports":      total_reports,
            "sources":      malicious_sources,
            "details":      results,
            "checked_at":   time.time(),
        }

    def _check_virustotal(self, ip: str) -> dict:
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {"x-apikey": self._vt_key}
            r = requests.get(url, headers=headers, timeout=5)
            if r.status_code != 200:
                return {"malicious": False, "error": f"HTTP {r.status_code}"}
            data = r.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            total = sum(stats.values()) or 1
            confidence = malicious_count / total
            return {
                "malicious":  malicious_count > 0,
                "confidence": round(confidence, 3),
                "reports":    malicious_count,
                "total_engines": total,
            }
        except Exception as e:
            logger.debug(f"[Reputation] VirusTotal error for {ip}: {e}")
            return {"malicious": False, "error": str(e)}

    def _check_abuseipdb(self, ip: str) -> dict:
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Key": self._abuse_key, "Accept": "application/json"}
            params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}
            r = requests.get(url, headers=headers, params=params, timeout=5)
            if r.status_code != 200:
                return {"malicious": False, "error": f"HTTP {r.status_code}"}
            data = r.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0) / 100.0
            reports = data.get("totalReports", 0)
            return {
                "malicious":  score > 0.2,
                "confidence": round(score, 3),
                "reports":    reports,
                "country":    data.get("countryCode", ""),
                "isp":        data.get("isp", ""),
                "usage_type": data.get("usageType", ""),
            }
        except Exception as e:
            logger.debug(f"[Reputation] AbuseIPDB error for {ip}: {e}")
            return {"malicious": False, "error": str(e)}

    def _check_otx(self, ip: str) -> dict:
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/reputation"
            headers = {"X-OTX-API-KEY": self._otx_key}
            r = requests.get(url, headers=headers, timeout=5)
            if r.status_code != 200:
                return {"malicious": False, "error": f"HTTP {r.status_code}"}
            data = r.json()
            rep_data = data.get("reputation", {})
            score = float(rep_data.get("threat_score", 0))
            # OTX score: 0–10 → normalise to 0–1
            norm = score / 10.0
            return {
                "malicious":  norm > 0.3,
                "confidence": round(norm, 3),
                "reports":    len(data.get("pulse_info", {}).get("pulses", [])),
                "threat_score": score,
            }
        except Exception as e:
            logger.debug(f"[Reputation] OTX error for {ip}: {e}")
            return {"malicious": False, "error": str(e)}

    def get_cache_stats(self) -> dict:
        return {
            "cached_ips": len(self._cache),
            "has_virustotal": bool(self._vt_key),
            "has_abuseipdb":  bool(self._abuse_key),
            "has_otx":        bool(self._otx_key),
        }


reputation_engine = ReputationEngine()
