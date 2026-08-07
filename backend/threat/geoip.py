"""
GeoIP Module using ip-api.com (Free, No Key)
============================================
Provides fast geographic location lookups for IPs with local caching.
"""

from __future__ import annotations

import time
import requests
from typing import Any, Optional

# In-memory cache for IP lookups
# ip -> (timestamp, data)
_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
CACHE_TTL = 3600 * 24  # 24 hours

def get_location(ip: str) -> Optional[dict[str, Any]]:
    """
    Lookup geographic information for an IP address.
    Uses an in-memory cache to avoid hitting rate limits on ip-api.com.
    Note: ip-api.com allows 45 requests per minute for free.
    """
    if not ip or ip.startswith(("10.", "192.168.", "127.", "172.")):
        # Ignore private and loopback IPs
        # (Technically 172 is 172.16.0.0/12, but this is a quick check)
        return None

    now = time.time()
    
    # Check cache
    if ip in _CACHE:
        ts, data = _CACHE[ip]
        if now - ts < CACHE_TTL:
            return data
            
    try:
        # Request data from ip-api.com
        # fields=status,message,country,countryCode,regionName,city,lat,lon,isp,org,as
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,org,as"
        resp = requests.get(url, timeout=5)
        
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                # Clean up the output structure
                result = {
                    "country": data.get("country", ""),
                    "country_code": data.get("countryCode", ""),
                    "region": data.get("regionName", ""),
                    "city": data.get("city", ""),
                    "latitude": data.get("lat", 0.0),
                    "longitude": data.get("lon", 0.0),
                    "isp": data.get("isp", ""),
                    "asn": data.get("as", ""),
                }
                
                # Cache and return
                _CACHE[ip] = (now, result)
                
                # Keep cache bounded (approx 10,000 entries max)
                if len(_CACHE) > 10000:
                    oldest = min(_CACHE.items(), key=lambda x: x[1][0])
                    del _CACHE[oldest[0]]
                    
                return result
                
    except Exception as e:
        print(f"[GeoIP] Lookup failed for {ip}: {e}")
        
    return None
