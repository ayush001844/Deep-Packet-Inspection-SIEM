"""
Rate Limiter Middleware (Upgrade 8)
====================================
Sliding-window rate limiter for FastAPI endpoints.
Uses in-memory tracking (no Redis dependency required).
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Callable

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Rate limits: path_prefix -> (max_requests, window_seconds)
RATE_LIMITS = {
    "/api/auth/login": (5, 60),       # 5 login attempts per minute
    "/api/auth/refresh": (10, 60),     # 10 refresh attempts per minute
    "/api/pcap/upload": (10, 300),     # 10 uploads per 5 minutes
    "/api/capture/start": (5, 60),     # 5 capture starts per minute
    "/api/ai/": (20, 60),             # 20 AI queries per minute
    "/api/": (120, 60),               # General: 120 requests per minute
}

# Paths exempt from rate limiting
EXEMPT_PATHS = {
    "/api/health",
    "/docs",
    "/openapi.json",
    "/redoc",
}


class RateLimiterMiddleware(BaseHTTPMiddleware):
    """
    Sliding-window rate limiter.
    Tracks requests per client IP and returns 429 when limits are exceeded.
    """

    def __init__(self, app, enabled: bool = True):
        super().__init__(app)
        self.enabled = enabled
        # client_key -> deque of timestamps
        self._windows: dict[str, deque] = defaultdict(lambda: deque())

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if not self.enabled:
            return await call_next(request)

        path = request.url.path

        # Skip exempt paths
        if path in EXEMPT_PATHS:
            return await call_next(request)

        # Determine client IP
        client_ip = request.client.host if request.client else "unknown"

        # Find the most specific rate limit that matches
        max_requests, window_seconds = self._find_limit(path)

        # Build a key: ip + path_prefix
        limit_key = f"{client_ip}:{self._find_limit_key(path)}"

        # Sliding window check
        now = time.time()
        window = self._windows[limit_key]

        # Remove expired entries
        cutoff = now - window_seconds
        while window and window[0] < cutoff:
            window.popleft()

        if len(window) >= max_requests:
            retry_after = int(window[0] + window_seconds - now) + 1
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Too Many Requests",
                    "detail": f"Rate limit exceeded. Max {max_requests} requests per {window_seconds}s.",
                    "retry_after": retry_after,
                },
                headers={"Retry-After": str(retry_after)},
            )

        # Record this request
        window.append(now)

        # Add rate limit headers to response
        response = await call_next(request)
        remaining = max(0, max_requests - len(window))
        response.headers["X-RateLimit-Limit"] = str(max_requests)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(int(now + window_seconds))

        return response

    def _find_limit(self, path: str) -> tuple[int, int]:
        """Find the most specific rate limit for a path."""
        best_match = ""
        best_limit = (120, 60)  # Default fallback

        for prefix, limit in RATE_LIMITS.items():
            if path.startswith(prefix) and len(prefix) > len(best_match):
                best_match = prefix
                best_limit = limit

        return best_limit

    def _find_limit_key(self, path: str) -> str:
        """Find the rate limit key prefix for grouping."""
        best_match = "/api/"
        for prefix in RATE_LIMITS:
            if path.startswith(prefix) and len(prefix) > len(best_match):
                best_match = prefix
        return best_match


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds security headers to all responses."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        return response
