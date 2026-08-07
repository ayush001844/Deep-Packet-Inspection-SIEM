"""
Firewall Backend – Abstract Base Class
=======================================
Defines the interface that all platform-specific firewall implementations must follow.
"""

from __future__ import annotations
from abc import ABC, abstractmethod


class FirewallBackend(ABC):
    """Abstract base class for firewall backends."""

    def __init__(self):
        # Store as dict: ip -> {"domain": str, "reason": str}
        self.blocked_entries: dict[str, dict] = {}

    @abstractmethod
    def _apply_rules(self) -> None:
        """Platform-specific: push the current blocklist to the OS firewall."""
        ...

    def block_ip(self, ip: str, reason: str = "", domain: str = "") -> bool:
        """Add an IP to the blocklist."""
        if not ip:
            return False
        if ip in self.blocked_entries:
            if domain and not self.blocked_entries[ip].get("domain"):
                self.blocked_entries[ip]["domain"] = domain
            return False

        self.blocked_entries[ip] = {"domain": domain, "reason": reason}
        print(f"[Firewall] BLOCKING IP {ip} domain={domain!r} (Reason: {reason})")
        self._apply_rules()
        return True

    def unblock_ip(self, ip: str) -> bool:
        """Remove an IP from the blocklist."""
        if ip in self.blocked_entries:
            del self.blocked_entries[ip]
            print(f"[Firewall] UNBLOCKING IP {ip}")
            self._apply_rules()
            return True
        return False

    def get_blocked_ips(self) -> list[str]:
        """Return list of blocked IPs."""
        return list(self.blocked_entries.keys())

    def get_blocked_entries(self) -> list[dict]:
        """Return full list of blocked entries with domain labels."""
        result = []
        for ip, meta in self.blocked_entries.items():
            result.append({
                "ip": ip,
                "domain": meta.get("domain", ""),
                "reason": meta.get("reason", ""),
            })
        return result


class DryRunBackend(FirewallBackend):
    """No-op backend for environments without root/admin privileges."""

    def __init__(self):
        super().__init__()
        print("[Firewall] Using DryRunBackend — rules logged but NOT enforced.")

    def _apply_rules(self) -> None:
        ips = list(self.blocked_entries.keys())
        if ips:
            print(f"[Firewall] DRY RUN: Would apply {len(ips)} block rules: {', '.join(ips[:5])}{'...' if len(ips) > 5 else ''}")
        else:
            print("[Firewall] DRY RUN: Blocklist cleared.")
