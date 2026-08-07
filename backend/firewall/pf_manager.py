"""
PF Firewall Integration (macOS)
===============================
Provides an interface to dynamically block malicious IPs using macOS's native `pfctl`.
Note: Executing pfctl requires root privileges (sudo).
If the backend is not running as root, blocks are stored in memory and logged (dry-run mode).
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from typing import Optional


class PFManager:
    def __init__(self):
        self.anchor_name = "com.packetanalyzer.blocklist"
        # Store as dict: ip -> {"domain": str, "reason": str}
        self.blocked_entries: dict[str, dict] = {}
        self.is_root = os.geteuid() == 0

        print(f"[Firewall] Initialized PF Manager. Root privileges: {self.is_root}")
        if self.is_root:
            self._ensure_anchor_configured()

    def _ensure_anchor_configured(self):
        """Ensure pf is enabled and our anchor is loaded."""
        try:
            subprocess.run(["pfctl", "-e"], capture_output=True)
            print("[Firewall] pfctl enabled.")
        except Exception as e:
            print(f"[Firewall] Failed to enable pfctl: {e}")

    def block_ip(self, ip: str, reason: str = "", domain: str = "") -> bool:
        """Add an IP to the blocklist with optional domain label."""
        if not ip:
            return False
        if ip in self.blocked_entries:
            # Update domain if provided and not set yet
            if domain and not self.blocked_entries[ip].get("domain"):
                self.blocked_entries[ip]["domain"] = domain
            return False

        self.blocked_entries[ip] = {"domain": domain, "reason": reason}
        print(f"[Firewall] BLOCKING IP {ip} domain={domain!r} (Reason: {reason})")

        if self.is_root:
            self._apply_rules()
        else:
            print(f"[Firewall] DRY RUN: Would block {ip} via pfctl (Run as root to enforce).")

        return True

    def unblock_ip(self, ip: str) -> bool:
        """Remove an IP from the blocklist."""
        if ip in self.blocked_entries:
            del self.blocked_entries[ip]
            print(f"[Firewall] UNBLOCKING IP {ip}")
            if self.is_root:
                self._apply_rules()
            return True
        return False

    def get_blocked_ips(self) -> list[str]:
        """Return list of blocked IPs (legacy compat)."""
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

    def _apply_rules(self):
        """Generate and apply the pf ruleset for blocked IPs."""
        ips = list(self.blocked_entries.keys())
        if not ips:
            rules = ""
        else:
            lines = []
            for ip in ips:
                lines.append(f"block drop in quick from {ip} to any")
                lines.append(f"block drop out quick from any to {ip}")
            rules = "\n".join(lines) + "\n"

        try:
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.conf', delete=False) as f:
                f.write(rules)
                temp_path = f.name

            cmd = ["pfctl", "-a", self.anchor_name, "-f", temp_path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            os.unlink(temp_path)

            if result.returncode != 0:
                print(f"[Firewall] pfctl error: {result.stderr}")
            else:
                print(f"[Firewall] Applied {len(ips)} block rules to anchor '{self.anchor_name}'")

        except Exception as e:
            print(f"[Firewall] Exception applying rules: {e}")


# Global singleton
firewall = PFManager()
