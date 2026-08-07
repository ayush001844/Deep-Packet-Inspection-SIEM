"""
PF Firewall Integration (macOS)
===============================
macOS-specific backend using pfctl. Inherits from FirewallBackend.
"""

from __future__ import annotations

import os
import subprocess
import tempfile

from backend.firewall.firewall_base import FirewallBackend


class PFBackend(FirewallBackend):
    """macOS firewall backend using pfctl."""

    def __init__(self):
        super().__init__()
        self.anchor_name = "com.packetanalyzer.blocklist"
        self.is_root = os.geteuid() == 0

        print(f"[Firewall] Using PFBackend (macOS). Root: {self.is_root}")
        if self.is_root:
            self._ensure_anchor_configured()

    def _ensure_anchor_configured(self):
        """Ensure pf is enabled and our anchor is loaded."""
        try:
            subprocess.run(["pfctl", "-e"], capture_output=True)
            print("[Firewall] pfctl enabled.")
        except Exception as e:
            print(f"[Firewall] Failed to enable pfctl: {e}")

    def _apply_rules(self):
        """Generate and apply the pf ruleset for blocked IPs."""
        if not self.is_root:
            ips = list(self.blocked_entries.keys())
            print(f"[Firewall] DRY RUN (no root): Would block {len(ips)} IPs via pfctl.")
            return

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
