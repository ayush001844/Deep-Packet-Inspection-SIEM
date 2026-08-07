"""
Firewall Backend – Linux (iptables / nftables)
===============================================
Manages block rules via iptables on Linux systems.
Requires root privileges for enforcement.
"""

from __future__ import annotations

import os
import subprocess

from backend.firewall.firewall_base import FirewallBackend


class IptablesBackend(FirewallBackend):
    """Linux firewall backend using iptables."""

    CHAIN_NAME = "PACKET_ANALYZER_BLOCK"

    def __init__(self):
        super().__init__()
        self.is_root = os.geteuid() == 0
        print(f"[Firewall] Using IptablesBackend (Linux). Root: {self.is_root}")

        if self.is_root:
            self._ensure_chain()

    def _ensure_chain(self) -> None:
        """Create our custom iptables chain if it doesn't exist."""
        try:
            # Check if chain exists
            result = subprocess.run(
                ["iptables", "-L", self.CHAIN_NAME],
                capture_output=True, text=True
            )
            if result.returncode != 0:
                # Create chain
                subprocess.run(["iptables", "-N", self.CHAIN_NAME], capture_output=True)
                # Insert jump rule at top of INPUT and OUTPUT
                subprocess.run(
                    ["iptables", "-I", "INPUT", "1", "-j", self.CHAIN_NAME],
                    capture_output=True
                )
                subprocess.run(
                    ["iptables", "-I", "OUTPUT", "1", "-j", self.CHAIN_NAME],
                    capture_output=True
                )
                print(f"[Firewall] Created iptables chain '{self.CHAIN_NAME}'")
        except Exception as e:
            print(f"[Firewall] Error creating iptables chain: {e}")

    def _apply_rules(self) -> None:
        """Flush and repopulate the iptables chain."""
        if not self.is_root:
            ips = list(self.blocked_entries.keys())
            print(f"[Firewall] DRY RUN (no root): Would block {len(ips)} IPs via iptables.")
            return

        try:
            # Flush existing rules in our chain
            subprocess.run(
                ["iptables", "-F", self.CHAIN_NAME],
                capture_output=True, text=True
            )

            # Add rules for each blocked IP
            for ip in self.blocked_entries:
                subprocess.run(
                    ["iptables", "-A", self.CHAIN_NAME, "-s", ip, "-j", "DROP"],
                    capture_output=True
                )
                subprocess.run(
                    ["iptables", "-A", self.CHAIN_NAME, "-d", ip, "-j", "DROP"],
                    capture_output=True
                )

            print(f"[Firewall] Applied {len(self.blocked_entries)} iptables block rules.")

        except Exception as e:
            print(f"[Firewall] Error applying iptables rules: {e}")
