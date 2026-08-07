"""
Firewall Backend – Windows (netsh advfirewall)
===============================================
Manages block rules via Windows Firewall (netsh) on Windows systems.
Requires Administrator privileges for enforcement.
"""

from __future__ import annotations

import ctypes
import subprocess
import sys

from backend.firewall.firewall_base import FirewallBackend


def _is_admin() -> bool:
    """Check if running with Administrator privileges on Windows."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


class WindowsFirewallBackend(FirewallBackend):
    """Windows firewall backend using netsh advfirewall."""

    RULE_PREFIX = "PacketAnalyzer_Block_"

    def __init__(self):
        super().__init__()
        self.is_admin = _is_admin()
        print(f"[Firewall] Using WindowsFirewallBackend. Administrator: {self.is_admin}")

    def _apply_rules(self) -> None:
        """Remove old rules and create new ones via netsh."""
        if not self.is_admin:
            ips = list(self.blocked_entries.keys())
            print(f"[Firewall] DRY RUN (not admin): Would block {len(ips)} IPs via Windows Firewall.")
            return

        try:
            # Delete existing PacketAnalyzer rules
            result = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule",
                 f"name=all"],
                capture_output=True, text=True
            )
            # Find and delete our rules
            for line in result.stdout.splitlines():
                if self.RULE_PREFIX in line and "Rule Name:" in line:
                    rule_name = line.split("Rule Name:")[-1].strip()
                    subprocess.run(
                        ["netsh", "advfirewall", "firewall", "delete", "rule",
                         f"name={rule_name}"],
                        capture_output=True
                    )

            # Add new block rules
            for ip in self.blocked_entries:
                safe_name = ip.replace(".", "_")
                rule_name = f"{self.RULE_PREFIX}{safe_name}"

                # Inbound block
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}_IN",
                    "dir=in", "action=block",
                    f"remoteip={ip}",
                    "enable=yes"
                ], capture_output=True)

                # Outbound block
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}_OUT",
                    "dir=out", "action=block",
                    f"remoteip={ip}",
                    "enable=yes"
                ], capture_output=True)

            print(f"[Firewall] Applied {len(self.blocked_entries)} Windows Firewall block rules.")

        except Exception as e:
            print(f"[Firewall] Error applying Windows Firewall rules: {e}")
