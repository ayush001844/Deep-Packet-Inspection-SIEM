"""
Firewall – Platform Auto-Detection Factory
============================================
Detects the current OS and returns the appropriate FirewallBackend.
"""

from __future__ import annotations

import sys

from backend.firewall.firewall_base import FirewallBackend, DryRunBackend


def create_firewall() -> FirewallBackend:
    """Auto-detect the OS and return the correct firewall backend."""
    platform = sys.platform

    if platform == "darwin":
        from backend.firewall.pf_manager import PFBackend
        return PFBackend()

    elif platform.startswith("linux"):
        from backend.firewall.iptables_manager import IptablesBackend
        return IptablesBackend()

    elif platform == "win32":
        from backend.firewall.win_firewall import WindowsFirewallBackend
        return WindowsFirewallBackend()

    else:
        print(f"[Firewall] Unsupported platform '{platform}' — using DryRunBackend.")
        return DryRunBackend()


# Global singleton — auto-detected on import
firewall = create_firewall()
