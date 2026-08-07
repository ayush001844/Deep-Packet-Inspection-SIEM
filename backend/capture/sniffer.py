"""
Live Packet Sniffer
===================
Wraps Scapy's sniff() in a background thread with start / stop / pause
semantics.  Captured packets are pushed through a callback so the FastAPI
WebSocket layer can forward them to clients in real time.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable, Optional

from scapy.all import sniff, get_if_list, conf, Ether


class PacketSniffer:
    """
    Non-blocking packet sniffer that runs in a daemon thread.

    Usage
    -----
    >>> sniffer = PacketSniffer()
    >>> sniffer.start("en0", callback=my_handler, bpf_filter="tcp port 80")
    >>> sniffer.stop()
    """

    def __init__(self) -> None:
        self._thread: Optional[threading.Thread] = None
        self._running = threading.Event()
        self._paused = threading.Event()
        self._stop_event = threading.Event()
        self._callback: Optional[Callable] = None
        self._interface: str = ""
        self._bpf_filter: str = ""
        self._packet_count: int = 0
        self._max_packets: int = 0  # 0 = unlimited
        self._start_time: float = 0.0
        self._lock = threading.Lock()
        self._last_error: str = ""  # Stores last sniffer error for the UI

    # ── Public API ──────────────────────────────────────────────────────

    @staticmethod
    def list_interfaces() -> list[dict[str, str]]:
        """Return available network interfaces."""
        interfaces = []
        for iface in get_if_list():
            interfaces.append({
                "name": iface,
                "description": iface,  # Scapy doesn't always provide descriptions on macOS
            })
        return interfaces

    def start(
        self,
        interface: str = "en0",
        callback: Optional[Callable] = None,
        bpf_filter: str = "",
        max_packets: int = 0,
    ) -> dict[str, Any]:
        """
        Start capturing packets on the given interface.

        Parameters
        ----------
        interface   : Network interface name (e.g. "en0", "lo0")
        callback    : Called for each packet with the raw Scapy packet object
        bpf_filter  : BPF filter string (e.g. "tcp port 80")
        max_packets : Stop after this many packets (0 = unlimited)

        Returns
        -------
        dict with status info.
        """
        if self._running.is_set():
            return {"status": "error", "message": "Capture already running"}

        # Pre-flight: check if we can open a BPF device (requires root on macOS)
        import os
        if os.path.exists("/dev/bpf0") and not os.access("/dev/bpf0", os.R_OK):
            msg = (
                "Permission denied: cannot open /dev/bpf0. "
                "Restart the backend with sudo: "
                "sudo venv/bin/uvicorn backend.main:app --host 0.0.0.0 --port 8000"
            )
            self._last_error = msg
            print(f"[Sniffer] {msg}")
            return {"status": "error", "message": msg}

        self._last_error = ""
        self._interface = interface
        self._callback = callback
        self._bpf_filter = bpf_filter
        self._max_packets = max_packets
        self._packet_count = 0
        self._stop_event.clear()
        self._paused.clear()
        self._start_time = time.time()

        self._thread = threading.Thread(
            target=self._capture_loop,
            daemon=True,
            name="PacketSniffer",
        )
        self._running.set()
        self._thread.start()

        return {
            "status": "started",
            "interface": interface,
            "filter": bpf_filter,
            "max_packets": max_packets,
        }

    def stop(self) -> dict[str, Any]:
        """Stop the capture and return a summary."""
        if not self._running.is_set():
            return {"status": "error", "message": "No capture running"}

        self._stop_event.set()
        self._running.clear()

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)

        elapsed = time.time() - self._start_time if self._start_time else 0
        summary = {
            "status": "stopped",
            "interface": self._interface,
            "packets_captured": self._packet_count,
            "duration_seconds": round(elapsed, 2),
            "packets_per_second": round(self._packet_count / elapsed, 1) if elapsed > 0 else 0,
        }
        self._thread = None
        return summary

    def pause(self) -> dict[str, str]:
        """Pause capture (packets are silently discarded)."""
        if not self._running.is_set():
            return {"status": "error", "message": "No capture running"}
        self._paused.set()
        return {"status": "paused"}

    def resume(self) -> dict[str, str]:
        """Resume a paused capture."""
        if not self._running.is_set():
            return {"status": "error", "message": "No capture running"}
        self._paused.clear()
        return {"status": "resumed"}

    @property
    def is_running(self) -> bool:
        return self._running.is_set()

    @property
    def is_paused(self) -> bool:
        return self._paused.is_set()

    @property
    def packet_count(self) -> int:
        return self._packet_count

    def get_status(self) -> dict[str, Any]:
        elapsed = time.time() - self._start_time if self._start_time and self._running.is_set() else 0
        return {
            "running": self._running.is_set(),
            "paused": self._paused.is_set(),
            "interface": self._interface,
            "filter": self._bpf_filter,
            "packets_captured": self._packet_count,
            "duration_seconds": round(elapsed, 2),
            "packets_per_second": round(self._packet_count / elapsed, 1) if elapsed > 0 else 0,
            "error": self._last_error,
        }

    # ── Internal ────────────────────────────────────────────────────────

    def _capture_loop(self) -> None:
        """Run in the background thread."""
        try:
            sniff(
                iface=self._interface,
                filter=self._bpf_filter if self._bpf_filter else None,
                prn=self._process_packet,
                stop_filter=lambda _: self._stop_event.is_set(),
                store=False,  # Don't accumulate packets in memory
                count=self._max_packets if self._max_packets > 0 else 0,
            )
        except PermissionError as e:
            msg = f"Permission denied on '{self._interface}'. Restart backend with sudo."
            self._last_error = msg
            print(f"[Sniffer] {msg}")
        except Exception as e:
            self._last_error = str(e)
            print(f"[Sniffer] Error: {e}")
        finally:
            self._running.clear()

    def _process_packet(self, pkt) -> None:
        """Scapy prn callback – invoked for each captured packet."""
        if self._paused.is_set():
            return

        with self._lock:
            self._packet_count += 1

        if self._callback:
            try:
                self._callback(pkt)
            except Exception as e:
                print(f"[Sniffer] Callback error: {e}")
