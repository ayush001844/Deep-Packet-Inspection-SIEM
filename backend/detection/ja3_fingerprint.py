"""
JA3/JA3S Fingerprinting
========================
Computes JA3 fingerprints from TLS Client Hello fields and checks
them against a database of known-malicious fingerprints.

JA3 = md5(TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)
"""

from __future__ import annotations

import hashlib
from typing import Any, Optional

from backend.detection.ids import Rule
from backend.detection.ja3_known_bad import lookup_ja3


def compute_ja3_from_raw(payload: bytes) -> Optional[str]:
    """
    Compute JA3 hash from raw TLS Client Hello bytes.
    Returns the JA3 hash string, or None if not a valid Client Hello.
    """
    if len(payload) < 6:
        return None
    # Content type 0x16 = Handshake
    if payload[0] != 0x16:
        return None
    # Handshake type 0x01 = Client Hello
    if payload[5] != 0x01:
        return None

    try:
        offset = 5 + 4  # skip handshake header
        
        # TLS version
        tls_version = int.from_bytes(payload[offset:offset + 2], "big")
        offset += 2

        # Skip random (32 bytes)
        offset += 32

        # Session ID
        sid_len = payload[offset]
        offset += 1 + sid_len

        # Cipher suites
        cs_len = int.from_bytes(payload[offset:offset + 2], "big")
        offset += 2
        ciphers = []
        for i in range(0, cs_len, 2):
            cs = int.from_bytes(payload[offset + i:offset + i + 2], "big")
            # Exclude GREASE values
            if (cs & 0x0f0f) != 0x0a0a:
                ciphers.append(str(cs))
        offset += cs_len

        # Compression methods
        comp_len = payload[offset]
        offset += 1 + comp_len

        # Extensions
        extensions = []
        elliptic_curves = []
        ec_point_formats = []

        if offset + 2 <= len(payload):
            ext_len = int.from_bytes(payload[offset:offset + 2], "big")
            offset += 2
            ext_end = offset + ext_len

            while offset + 4 <= ext_end and offset + 4 <= len(payload):
                ext_type = int.from_bytes(payload[offset:offset + 2], "big")
                ext_data_len = int.from_bytes(payload[offset + 2:offset + 4], "big")
                offset += 4

                # Exclude GREASE extension types
                if (ext_type & 0x0f0f) != 0x0a0a:
                    extensions.append(str(ext_type))

                # Supported Groups (elliptic curves) - ext type 0x000a
                if ext_type == 0x000a and ext_data_len >= 2:
                    groups_len = int.from_bytes(payload[offset:offset + 2], "big")
                    for i in range(0, groups_len, 2):
                        if offset + 2 + i + 2 <= len(payload):
                            group = int.from_bytes(payload[offset + 2 + i:offset + 2 + i + 2], "big")
                            if (group & 0x0f0f) != 0x0a0a:
                                elliptic_curves.append(str(group))

                # EC Point Formats - ext type 0x000b
                if ext_type == 0x000b and ext_data_len >= 1:
                    formats_len = payload[offset]
                    for i in range(formats_len):
                        if offset + 1 + i < len(payload):
                            ec_point_formats.append(str(payload[offset + 1 + i]))

                offset += ext_data_len

        # Build JA3 string
        ja3_string = ",".join([
            str(tls_version),
            "-".join(ciphers),
            "-".join(extensions),
            "-".join(elliptic_curves),
            "-".join(ec_point_formats),
        ])

        # Hash it
        ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()
        return ja3_hash

    except (IndexError, ValueError):
        return None


class JA3FingerprintRule(Rule):
    """
    Computes JA3 fingerprints from TLS Client Hello packets and
    checks them against a database of known-malicious fingerprints.
    """

    def __init__(self):
        super().__init__(
            rule_id="AI-002",
            name="Malicious JA3 TLS Fingerprint",
            description="TLS Client Hello fingerprint matches a known malware family.",
            mitre_technique="T1573",  # Encrypted Channel
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"  # 9.1 Critical
        )
        # Track already-seen fingerprints to avoid duplicate alerts per flow
        self._seen: set[str] = set()

    def evaluate_packet(self, packet: dict[str, Any]) -> Optional[dict[str, Any]]:
        """Check TLS Client Hello packets for known-bad JA3 fingerprints."""
        # Look for TLS layer in packet
        for layer in packet.get("layers", []):
            if layer.get("layer") != "TLS" or layer.get("handshake") != "ClientHello":
                continue

            # If the protocol parser already extracted cipher info, try to compute JA3
            # But we need raw payload — check if ja3_hash was pre-computed
            ja3_hash = layer.get("ja3_hash")
            if not ja3_hash:
                continue

            # Deduplicate
            flow_key = f"{packet.get('src_ip')}:{packet.get('dst_ip')}:{ja3_hash}"
            if flow_key in self._seen:
                return None
            self._seen.add(flow_key)

            # Prune seen set if too large
            if len(self._seen) > 10000:
                self._seen.clear()

            # Lookup
            match = lookup_ja3(ja3_hash)
            if match and match["confidence"] >= 0.5:
                return self.generate_alert(
                    src_ip=packet.get("src_ip", ""),
                    dst_ip=packet.get("dst_ip", ""),
                    evidence=(
                        f"JA3 hash {ja3_hash} matched: {match['label']} "
                        f"({match['family']}, confidence={match['confidence']:.0%})"
                    )
                )

        return None
