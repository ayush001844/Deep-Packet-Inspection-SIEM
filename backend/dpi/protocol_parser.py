"""
Deep Packet Inspection – Full L2-L7 Protocol Parser
====================================================
Uses Scapy's built-in dissectors to extract every protocol field that
the frontend dashboard needs.  Each packet is turned into a rich dict
that the WebSocket and REST layers serialise to JSON.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any, Optional

from scapy.all import (
    Ether, ARP, Dot1Q,
    IP, IPv6, ICMP, ICMPv6Unknown,
    TCP, UDP,
    DNS, DNSQR, DNSRR,
    Raw,
    conf,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_str(val: Any) -> str:
    """Return a safe string representation (never None)."""
    if val is None:
        return ""
    return str(val)


def _mac(pkt_field: Any) -> str:
    return _safe_str(pkt_field).lower()


def _flags_to_list(flags_int: int) -> list[str]:
    """Convert a TCP flags integer to human-readable flag names."""
    mapping = [
        (0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"),
        (0x08, "PSH"), (0x10, "ACK"), (0x20, "URG"),
        (0x40, "ECE"), (0x80, "CWR"),
    ]
    return [name for bit, name in mapping if flags_int & bit]


# ---------------------------------------------------------------------------
# TLS helpers  (Scapy doesn't always dissect TLS without scapy-tls)
# ---------------------------------------------------------------------------

def _parse_tls_client_hello(payload: bytes) -> Optional[dict]:
    """
    Manually parse a TLS Client Hello from raw TCP payload bytes.
    Returns dict with sni, tls_version, cipher_suites, etc. or None.
    """
    if len(payload) < 6:
        return None
    # Content type 0x16 = Handshake
    if payload[0] != 0x16:
        return None
    # Handshake type 0x01 = Client Hello
    if payload[5] != 0x01:
        return None

    result: dict[str, Any] = {}

    # TLS record version
    rec_major, rec_minor = payload[1], payload[2]
    result["tls_record_version"] = f"{rec_major}.{rec_minor}"

    try:
        offset = 5 + 4  # skip handshake header (type + 3-byte length)
        # Client version
        cli_major, cli_minor = payload[offset], payload[offset + 1]
        version_map = {
            (3, 1): "TLS 1.0", (3, 2): "TLS 1.1",
            (3, 3): "TLS 1.2", (3, 4): "TLS 1.3",
            (3, 0): "SSL 3.0",
        }
        result["tls_version"] = version_map.get(
            (cli_major, cli_minor), f"{cli_major}.{cli_minor}"
        )
        offset += 2

        # Skip random (32 bytes)
        offset += 32

        # Session ID
        sid_len = payload[offset]
        offset += 1 + sid_len

        # Cipher suites
        cs_len = int.from_bytes(payload[offset:offset + 2], "big")
        offset += 2
        num_ciphers = cs_len // 2
        result["cipher_suite_count"] = num_ciphers
        offset += cs_len

        # Compression methods
        comp_len = payload[offset]
        offset += 1 + comp_len

        # Extensions
        if offset + 2 > len(payload):
            return result
        ext_len = int.from_bytes(payload[offset:offset + 2], "big")
        offset += 2
        ext_end = offset + ext_len

        while offset + 4 <= ext_end and offset + 4 <= len(payload):
            ext_type = int.from_bytes(payload[offset:offset + 2], "big")
            ext_data_len = int.from_bytes(payload[offset + 2:offset + 4], "big")
            offset += 4
            if offset + ext_data_len > len(payload):
                break

            # SNI extension (type 0x0000)
            if ext_type == 0x0000 and ext_data_len >= 5:
                sni_type = payload[offset + 2]
                sni_len = int.from_bytes(payload[offset + 3:offset + 5], "big")
                if sni_type == 0x00 and offset + 5 + sni_len <= len(payload):
                    result["sni"] = payload[offset + 5:offset + 5 + sni_len].decode(
                        "ascii", errors="replace"
                    )

            # ALPN extension (type 0x0010)
            if ext_type == 0x0010 and ext_data_len >= 2:
                alpn_list_len = int.from_bytes(
                    payload[offset:offset + 2], "big"
                )
                alpn_off = offset + 2
                alpn_end = offset + 2 + alpn_list_len
                protocols = []
                while alpn_off < alpn_end and alpn_off < len(payload):
                    plen = payload[alpn_off]
                    alpn_off += 1
                    if alpn_off + plen <= len(payload):
                        protocols.append(
                            payload[alpn_off:alpn_off + plen].decode(
                                "ascii", errors="replace"
                            )
                        )
                    alpn_off += plen
                result["alpn"] = protocols

            offset += ext_data_len

    except (IndexError, ValueError):
        pass

    return result if result else None


def _parse_http_request(payload: bytes) -> Optional[dict]:
    """Parse an HTTP request from raw bytes."""
    try:
        text = payload.decode("ascii", errors="replace")
    except Exception:
        return None

    methods = ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ")
    if not any(text.startswith(m) for m in methods):
        return None

    lines = text.split("\r\n")
    if not lines:
        return None

    result: dict[str, Any] = {}

    # Request line
    parts = lines[0].split(" ", 2)
    if len(parts) >= 2:
        result["method"] = parts[0]
        result["url"] = parts[1]
    if len(parts) >= 3:
        result["http_version"] = parts[2]

    # Headers
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            break
        if ": " in line:
            k, v = line.split(": ", 1)
            headers[k.lower()] = v

    result["host"] = headers.get("host", "")
    result["user_agent"] = headers.get("user-agent", "")
    result["content_type"] = headers.get("content-type", "")
    result["cookies"] = headers.get("cookie", "")
    result["referer"] = headers.get("referer", "")

    return result


def _parse_http_response(payload: bytes) -> Optional[dict]:
    """Parse an HTTP response from raw bytes."""
    try:
        text = payload.decode("ascii", errors="replace")
    except Exception:
        return None

    if not text.startswith("HTTP/"):
        return None

    lines = text.split("\r\n")
    if not lines:
        return None

    result: dict[str, Any] = {}
    parts = lines[0].split(" ", 2)
    if len(parts) >= 2:
        result["http_version"] = parts[0]
        result["status_code"] = int(parts[1]) if parts[1].isdigit() else 0
    if len(parts) >= 3:
        result["status_text"] = parts[2]

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            break
        if ": " in line:
            k, v = line.split(": ", 1)
            headers[k.lower()] = v

    result["server"] = headers.get("server", "")
    result["content_type"] = headers.get("content-type", "")

    return result


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------

def parse_packet(pkt, packet_id: int = 0) -> dict[str, Any]:
    """
    Dissect a Scapy packet into a rich dictionary covering L2-L7.

    Parameters
    ----------
    pkt : scapy.packet.Packet
        A Scapy packet object (from sniff() or rdpcap()).
    packet_id : int
        A monotonic counter assigned by the caller.

    Returns
    -------
    dict  – JSON-serialisable packet record.
    """
    record: dict[str, Any] = {
        "id": packet_id,
        "timestamp": float(pkt.time),
        "length": len(pkt),
        "layers": [],
        "summary": pkt.summary(),
    }

    # ── Layer 2 ──────────────────────────────────────────────────────────
    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        l2: dict[str, Any] = {
            "layer": "Ethernet",
            "src_mac": _mac(eth.src),
            "dst_mac": _mac(eth.dst),
            "ether_type": hex(eth.type),
        }
        # VLAN tagging
        if pkt.haslayer(Dot1Q):
            dot1q = pkt[Dot1Q]
            l2["vlan_id"] = dot1q.vlan
        record["layers"].append(l2)
        record["src_mac"] = l2["src_mac"]
        record["dst_mac"] = l2["dst_mac"]

    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        arp_info: dict[str, Any] = {
            "layer": "ARP",
            "operation": "request" if arp.op == 1 else "reply",
            "sender_mac": _mac(arp.hwsrc),
            "sender_ip": _safe_str(arp.psrc),
            "target_mac": _mac(arp.hwdst),
            "target_ip": _safe_str(arp.pdst),
        }
        record["layers"].append(arp_info)
        record["protocol"] = "ARP"
        record["src_ip"] = arp_info["sender_ip"]
        record["dst_ip"] = arp_info["target_ip"]
        return record  # ARP packets have no higher layers

    # ── Layer 3 ──────────────────────────────────────────────────────────
    if pkt.haslayer(IP):
        ip = pkt[IP]
        l3: dict[str, Any] = {
            "layer": "IPv4",
            "src_ip": _safe_str(ip.src),
            "dst_ip": _safe_str(ip.dst),
            "ttl": ip.ttl,
            "protocol_num": ip.proto,
            "identification": ip.id,
            "flags": str(ip.flags),
            "fragment_offset": ip.frag,
            "total_length": ip.len,
            "header_length": ip.ihl * 4,
        }
        record["layers"].append(l3)
        record["src_ip"] = l3["src_ip"]
        record["dst_ip"] = l3["dst_ip"]
        record["ttl"] = l3["ttl"]
    elif pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        l3 = {
            "layer": "IPv6",
            "src_ip": _safe_str(ip6.src),
            "dst_ip": _safe_str(ip6.dst),
            "hop_limit": ip6.hlim,
            "flow_label": ip6.fl,
            "traffic_class": ip6.tc,
            "payload_length": ip6.plen,
        }
        record["layers"].append(l3)
        record["src_ip"] = l3["src_ip"]
        record["dst_ip"] = l3["dst_ip"]
        record["ttl"] = l3.get("hop_limit", 0)

    # ICMP
    if pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        icmp_info: dict[str, Any] = {
            "layer": "ICMP",
            "type": icmp.type,
            "code": icmp.code,
            "type_name": {
                0: "Echo Reply", 3: "Destination Unreachable",
                5: "Redirect", 8: "Echo Request",
                11: "Time Exceeded",
            }.get(icmp.type, f"Type {icmp.type}"),
        }
        if hasattr(icmp, "id"):
            icmp_info["identifier"] = icmp.id
        if hasattr(icmp, "seq"):
            icmp_info["sequence"] = icmp.seq
        record["layers"].append(icmp_info)
        record["protocol"] = "ICMP"
        return record

    # ── Layer 4 ──────────────────────────────────────────────────────────
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        flags_int = int(tcp.flags) if tcp.flags else 0
        l4: dict[str, Any] = {
            "layer": "TCP",
            "src_port": tcp.sport,
            "dst_port": tcp.dport,
            "seq": tcp.seq,
            "ack": tcp.ack,
            "flags": _flags_to_list(flags_int),
            "flags_raw": flags_int,
            "window": tcp.window,
            "data_offset": tcp.dataofs * 4 if tcp.dataofs else 0,
        }
        record["layers"].append(l4)
        record["src_port"] = l4["src_port"]
        record["dst_port"] = l4["dst_port"]
        record["protocol"] = "TCP"
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        l4 = {
            "layer": "UDP",
            "src_port": udp.sport,
            "dst_port": udp.dport,
            "length": udp.len,
        }
        record["layers"].append(l4)
        record["src_port"] = l4["src_port"]
        record["dst_port"] = l4["dst_port"]
        record["protocol"] = "UDP"

    # ── Layer 7 ──────────────────────────────────────────────────────────
    src_port = record.get("src_port", 0)
    dst_port = record.get("dst_port", 0)

    # DNS
    if pkt.haslayer(DNS):
        dns = pkt[DNS]
        dns_info: dict[str, Any] = {"layer": "DNS"}

        # Query
        if dns.qr == 0 and pkt.haslayer(DNSQR):
            qr = pkt[DNSQR]
            dns_info["type"] = "query"
            dns_info["query_name"] = _safe_str(qr.qname.decode() if isinstance(qr.qname, bytes) else qr.qname).rstrip(".")
            qtype_map = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}
            dns_info["query_type"] = qtype_map.get(qr.qtype, str(qr.qtype))
        # Response
        elif dns.qr == 1:
            dns_info["type"] = "response"
            dns_info["rcode"] = dns.rcode
            rcode_map = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}
            dns_info["rcode_name"] = rcode_map.get(dns.rcode, str(dns.rcode))
            answers = []
            for i in range(dns.ancount):
                try:
                    rr = dns.an[i]
                    answers.append({
                        "name": _safe_str(rr.rrname.decode() if isinstance(rr.rrname, bytes) else rr.rrname).rstrip("."),
                        "type": str(rr.type),
                        "rdata": _safe_str(rr.rdata.decode() if isinstance(rr.rdata, bytes) else rr.rdata) if hasattr(rr, "rdata") else "",
                        "ttl": rr.ttl,
                    })
                except Exception:
                    pass
            dns_info["answers"] = answers
            if pkt.haslayer(DNSQR):
                qr = pkt[DNSQR]
                dns_info["query_name"] = _safe_str(qr.qname.decode() if isinstance(qr.qname, bytes) else qr.qname).rstrip(".")

        record["layers"].append(dns_info)
        record["protocol"] = "DNS"
        return record

    # Payload-based L7 inspection (TCP only)
    raw_payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""

    if raw_payload and record.get("protocol") == "TCP":
        record["payload_length"] = len(raw_payload)
        record["payload_hash"] = hashlib.sha256(raw_payload).hexdigest()[:16]

        # ── TLS ──
        if raw_payload[0:1] == b"\x16":
            tls_info = _parse_tls_client_hello(raw_payload)
            if tls_info:
                tls_layer: dict[str, Any] = {"layer": "TLS", "handshake": "ClientHello"}
                tls_layer.update(tls_info)
                record["layers"].append(tls_layer)
                record["protocol"] = "TLS"
                if "sni" in tls_info:
                    record["sni"] = tls_info["sni"]
                return record

        # ── HTTP Request ──
        http_req = _parse_http_request(raw_payload)
        if http_req:
            http_req["layer"] = "HTTP"
            http_req["direction"] = "request"
            record["layers"].append(http_req)
            record["protocol"] = "HTTP"
            return record

        # ── HTTP Response ──
        http_resp = _parse_http_response(raw_payload)
        if http_resp:
            http_resp["layer"] = "HTTP"
            http_resp["direction"] = "response"
            record["layers"].append(http_resp)
            record["protocol"] = "HTTP"
            return record

        # ── SSH ──
        if dst_port == 22 or src_port == 22:
            try:
                text = raw_payload.decode("ascii", errors="replace")
                if text.startswith("SSH-"):
                    ssh_info = {
                        "layer": "SSH",
                        "version_string": text.strip(),
                    }
                    record["layers"].append(ssh_info)
                    record["protocol"] = "SSH"
                    return record
            except Exception:
                pass

        # ── FTP ──
        if dst_port == 21 or src_port == 21:
            try:
                text = raw_payload.decode("ascii", errors="replace").strip()
                ftp_commands = ("USER", "PASS", "RETR", "STOR", "LIST", "CWD",
                                "PWD", "QUIT", "PORT", "PASV", "TYPE")
                parts = text.split(" ", 1)
                if parts[0].upper() in ftp_commands:
                    record["layers"].append({
                        "layer": "FTP",
                        "command": parts[0].upper(),
                        "argument": parts[1] if len(parts) > 1 else "",
                    })
                    record["protocol"] = "FTP"
                    return record
                # FTP response (3-digit code)
                if len(parts[0]) == 3 and parts[0].isdigit():
                    record["layers"].append({
                        "layer": "FTP",
                        "response_code": int(parts[0]),
                        "message": parts[1] if len(parts) > 1 else "",
                    })
                    record["protocol"] = "FTP"
                    return record
            except Exception:
                pass

        # ── SMTP ──
        if dst_port == 25 or dst_port == 587 or src_port == 25 or src_port == 587:
            try:
                text = raw_payload.decode("ascii", errors="replace").strip()
                smtp_commands = ("EHLO", "HELO", "MAIL FROM", "RCPT TO",
                                 "DATA", "QUIT", "AUTH", "STARTTLS")
                upper = text.upper()
                for cmd in smtp_commands:
                    if upper.startswith(cmd):
                        record["layers"].append({
                            "layer": "SMTP",
                            "command": cmd,
                            "data": text[len(cmd):].strip().lstrip(":").strip(),
                        })
                        record["protocol"] = "SMTP"
                        return record
            except Exception:
                pass

    # Assign generic protocol name if still TCP/UDP
    if record.get("protocol") == "TCP":
        well_known = {
            80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP",
            25: "SMTP", 587: "SMTP", 53: "DNS", 3306: "MySQL",
            5432: "PostgreSQL", 6379: "Redis", 3389: "RDP",
            8080: "HTTP-Alt", 8443: "HTTPS-Alt",
        }
        for port in (dst_port, src_port):
            if port in well_known:
                record["protocol"] = well_known[port]
                break

    if record.get("protocol") == "UDP":
        if dst_port == 53 or src_port == 53:
            record["protocol"] = "DNS"
        elif dst_port == 67 or dst_port == 68:
            record["protocol"] = "DHCP"
        elif dst_port == 123:
            record["protocol"] = "NTP"
        elif dst_port == 5353:
            record["protocol"] = "mDNS"

    return record
