"""
JA3 Known-Bad Fingerprint Database
====================================
Hardcoded set of known-malicious JA3 hashes from public threat intel.
These fingerprints are associated with common attack tools and malware families.
"""

# Source: Various public JA3 databases and threat research
# Format: { ja3_hash: { "label": str, "family": str, "confidence": float } }

KNOWN_BAD_JA3: dict[str, dict] = {
    # Cobalt Strike
    "72a589da586844d7f0818ce684948eea": {
        "label": "Cobalt Strike",
        "family": "C2 Framework",
        "confidence": 0.95,
    },
    "a0e9f5d64349fb13191bc781f81f42e1": {
        "label": "Cobalt Strike Beacon",
        "family": "C2 Framework",
        "confidence": 0.90,
    },

    # Metasploit / Meterpreter
    "5d65ea3fb1d4aa7d826733d2f2cbf277": {
        "label": "Metasploit Meterpreter",
        "family": "Exploitation Framework",
        "confidence": 0.90,
    },
    "e35df3e00ca4ef31d42b34bebaa2f86e": {
        "label": "Metasploit Reverse HTTPS",
        "family": "Exploitation Framework",
        "confidence": 0.85,
    },

    # Trickbot
    "6734f37431670b3ab4292b8f60f29984": {
        "label": "Trickbot",
        "family": "Banking Trojan",
        "confidence": 0.92,
    },

    # Emotet
    "4d7a28d6f2263ed61de88ca66eb2e557": {
        "label": "Emotet",
        "family": "Loader / Dropper",
        "confidence": 0.88,
    },

    # Dridex
    "51c64c77e60f3980eea90869b68c58a8": {
        "label": "Dridex",
        "family": "Banking Trojan",
        "confidence": 0.85,
    },

    # AsyncRAT
    "3b5074b1b5d032e5620f69f9f700ff0e": {
        "label": "AsyncRAT",
        "family": "Remote Access Trojan",
        "confidence": 0.90,
    },

    # IcedID / BokBot
    "c12f54a3f91dc7bafd92b15ef9fba266": {
        "label": "IcedID",
        "family": "Banking Trojan",
        "confidence": 0.87,
    },

    # QakBot / QBot
    "c35a61411ee5bdf666b4d64b05c29e64": {
        "label": "QakBot",
        "family": "Banking Trojan / Loader",
        "confidence": 0.88,
    },

    # PoshC2
    "b386946a5a44d1ddcc843bc75336dfce": {
        "label": "PoshC2",
        "family": "C2 Framework",
        "confidence": 0.80,
    },

    # Sliver C2
    "cd08e31494f9531f0ab1fd510eb54013": {
        "label": "Sliver C2",
        "family": "C2 Framework",
        "confidence": 0.85,
    },

    # Empire / PowerShell Empire
    "2ce0bb3bb92f2de3e1a344bbc0bb6ead": {
        "label": "PowerShell Empire",
        "family": "C2 Framework",
        "confidence": 0.80,
    },

    # BazarLoader / BazarBackdoor
    "398b83e01ed4e49642d7ef6f0a3157b3": {
        "label": "BazarLoader",
        "family": "Loader / Backdoor",
        "confidence": 0.85,
    },

    # Generic suspicious - old/weak cipher suites
    "e7d705a3286e19ea42f587b344ee6865": {
        "label": "Suspicious Legacy TLS Client",
        "family": "Weak Crypto",
        "confidence": 0.60,
    },

    # Golang default TLS (common in custom malware)
    "473cd7cb9faa642487833865d516e578": {
        "label": "Go Default TLS",
        "family": "Suspicious (common in custom malware)",
        "confidence": 0.50,
    },

    # Python requests library (sometimes used in credential stealers)
    "b32309a26951912be7dba376398abc3b": {
        "label": "Python urllib3/requests",
        "family": "Scripting (possible automation/scraping)",
        "confidence": 0.30,
    },
}


def lookup_ja3(ja3_hash: str) -> dict | None:
    """Look up a JA3 hash in the known-bad database. Returns match dict or None."""
    return KNOWN_BAD_JA3.get(ja3_hash)
