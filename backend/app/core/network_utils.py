"""
Network Utils — Shared network/IP utilities.

بيوفر:
- IP validation (v4/v6)
- IP normalization
- CIDR matching
- Private/Public IP detection
- Reserved/Special IP detection
- Loopback/Link-local detection
- IPv4 ↔ IPv6 conversion
- Port validation
- Domain validation
- URL parsing & validation
- Subnet checks
- IP range checks

الفكرة:
- مكتبة مساعدة بتُستخدم من كل ملفات Tier 2
- بسيطة، سريعة، بدون dependencies خارجية (بس ipaddress + socket)
- error-safe (بترجع None/False بدل ما ترمي exception)

الاستخدام:
- ip_logger.py
- geoip.py
- ip_reputation.py
- whitelist_manager.py
- rate_limiter.py
- أي ملف محتاج IP/network handling
"""

import ipaddress
import re
import socket
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

import structlog

logger = structlog.get_logger()


class NetworkUtils:
    """
    Network/IP Utilities.

    كل الدوال بترجع None/False لو فشلت بدل ما ترمي exception.
    """

    # ─── Config ────────────────────────────────────────────
    MAX_IP_LENGTH = 45          # IPv6 كامل مع scope

    # ─── Regex Patterns ───────────────────────────────────
    DOMAIN_PATTERN = re.compile(
        r"^(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"
        r"+[a-zA-Z]{2,}$"
    )

    EMAIL_PATTERN = re.compile(
        r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    )

    URL_PATTERN = re.compile(
        r"^https?://"
        r"(?:\S+(?::\S*)?@)?"
        r"(?:(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}|"
        r"localhost|"
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
        r"(?::\d{2,5})?"
        r"(?:/\S*)?$"
    )

    # ─── Private IP Ranges (CIDR) ─────────────────────────
    PRIVATE_RANGES_V4 = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",   # Link-local
        "127.0.0.0/8",      # Loopback
        "100.64.0.0/10",    # Shared address space (CGN)
    ]

    PRIVATE_RANGES_V6 = [
        "::1/128",          # Loopback
        "fc00::/7",         # Unique local
        "fe80::/10",        # Link-local
    ]

    # ─── Special IP Ranges ────────────────────────────────
    RESERVED_RANGES = [
        "0.0.0.0/8",        # Current network
        "192.0.0.0/24",     # IETF Protocol Assignments
        "192.0.2.0/24",     # TEST-NET-1
        "198.18.0.0/15",    # Benchmarking
        "198.51.100.0/24",  # TEST-NET-2
        "203.0.113.0/24",   # TEST-NET-3
        "224.0.0.0/4",      # Multicast
        "240.0.0.0/4",      # Reserved
        "255.255.255.255/32",  # Broadcast
    ]

    # ─── Common Ports ─────────────────────────────────────
    WELL_KNOWN_PORTS = {
        20: "ftp-data",
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        143: "imap",
        443: "https",
        445: "smb",
        587: "smtp-submission",
        993: "imaps",
        995: "pop3s",
        1433: "mssql",
        3306: "mysql",
        3389: "rdp",
        5432: "postgres",
        5900: "vnc",
        6379: "redis",
        8080: "http-alt",
        8443: "https-alt",
        27017: "mongodb",
    }

    # ═══════════════════════════════════════════════════════
    #  IP Validation
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def is_valid_ipv4(ip: str) -> bool:
        """بيتحقق لو IPv4 صحيح."""
        if not ip or not isinstance(ip, str):
            return False
        try:
            ipaddress.IPv4Address(ip)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False

    @staticmethod
    def is_valid_ipv6(ip: str) -> bool:
        """بيتحقق لو IPv6 صحيح."""
        if not ip or not isinstance(ip, str):
            return False
        try:
            ipaddress.IPv6Address(ip)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False

    @classmethod
    def is_valid_ip(cls, ip: str) -> bool:
        """بيتحقق لو IP صحيح (v4 أو v6)."""
        return cls.is_valid_ipv4(ip) or cls.is_valid_ipv6(ip)

    @staticmethod
    def normalize_ip(ip: str) -> Optional[str]:
        """
        بيطبع الـ IP لشكل موحد.

        مثال: "::1" → "0:0:0:0:0:0:0:1"
              "192.168.001.001" → "192.168.1.1"
        """
        if not ip or not isinstance(ip, str):
            return None
        try:
            return str(ipaddress.ip_address(ip.strip()))
        except (ipaddress.AddressValueError, ValueError):
            return None

    @staticmethod
    def get_ip_version(ip: str) -> Optional[int]:
        """بيرجع إصدار الـ IP (4 أو 6)."""
        try:
            addr = ipaddress.ip_address(ip)
            return addr.version
        except (ipaddress.AddressValueError, ValueError):
            return None

    # ═══════════════════════════════════════════════════════
    #  Private / Public IP Detection
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """بيتحقق لو IP خاص."""
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_private
        except (ipaddress.AddressValueError, ValueError):
            return False

    @staticmethod
    def is_public_ip(ip: str) -> bool:
        """بيتحقق لو IP عام (على الإنترنت)."""
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_global
        except (ipaddress.AddressValueError, ValueError):
            return False

    @staticmethod
    def is_loopback(ip: str) -> bool:
        """بيتحقق لو loopback (127.0.0.1 أو ::1)."""
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_loopback
        except (ipaddress.AddressValueError, ValueError):
            return False

    @staticmethod
    def is_link_local(ip: str) -> bool:
        """بيتحقق لو link-local."""
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_link_local
        except (ipaddress.AddressValueError, ValueError):
            return False

    @staticmethod
    def is_multicast(ip: str) -> bool:
        """بيتحقق لو multicast."""
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_multicast
        except (ipaddress.AddressValueError, ValueError):
            return False

    @staticmethod
    def is_reserved(ip: str) -> bool:
        """بيتحقق لو reserved."""
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_reserved
        except (ipaddress.AddressValueError, ValueError):
            return False

    @classmethod
    def is_special_ip(cls, ip: str) -> bool:
        """
        بيتحقق لو IP خاص/محجوز.

        (Loopback, Link-local, Multicast, Reserved, Private)
        """
        return (
            cls.is_private_ip(ip)
            or cls.is_loopback(ip)
            or cls.is_link_local(ip)
            or cls.is_multicast(ip)
            or cls.is_reserved(ip)
        )

    @classmethod
    def classify_ip(cls, ip: str) -> Dict[str, Any]:
        """
        بيصنف الـ IP بشكل شامل.

        Returns:
            dict فيه: valid, version, is_private, is_public, ...
        """
        if not cls.is_valid_ip(ip):
            return {
                "valid": False,
                "ip": ip,
            }

        addr = ipaddress.ip_address(ip)

        return {
            "valid": True,
            "ip": str(addr),
            "version": addr.version,
            "is_private": addr.is_private,
            "is_global": addr.is_global,
            "is_loopback": addr.is_loopback,
            "is_link_local": addr.is_link_local,
            "is_multicast": addr.is_multicast,
            "is_reserved": addr.is_reserved,
            "is_unspecified": addr.is_unspecified,
            "compressed": addr.compressed,
            "exploded": addr.exploded,
        }

    # ═══════════════════════════════════════════════════════
    #  CIDR Operations
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def is_valid_cidr(cidr: str) -> bool:
        """بيتحقق لو CIDR صحيح."""
        if not cidr or not isinstance(cidr, str):
            return False
        try:
            ipaddress.ip_network(cidr, strict=False)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False

    @staticmethod
    def ip_in_cidr(ip: str, cidr: str) -> bool:
        """بيتحقق لو IP جوه CIDR range."""
        try:
            addr = ipaddress.ip_address(ip)
            network = ipaddress.ip_network(cidr, strict=False)
            return addr in network
        except (ipaddress.AddressValueError, ValueError):
            return False

    @staticmethod
    def ip_in_any_cidr(ip: str, cidrs: List[str]) -> bool:
        """بيتحقق لو IP جوه أي CIDR من القائمة."""
        for cidr in cidrs:
            if NetworkUtils.ip_in_cidr(ip, cidr):
                return True
        return False

    @staticmethod
    def get_network_info(cidr: str) -> Optional[Dict[str, Any]]:
        """بيرجع معلومات الـ network."""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            return {
                "cidr": str(network),
                "network_address": str(network.network_address),
                "broadcast_address": (
                    str(network.broadcast_address)
                    if network.version == 4 else None
                ),
                "netmask": str(network.netmask),
                "prefix_length": network.prefixlen,
                "num_addresses": network.num_addresses,
                "version": network.version,
                "is_private": network.is_private,
                "is_global": network.is_global,
            }
        except (ipaddress.AddressValueError, ValueError):
            return None

    # ═══════════════════════════════════════════════════════
    #  IP Range Checks
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def ip_in_range(ip: str, start: str, end: str) -> bool:
        """بيتحقق لو IP بين start و end."""
        try:
            addr = ipaddress.ip_address(ip)
            start_addr = ipaddress.ip_address(start)
            end_addr = ipaddress.ip_address(end)
            return start_addr <= addr <= end_addr
        except (ipaddress.AddressValueError, ValueError):
            return False

    # ═══════════════════════════════════════════════════════
    #  Domain / URL Validation
    # ═══════════════════════════════════════════════════════

    @classmethod
    def is_valid_domain(cls, domain: str) -> bool:
        """بيتحقق لو domain صحيح."""
        if not domain or not isinstance(domain, str):
            return False
        if len(domain) > 253:
            return False
        return bool(cls.DOMAIN_PATTERN.match(domain))

    @classmethod
    def is_valid_email(cls, email: str) -> bool:
        """بيتحقق لو email صحيح."""
        if not email or not isinstance(email, str):
            return False
        if len(email) > 320:
            return False
        return bool(cls.EMAIL_PATTERN.match(email))

    @classmethod
    def is_valid_url(cls, url: str) -> bool:
        """بيتحقق لو URL صحيح."""
        if not url or not isinstance(url, str):
            return False
        if len(url) > 2048:
            return False
        return bool(cls.URL_PATTERN.match(url))

    @staticmethod
    def parse_url(url: str) -> Optional[Dict[str, Any]]:
        """
        بيفكك الـ URL لأجزاء.

        Returns:
            dict فيه: scheme, host, port, path, query, fragment
        """
        if not url:
            return None
        try:
            parsed = urllib.parse.urlparse(url)

            # استخرج port
            port = parsed.port
            if port is None:
                if parsed.scheme == "https":
                    port = 443
                elif parsed.scheme == "http":
                    port = 80

            return {
                "scheme": parsed.scheme,
                "host": parsed.hostname,
                "port": port,
                "path": parsed.path,
                "query": parsed.query,
                "fragment": parsed.fragment,
                "username": parsed.username,
                "password": parsed.password,
            }
        except (ValueError, AttributeError):
            return None

    @staticmethod
    def extract_host(url: str) -> Optional[str]:
        """بيستخرج الـ host من URL."""
        parsed = NetworkUtils.parse_url(url)
        return parsed.get("host") if parsed else None

    # ═══════════════════════════════════════════════════════
    #  Port Validation
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def is_valid_port(port: Any) -> bool:
        """بيتحقق لو port صحيح (1-65535)."""
        try:
            p = int(port)
            return 1 <= p <= 65535
        except (ValueError, TypeError):
            return False

    @classmethod
    def get_port_name(cls, port: int) -> str:
        """بيرجع اسم الـ port لو معروف."""
        return cls.WELL_KNOWN_PORTS.get(port, "unknown")

    # ═══════════════════════════════════════════════════════
    #  DNS / Hostname Resolution
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def resolve_hostname(hostname: str) -> Optional[str]:
        """
        بيعمل resolve للـ hostname.

        Returns:
            IP address أو None
        """
        if not hostname:
            return None
        try:
            return socket.gethostbyname(hostname)
        except (socket.gaierror, OSError):
            return None

    @staticmethod
    def reverse_dns(ip: str) -> Optional[str]:
        """
        بيعمل reverse DNS lookup.

        Returns:
            hostname أو None
        """
        if not NetworkUtils.is_valid_ip(ip):
            return None
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            return None

    # ═══════════════════════════════════════════════════════
    #  IP Conversion
    # ═══════════════════════════════════════════════════════

    @staticmethod
    def ip_to_int(ip: str) -> Optional[int]:
        """بيحول IPv4 لـ integer."""
        try:
            return int(ipaddress.IPv4Address(ip))
        except (ipaddress.AddressValueError, ValueError):
            return None

    @staticmethod
    def int_to_ip(num: int) -> Optional[str]:
        """بيحول integer لـ IPv4."""
        try:
            return str(ipaddress.IPv4Address(num))
        except (ipaddress.AddressValueError, ValueError):
            return None

    @staticmethod
    def ipv4_to_ipv6_mapped(ipv4: str) -> Optional[str]:
        """
        بيحول IPv4 لـ IPv6 mapped.

        مثال: "192.168.1.1" → "::ffff:192.168.1.1"
        """
        try:
            addr = ipaddress.IPv4Address(ipv4)
            mapped = ipaddress.IPv6Address(f"::ffff:{addr}")
            return str(mapped)
        except (ipaddress.AddressValueError, ValueError):
            return None

    # ═══════════════════════════════════════════════════════
    #  High-Level Helpers
    # ═══════════════════════════════════════════════════════

    @classmethod
    def analyze_ip(cls, ip: str) -> Dict[str, Any]:
        """
        تحليل شامل للـ IP.

        Returns:
            dict فيه: valid, version, type, is_special, ...
        """
        if not cls.is_valid_ip(ip):
            return {
                "valid": False,
                "ip": ip,
                "reason": "invalid_format",
            }

        classified = cls.classify_ip(ip)

        # حدد النوع
        ip_type = "public"
        if classified["is_loopback"]:
            ip_type = "loopback"
        elif classified["is_link_local"]:
            ip_type = "link_local"
        elif classified["is_multicast"]:
            ip_type = "multicast"
        elif classified["is_reserved"]:
            ip_type = "reserved"
        elif classified["is_private"]:
            ip_type = "private"
        elif classified["is_global"]:
            ip_type = "public"

        return {
            "valid": True,
            "ip": classified["ip"],
            "version": classified["version"],
            "type": ip_type,
            "is_special": cls.is_special_ip(ip),
            "is_public": classified["is_global"],
            "classification": classified,
        }

    @staticmethod
    def anonymize_ip(ip: str, keep_octets: int = 2) -> str:
        """
        بيخفي جزء من الـ IP (للـ logs).

        مثال: "192.168.1.100" مع keep_octets=2 → "192.168.x.x"
        """
        if not NetworkUtils.is_valid_ipv4(ip):
            return ip

        parts = ip.split(".")
        if keep_octets >= 4:
            return ip
        if keep_octets <= 0:
            return "x.x.x.x"

        result = parts[:keep_octets] + ["x"] * (4 - keep_octets)
        return ".".join(result)


# ─── Standalone functions (للـ convenience) ─────────────

def is_valid_ip(ip: str) -> bool:
    """Shortcut for NetworkUtils.is_valid_ip."""
    return NetworkUtils.is_valid_ip(ip)


def is_private_ip(ip: str) -> bool:
    """Shortcut for NetworkUtils.is_private_ip."""
    return NetworkUtils.is_private_ip(ip)


def is_public_ip(ip: str) -> bool:
    """Shortcut for NetworkUtils.is_public_ip."""
    return NetworkUtils.is_public_ip(ip)


def is_valid_ipv4(ip: str) -> bool:
    """Shortcut for NetworkUtils.is_valid_ipv4."""
    return NetworkUtils.is_valid_ipv4(ip)


def is_valid_ipv6(ip: str) -> bool:
    """Shortcut for NetworkUtils.is_valid_ipv6."""
    return NetworkUtils.is_valid_ipv6(ip)


def normalize_ip(ip: str) -> Optional[str]:
    """Shortcut for NetworkUtils.normalize_ip."""
    return NetworkUtils.normalize_ip(ip)


def ip_in_cidr(ip: str, cidr: str) -> bool:
    """Shortcut for NetworkUtils.ip_in_cidr."""
    return NetworkUtils.ip_in_cidr(ip, cidr)


def is_valid_domain(domain: str) -> bool:
    """Shortcut for NetworkUtils.is_valid_domain."""
    return NetworkUtils.is_valid_domain(domain)


def is_valid_email(email: str) -> bool:
    """Shortcut for NetworkUtils.is_valid_email."""
    return NetworkUtils.is_valid_email(email)


def is_valid_url(url: str) -> bool:
    """Shortcut for NetworkUtils.is_valid_url."""
    return NetworkUtils.is_valid_url(url)


def parse_url(url: str) -> Optional[Dict[str, Any]]:
    """Shortcut for NetworkUtils.parse_url."""
    return NetworkUtils.parse_url(url)


def is_valid_port(port: Any) -> bool:
    """Shortcut for NetworkUtils.is_valid_port."""
    return NetworkUtils.is_valid_port(port)


def anonymize_ip(ip: str, keep_octets: int = 2) -> str:
    """Shortcut for NetworkUtils.anonymize_ip."""
    return NetworkUtils.anonymize_ip(ip, keep_octets)


def analyze_ip(ip: str) -> Dict[str, Any]:
    """Shortcut for NetworkUtils.analyze_ip."""
    return NetworkUtils.analyze_ip(ip)