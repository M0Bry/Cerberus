"""
Advanced Attack Patterns — Detects advanced/emerging attack patterns.

بيكشف أنماط هجمات متقدمة:
- XXE (XML External Entity)
- SSRF (Server-Side Request Forgery)
- NoSQL Injection
- LDAP Injection
- SSTI (Server-Side Template Injection)
- CRLF Injection
- Open Redirect
- JWT Attacks
- Prototype Pollution
- GraphQL Injection
- Deserialization
- Host Header Injection

ملف مستقل — مش بيعتمد على أي حاجة تانية.
"""

import re
from typing import Dict, List, Optional, Set

import structlog

logger = structlog.get_logger()


class AdvancedPatterns:
    """
    كلاس لكشف أنماط الهجمات المتقدمة.

    كل pattern له قائمة من الـ regexes.
    """

    # ─── XXE (XML External Entity) ─────────────────────────
    XXE_PATTERNS = [
        r"<!ENTITY\s+\w+\s+SYSTEM",
        r"<!ENTITY\s+\w+\s+PUBLIC",
        r"<!DOCTYPE\s+\w+\s*\[",
        r"<!DOCTYPE\s+\w+\s+SYSTEM",
        r"SYSTEM\s+['\"]file://",
        r"SYSTEM\s+['\"]http://",
        r"SYSTEM\s+['\"]https://",
        r"SYSTEM\s+['\"]php://",
        r"SYSTEM\s+['\"]expect://",
        r"SYSTEM\s+['\"]gopher://",
        r"&xxe;",
        r"&file;",
        r"%remote;",
        r"%local;",
        r"<!ENTITY\s+%\s+\w+",
    ]

    # ─── SSRF (Server-Side Request Forgery) ───────────────
    SSRF_PATTERNS = [
        # Localhost / Internal
        r"(https?|ftp|file|gopher|dict)://127\.0\.0\.1",
        r"(https?|ftp|file|gopher|dict)://localhost",
        r"(https?|ftp|file|gopher|dict)://0\.0\.0\.0",
        r"(https?|ftp|file|gopher|dict)://\[::1\]",
        # Cloud metadata (AWS, GCP, Azure)
        r"169\.254\.169\.254",
        r"metadata\.google\.internal",
        r"metadata\.azure\.com",
        r"100\.100\.100\.200",
        # Internal IPs
        r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        r"192\.168\.\d{1,3}\.\d{1,3}",
        r"172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}",
        # Protocols
        r"file://",
        r"gopher://",
        r"dict://",
        r"ftp://",
        r"ldap://",
        r"tftp://",
        # URL encoding tricks
        r"127\.0\.0\.1\.\w+\.nip\.io",
        r"127\.0\.0\.1\.xip\.io",
        # Decimal / Octal / Hex IP
        r"2130706433",           # 127.0.0.1 in decimal
        r"0177\.0\.0\.1",        # octal
        r"0x7f\.0\.0\.1",        # hex
    ]

    # ─── NoSQL Injection ───────────────────────────────────
    NOSQL_PATTERNS = [
        # MongoDB operators (مع quotes اختيارية)
        r"\$where\s*[\"']?\s*:",
        r"\$ne\s*[\"']?\s*:",
        r"\$gt\s*[\"']?\s*:",
        r"\$lt\s*[\"']?\s*:",
        r"\$gte\s*[\"']?\s*:",
        r"\$lte\s*[\"']?\s*:",
        r"\$regex\s*[\"']?\s*:",
        r"\$exists\s*[\"']?\s*:",
        r"\$in\s*[\"']?\s*:",
        r"\$nin\s*[\"']?\s*:",
        r"\$or\s*[\"']?\s*:",
        r"\$and\s*[\"']?\s*:",
        r"\$not\s*[\"']?\s*:",
        r"\$nor\s*[\"']?\s*:",
        r"\$type\s*[\"']?\s*:",
        r"\$where\b",
        r"\$ne\b",
        r"\$regex\b",
        # JavaScript injection
        r"this\.\w+\s*[=<>!]",
        r"function\s*\(\s*\)\s*\{",
        r";\s*return\s+",
        # CouchDB
        r"_all_docs",
        r"_design/",
        # Common payloads
        r"\{\s*[\"']?\$ne[\"']?\s*:\s*null\s*\}",
        r"\{\s*[\"']?\$ne[\"']?\s*:\s*[\"']\w+[\"']\s*\}",
        r"\{\s*[\"']?\$gt[\"']?\s*:\s*[\"']{2}\s*\}",
    ]
    # ─── LDAP Injection ────────────────────────────────────
    LDAP_PATTERNS = [
        r"\(\s*\|\s*\(",
        r"\(\s*&\s*\(",
        r"\(\s*!\s*\(",
        r"\*\)\(\w+=\*\)",
        r"\(\w+=\*\)",
        r"\)\s*\(\s*\|\s*\(",
        r"\*\)\s*\(\s*\w+=\*",
        r"\)\s*\(\s*cn=\*",
        r"admin\)\(\|\(",
        r"\)\(cn=\*",
        # Common attributes
        r"\(\s*(cn|uid|mail|userPassword|memberOf)\s*=",
    ]

    # ─── SSTI (Server-Side Template Injection) ─────────────
    SSTI_PATTERNS = [
        # Jinja2 / Twig
        r"\{\{\s*[\d'\"]+\s*[\*\+\-\/]\s*[\d'\"]+\s*\}\}",
        r"\{\{\s*\d+\s*\*\s*\d+\s*\}\}",
        r"\{\{\s*config\s*\}\}",
        r"\{\{\s*self\s*\}\}",
        r"\{\{\s*request\s*\}\}",
        r"\{\{\s*session\s*\}\}",
        r"\{\{\s*['\"]\w+['\"]\.__class__",
        r"\{\{\s*['\"]\w+['\"]\.__mro__",
        r"\{\{\s*['\"]\w+['\"]\.__subclasses__",
        r"\{\{\s*lipsum\.__class__",
        # Freemarker
        r"\$\{.*\}",
        r"<\#assign",
        r"\$\{\s*\d+\s*[\*\+\-]\s*\d+\s*\}",
        # Velocity
        r"\#set\s*\(",
        r"\#if\s*\(",
        # Smarty
        r"\{php\}",
        r"\{/php\}",
        # ERB (Ruby)
        r"<%=.*%>",
        # Pebble / Thymeleaf (Java)
        r"\{\{\s*['\"]\w+['\"]\s*\}\}",
        r"\*\{.*\}",
        # Razor (.NET)
        r"@\(.*\)",
        # Handlebars
        r"\{\{\s*this\s*\}\}",
    ]

    # ─── CRLF Injection ────────────────────────────────────
    CRLF_PATTERNS = [
        r"%0d%0a",
        r"%0D%0A",
        r"%0a",
        r"%0d",
        r"\\r\\n",
        r"\r\n",
        r"%5cr%5cn",           # \\r\\n URL-encoded
        r"%E5%98%8A%E5%98%8D",  # Unicode CRLF
        r"\\\\r\\\\n",
    ]

    # ─── Open Redirect ─────────────────────────────────────
    OPEN_REDIRECT_PATTERNS = [
        r"(https?|ftp)://[^/]*@",       # user@host trick
        r"(https?|ftp)://[^.]*\.[^.]*@",  # subdomain trick
        r"\/\/[a-z0-9\-\.]+\.[a-z]{2,}",  # protocol-relative
        r"^https?://evil\.",
        r"^//evil\.",
        r"url=(https?|ftp)://",
        r"redirect=(https?|ftp)://",
        r"next=(https?|ftp)://",
        r"return=(https?|ftp)://",
        r"continue=(https?|ftp)://",
    ]

    # ─── JWT Attacks ───────────────────────────────────────
    JWT_PATTERNS = [
        r"eyJhbGciOiJub25lIiw",         # alg: none
        r"eyJhbGciOiJOb25lIiw",         # alg: None
        r"eyJhbGciOiJub25lIn0",         # base64 "none"
        r"\"alg\"\s*:\s*\"none\"",
        r"\"alg\"\s*:\s*\"None\"",
        r"\"alg\"\s*:\s*\"NONE\"",
        r"\"alg\"\s*:\s*\"HS256\"",     # HS256 confusion
        r"\"alg\"\s*:\s*\"HS384\"",
        r"\"alg\"\s*:\s*\"HS512\"",
    ]

        # ─── Prototype Pollution ───────────────────────────────
    PROTOTYPE_POLLUTION_PATTERNS = [
        r"__proto__\s*[\"']?\s*[:=]",
        r"[\"']__proto__[\"']\s*:",
        r"constructor\s*\.\s*prototype",
        r"[\"']?constructor[\"']?\s*[\"']?\s*[:=]\s*[\"']?prototype",
        r"prototype\s*[\"']?\s*[:=]",
        r"\[constructor\]",
        r"\[__proto__\]",
        r"\[\"__proto__\"\]",
        r"__defineGetter__",
        r"__defineSetter__",
        r"__lookupGetter__",
        r"__lookupSetter__",
        r"\b__proto__\b",
        r"\bprototype\b.*\bconstructor\b",
    ]

    # ─── GraphQL Injection ─────────────────────────────────
    GRAPHQL_PATTERNS = [
        r"__schema",
        r"__type",
        r"\bmutation\s*\{",
        r"\bquery\s*\{",
        r"\bsubscription\s*\{",
        r"\.\.\.\s*on\s+\w+",           # fragments
        r"__typename",
        r"\bfragment\s+\w+\s+on\b",
        # Introspection
        r"\{\s*__schema\s*\{",
        r"\{\s*__type\s*\(",
    ]

    # ─── Deserialization ───────────────────────────────────
    DESERIALIZATION_PATTERNS = [
        # Python Pickle
        r"gASV",                         # Pickle base64 start
        r"cos\nsystem",
        r"cposix\nsystem",
        r"__reduce__",
        r"__reduce_ex__",
        r"pickle\.loads",
        # Java serialization
        r"rO0AB",                       # Java serialized base64
        r"\\xac\\xed",                  # Java magic (0xACED)
        r"java\.io\.ObjectInputStream",
        r"java\.util\.",
        # PHP
        r"O:\d+:\"",
        r"a:\d+:\{",
        r"__wakeup",
        r"__destruct",
        r"__sleep",
        # .NET
        r"AAEAAAD",                     # BinaryFormatter base64
        r"System\.Runtime\.Serialization",
        # YAML
        r"!!python/object",
        r"!!javax\.script",
        r"!!java\.net",
        r"!<tag:yaml\.org",
    ]

    # ─── Host Header Injection ─────────────────────────────
    HOST_HEADER_PATTERNS = [
        r"X-Forwarded-Host\s*:\s*evil",
        r"X-Host\s*:\s*evil",
        r"X-Original-URL\s*:\s*/admin",
        r"X-Rewrite-URL\s*:\s*/admin",
        r"X-HTTP-Method-Override\s*:\s*(GET|POST|PUT|DELETE)",
    ]

    # ─── Methods ───────────────────────────────────────────

    @classmethod
    def detect_xxe(cls, value: str) -> bool:
        """كشف XXE."""
        return cls._match_any(value, cls.XXE_PATTERNS)

    @classmethod
    def detect_ssrf(cls, value: str) -> bool:
        """كشف SSRF."""
        return cls._match_any(value, cls.SSRF_PATTERNS)

    @classmethod
    def detect_nosql(cls, value: str) -> bool:
        """كشف NoSQL Injection."""
        return cls._match_any(value, cls.NOSQL_PATTERNS)

    @classmethod
    def detect_ldap(cls, value: str) -> bool:
        """كشف LDAP Injection."""
        return cls._match_any(value, cls.LDAP_PATTERNS)

    @classmethod
    def detect_ssti(cls, value: str) -> bool:
        """كشف SSTI."""
        return cls._match_any(value, cls.SSTI_PATTERNS)

    @classmethod
    def detect_crlf(cls, value: str) -> bool:
        """كشف CRLF Injection."""
        return cls._match_any(value, cls.CRLF_PATTERNS)

    @classmethod
    def detect_open_redirect(cls, value: str) -> bool:
        """كشف Open Redirect."""
        return cls._match_any(value, cls.OPEN_REDIRECT_PATTERNS)

    @classmethod
    def detect_jwt(cls, value: str) -> bool:
        """كشف JWT Attacks."""
        return cls._match_any(value, cls.JWT_PATTERNS)

    @classmethod
    def detect_prototype_pollution(cls, value: str) -> bool:
        """كشف Prototype Pollution."""
        return cls._match_any(value, cls.PROTOTYPE_POLLUTION_PATTERNS)

    @classmethod
    def detect_graphql(cls, value: str) -> bool:
        """كشف GraphQL Injection."""
        return cls._match_any(value, cls.GRAPHQL_PATTERNS)

    @classmethod
    def detect_deserialization(cls, value: str) -> bool:
        """كشف Deserialization Attacks."""
        return cls._match_any(value, cls.DESERIALIZATION_PATTERNS)

    @classmethod
    def detect_host_header(cls, value: str) -> bool:
        """كشف Host Header Injection."""
        return cls._match_any(value, cls.HOST_HEADER_PATTERNS)

    # ─── All-in-One ────────────────────────────────────────

    @classmethod
    def detect_all(cls, value: str) -> Dict[str, bool]:
        """
        بيكشف كل الأنواع مرة واحدة.

        Returns:
            dict فيه كل نوع و لو موجود
        """
        return {
            "xxe": cls.detect_xxe(value),
            "ssrf": cls.detect_ssrf(value),
            "nosql": cls.detect_nosql(value),
            "ldap": cls.detect_ldap(value),
            "ssti": cls.detect_ssti(value),
            "crlf": cls.detect_crlf(value),
            "open_redirect": cls.detect_open_redirect(value),
            "jwt": cls.detect_jwt(value),
            "prototype_pollution": cls.detect_prototype_pollution(value),
            "graphql": cls.detect_graphql(value),
            "deserialization": cls.detect_deserialization(value),
            "host_header": cls.detect_host_header(value),
        }

    @classmethod
    def get_threat_summary(cls, value: str) -> str:
        """
        بترجع ملخص نصي للتهديدات.
        """
        threats = cls.detect_all(value)
        active = [k for k, v in threats.items() if v]
        return ", ".join(active) if active else "clean"

    @classmethod
    def get_threat_score(cls, value: str) -> int:
        """
        بترجع درجة خطورة (0-100).

        كل نوع له وزن مختلف.
        """
        threats = cls.detect_all(value)
        weights = {
            "xxe": 15,
            "ssrf": 20,
            "nosql": 15,
            "ldap": 10,
            "ssti": 20,
            "crlf": 10,
            "open_redirect": 8,
            "jwt": 15,
            "prototype_pollution": 12,
            "graphql": 10,
            "deserialization": 25,
            "host_header": 10,
        }
        score = sum(weights.get(k, 0) for k, v in threats.items() if v)
        return min(score, 100)

    # ─── Helper ────────────────────────────────────────────

    @staticmethod
    def _match_any(value: str, patterns: List[str]) -> bool:
        """بيدور على أي pattern في القائمة."""
        if not isinstance(value, str) or not value:
            return False
        for pattern in patterns:
            try:
                if re.search(pattern, value, re.IGNORECASE):
                    return True
            except re.error as e:
                logger.warning("regex_error", pattern=pattern, error=str(e))
                continue
        return False


# ─── Singleton ─────────────────────────────────────────────

advanced_patterns = AdvancedPatterns()