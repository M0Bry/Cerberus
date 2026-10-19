"""
Header Validator — Validates HTTP headers for security issues.

بيفحص الـ HTTP Headers:
- Header Injection (\r\n في القيم)
- CRLF Injection (%0d%0a)
- Host Header spoofing
- X-Forwarded-For IP spoofing
- User-Agent analysis (bots, scanners)
- Referer validation
- Cookie security
- Authorization (JWT)
- Content-Type validation
- Size limits

ملف مستقل.
"""

import re
from typing import Any, Dict, List, Optional, Set, Tuple

import structlog

from app.core.advanced_patterns import AdvancedPatterns
from app.core.encoding_detector import EncodingDetector
from app.core.heuristic_scorer import HeuristicScorer

logger = structlog.get_logger()


class HeaderValidator:
    """
    كلاس لفحص HTTP Headers.

    بيفحص:
    - Header Injection
    - CRLF
    - Spoofing
    - Bots
    - Size limits
    """

    # ─── Limits ────────────────────────────────────────────
    MAX_HEADER_NAME_LENGTH = 256
    MAX_HEADER_VALUE_LENGTH = 8192
    MAX_HEADERS_COUNT = 100
    MAX_COOKIE_LENGTH = 4096
    MAX_USER_AGENT_LENGTH = 512
    MAX_URL_LENGTH = 2048

    # ─── Threshold ─────────────────────────────────────────
    BLOCK_THRESHOLD = 30

    # ─── Injection Patterns ────────────────────────────────
    INJECTION_PATTERNS = [
        r"\r\n",           # CRLF literal
        r"\n",             # LF
        r"\r",             # CR
        r"%0d%0a",         # URL-encoded CRLF
        r"%0a",            # URL-encoded LF
        r"%0d",            # URL-encoded CR
        r"\\r\\n",         # Escaped CRLF
        r"\\n",            # Escaped LF
        r"\\r",            # Escaped CR
        r"\x00",           # Null byte
        r"%00",            # URL-encoded null
    ]

    # ─── Bot/Suspicious User-Agents ────────────────────────
    SUSPICIOUS_UA_PATTERNS = [
        # Security tools
        r"(sqlmap|nikto|nmap|masscan|acunetix|nessus|openvas|burp|zap)",
        r"(dirbuster|gobuster|wfuzz|ffuf|feroxbuster|dirb)",
        r"(hydra|medusa|patator|ncrack)",
        r"(metasploit|msfconsole|cobalt.?strike)",
        # Scripts
        r"(curl|wget|httpie|python-requests|go-http-client|java/)",
        r"(libwww-perl|python-urllib|ruby|perl|php)",
        # Scanners
        r"(scanner|crawler|spider|bot|scraper)",
        # Empty / short
        r"^-?$",
    ]

    # ─── Allowed Content Types ─────────────────────────────
    ALLOWED_CONTENT_TYPES = {
        "application/json",
        "application/x-www-form-urlencoded",
        "multipart/form-data",
        "application/xml",
        "text/xml",
        "text/plain",
        "text/html",
        "application/octet-stream",
    }

    # ─── Dangerous Content Types ───────────────────────────
    DANGEROUS_CONTENT_TYPES = {
        "application/x-httpd-php",
        "application/x-php",
        "application/x-executable",
        "application/x-msdownload",
        "application/x-sh",
        "application/x-shellscript",
    }

    # ─── Main API ──────────────────────────────────────────

    @classmethod
    def validate_headers(cls, headers: Dict[str, str]) -> Dict[str, Any]:
        """
        بيفحص كل الـ headers.

        Returns:
            dict فيه:
            - valid: bool
            - issues: list of issues
            - score: خطورة
            - sanitized_headers: headers منضفة
        """
        if not isinstance(headers, dict):
            return cls._invalid("headers_not_dict")

        issues: List[Dict[str, Any]] = []
        total_score = 0
        sanitized: Dict[str, str] = {}

        # 1. عدد الـ headers
        if len(headers) > cls.MAX_HEADERS_COUNT:
            issues.append({
                "type": "too_many_headers",
                "count": len(headers),
                "max": cls.MAX_HEADERS_COUNT,
                "score": 10,
            })
            total_score += 10

        # 2. فحص كل header
        for name, value in headers.items():
            header_issues = cls._validate_single_header(name, value)
            if header_issues:
                issues.extend(header_issues["issues"])
                total_score += header_issues["score"]
            else:
                sanitized[name] = value

        # 3. فحوصات مخصصة
        custom_issues = cls._validate_custom_headers(headers)
        if custom_issues:
            issues.extend(custom_issues["issues"])
            total_score += custom_issues["score"]

        # 4. تحديد الخطورة
        score = min(total_score, 100)
        level = cls._get_level(score)

        return {
            "valid": score < cls.BLOCK_THRESHOLD,
            "score": score,
            "level": level,
            "issues": issues,
            "sanitized_headers": sanitized if score < cls.BLOCK_THRESHOLD else {},
        }

    @classmethod
    def _validate_single_header(
        cls,
        name: str,
        value: str,
    ) -> Optional[Dict[str, Any]]:
        """بيفحص header واحد."""
        issues: List[Dict[str, Any]] = []
        score = 0

        # 1. نوع البيانات
        if not isinstance(name, str) or not isinstance(value, str):
            return {
                "issues": [{"type": "invalid_type", "score": 5}],
                "score": 5,
            }

        # 2. اسم الـ header
        if len(name) > cls.MAX_HEADER_NAME_LENGTH:
            issues.append({
                "type": "header_name_too_long",
                "header": name[:50],
                "score": 5,
            })
            score += 5

        if not cls._is_valid_header_name(name):
            issues.append({
                "type": "invalid_header_name",
                "header": name[:50],
                "score": 15,
            })
            score += 15

        # 3. قيمة الـ header
        if len(value) > cls.MAX_HEADER_VALUE_LENGTH:
            issues.append({
                "type": "header_value_too_long",
                "header": name,
                "length": len(value),
                "score": 5,
            })
            score += 5

        # 4. Header Injection
        if cls._has_injection(value):
            issues.append({
                "type": "header_injection",
                "header": name,
                "score": 40,
            })
            score += 40

        # 5. Null bytes
        if "\x00" in value:
            issues.append({
                "type": "null_byte_in_header",
                "header": name,
                "score": 30,
            })
            score += 30

        # 6. Heuristic scoring
        heuristic = HeuristicScorer.score(value, name)
        if heuristic["score"] >= cls.BLOCK_THRESHOLD:
            issues.append({
                "type": "suspicious_header_value",
                "header": name,
                "heuristic_score": heuristic["score"],
                "signals": list(heuristic["signals"].keys()),
                "score": min(heuristic["score"], 35),
            })
            score += min(heuristic["score"], 35)

        if not issues:
            return None

        return {"issues": issues, "score": score}

    @classmethod
    def _validate_custom_headers(cls, headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """فحوصات مخصصة لـ headers معينة."""
        issues: List[Dict[str, Any]] = []
        score = 0

        # طبّع الأسماء لـ lowercase
        headers_lower = {k.lower(): v for k, v in headers.items()}

        # 1. Host Header
        if "host" in headers_lower:
            host = headers_lower["host"]
            if cls._is_suspicious_host(host):
                issues.append({
                    "type": "suspicious_host",
                    "host": host,
                    "score": 35,
                })
                score += 35

        # 2. X-Forwarded-For (IP spoofing)
        if "x-forwarded-for" in headers_lower:
            xff = headers_lower["x-forwarded-for"]
            if not cls._is_valid_ip_list(xff):
                issues.append({
                    "type": "invalid_x_forwarded_for",
                    "value": xff[:100],
                    "score": 30,
                })
                score += 30

        # 3. X-Forwarded-Host
        if "x-forwarded-host" in headers_lower:
            xfh = headers_lower["x-forwarded-host"]
            if cls._is_suspicious_host(xfh):
                issues.append({
                    "type": "suspicious_x_forwarded_host",
                    "value": xfh[:100],
                    "score": 35,
                })
                score += 35

        # 4. User-Agent
        if "user-agent" in headers_lower:
            ua = headers_lower["user-agent"]
            ua_issue = cls._check_user_agent(ua)
            if ua_issue:
                issues.append(ua_issue)
                score += ua_issue["score"]

        # 5. Referer
        if "referer" in headers_lower:
            referer = headers_lower["referer"]
            if cls._is_suspicious_referer(referer):
                issues.append({
                    "type": "suspicious_referer",
                    "value": referer[:100],
                    "score": 25,
                })
                score += 25

        # 6. Content-Type
        if "content-type" in headers_lower:
            content_type = headers_lower["content-type"].split(";")[0].strip().lower()
            if content_type in cls.DANGEROUS_CONTENT_TYPES:
                issues.append({
                    "type": "dangerous_content_type",
                    "value": content_type,
                    "score": 40,
                })
                score += 40

        # 7. Cookie
        if "cookie" in headers_lower:
            cookie = headers_lower["cookie"]
            if len(cookie) > cls.MAX_COOKIE_LENGTH:
                issues.append({
                    "type": "cookie_too_long",
                    "length": len(cookie),
                    "score": 10,
                })
                score += 10

        # 8. Authorization (JWT check)
        if "authorization" in headers_lower:
            auth = headers_lower["authorization"]
            if cls._is_suspicious_auth(auth):
                issues.append({
                    "type": "suspicious_authorization",
                    "score": 45,
                })
                score += 45

        if not issues:
            return None

        return {"issues": issues, "score": score}

    # ─── Individual Checks ─────────────────────────────────

    @staticmethod
    def _is_valid_header_name(name: str) -> bool:
        """بيفحص لو اسم الـ header صح."""
        # RFC 7230: token = 1*tchar
        pattern = r"^[a-zA-Z0-9!#$%&'*+\-.^_`|~]+$"
        return bool(re.match(pattern, name))

    @classmethod
    def _has_injection(cls, value: str) -> bool:
        """بيفحص لو فيه header injection."""
        for pattern in cls.INJECTION_PATTERNS:
            if re.search(pattern, value):
                return True
        return False

    @staticmethod
    def _is_valid_ip_list(value: str) -> bool:
        """بيفحص X-Forwarded-For."""
        ips = [ip.strip() for ip in value.split(",")]
        for ip in ips[:5]:
            if not ip:
                continue
            # IPv4
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                octets = ip.split(".")
                if not all(0 <= int(o) <= 255 for o in octets):
                    return False
            # IPv6 (بسيط)
            elif not re.match(r"^[0-9a-fA-F:]+$", ip):
                return False
        return True

    @staticmethod
    def _is_suspicious_host(host: str) -> bool:
        """بيفحص لو الـ host مشبوه."""
        if not host:
            return True

        hostname = host.split(":")[0].lower()

        suspicious = [
            r"^(localhost|127\.|0\.0\.0\.0)",
            r"\.\.",
            r"[\r\n]",
            r"^[0-9.]+$",
        ]

        for pattern in suspicious:
            if re.search(pattern, hostname):
                return True

        return False

    @classmethod
    def _check_user_agent(cls, ua: str) -> Optional[Dict[str, Any]]:
        """بيفحص الـ User-Agent."""
        if not ua:
            return {
                "type": "empty_user_agent",
                "score": 35,
            }

        if len(ua) > cls.MAX_USER_AGENT_LENGTH:
            return {
                "type": "user_agent_too_long",
                "length": len(ua),
                "score": 15,
            }

        # فحص البوتات
        for pattern in cls.SUSPICIOUS_UA_PATTERNS:
            if re.search(pattern, ua, re.IGNORECASE):
                return {
                    "type": "suspicious_user_agent",
                    "pattern": pattern,
                    "user_agent": ua[:100],
                    "score": 35,
                }

        # فحص التشفير
        if EncodingDetector.is_suspicious(ua, threshold=30):
            return {
                "type": "obfuscated_user_agent",
                "score": 30,
            }

        return None

    @staticmethod
    def _is_suspicious_referer(referer: str) -> bool:
        """بيفحص الـ Referer."""
        if not referer:
            return False

        suspicious = [
            r"//[^/]+",
            r"@",
            r"[\r\n]",
            r"^(javascript|data|vbscript):",
        ]

        for pattern in suspicious:
            if re.search(pattern, referer, re.IGNORECASE):
                return True

        return False

    @classmethod
    def _is_suspicious_auth(cls, auth: str) -> bool:
        """بيفحص الـ Authorization header."""
        if not auth:
            return False

        # JWT check
        if auth.startswith("Bearer "):
            token = auth[7:]
            return AdvancedPatterns.detect_jwt(token)

        # Basic auth — ممكن يكون مشبوه لو فيه أحرف غريبة
        if auth.startswith("Basic "):
            return EncodingDetector.is_suspicious(auth, threshold=40)

        return False

    @staticmethod
    def _get_level(score: int) -> str:
        """بيرجع المستوى."""
        if score == 0:
            return "clean"
        if score < 20:
            return "low"
        if score < 40:
            return "medium"
        if score < 60:
            return "high"
        return "critical"

    @staticmethod
    def _invalid(reason: str) -> Dict[str, Any]:
        """نتيجة فاضية."""
        return {
            "valid": False,
            "score": 0,
            "level": "error",
            "issues": [{"type": reason, "score": 0}],
            "sanitized_headers": {},
        }

    # ─── Specific Header Getters ───────────────────────────

    @staticmethod
    def get_real_ip(headers: Dict[str, str], fallback: str = "unknown") -> str:
        """بيرجع الـ IP الحقيقي من الـ headers."""
        headers_lower = {k.lower(): v for k, v in headers.items()}

        for header in ["x-forwarded-for", "x-real-ip", "cf-connecting-ip"]:
            if header in headers_lower:
                value = headers_lower[header]
                first_ip = value.split(",")[0].strip()
                if first_ip:
                    return first_ip

        return fallback

    @staticmethod
    def get_user_agent(headers: Dict[str, str]) -> str:
        """بيرجع الـ User-Agent."""
        headers_lower = {k.lower(): v for k, v in headers.items()}
        return headers_lower.get("user-agent", "")

    @staticmethod
    def get_content_type(headers: Dict[str, str]) -> str:
        """بيرجع الـ Content-Type (من غير parameters)."""
        headers_lower = {k.lower(): v for k, v in headers.items()}
        ct = headers_lower.get("content-type", "")
        return ct.split(";")[0].strip().lower()

    @staticmethod
    def is_json_request(headers: Dict[str, str]) -> bool:
        """بيفحص لو الطلب JSON."""
        ct = HeaderValidator.get_content_type(headers)
        return "application/json" in ct or "+json" in ct

    @staticmethod
    def is_form_request(headers: Dict[str, str]) -> bool:
        """بيفحص لو الطلب form."""
        ct = HeaderValidator.get_content_type(headers)
        return "application/x-www-form-urlencoded" in ct

    @staticmethod
    def is_multipart_request(headers: Dict[str, str]) -> bool:
        """بيفحص لو الطلب multipart."""
        ct = HeaderValidator.get_content_type(headers)
        return "multipart/form-data" in ct

    # ─── Sanitization ──────────────────────────────────────

    @classmethod
    def sanitize_header_value(cls, value: str) -> str:
        """بينضف قيمة الـ header من الـ injection."""
        if not isinstance(value, str):
            return ""

        value = value.replace("\r", "").replace("\n", "")
        value = value.replace("\x00", "")
        value = value.replace("%0d", "").replace("%0a", "")
        value = value.replace("%0D", "").replace("%0A", "")

        return value


# ─── Singleton ─────────────────────────────────────────────

header_validator = HeaderValidator()