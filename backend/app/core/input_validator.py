"""
Input Validator — Sanitizes all user input against injection attacks.
"""

import html
import re

# ─── Attack Patterns ──────────────────────────────────────────
_SQLI_PATTERNS = [
    r"(\bunion\b.*\bselect\b)", r"(\bselect\b.*\bfrom\b.*\bwhere\b)",
    r"(;?\s*drop\s+table)", r"(--\s*$)", r"('\s*or\s+'1'\s*=\s*'1)",
    r"(\bexec\b.*\b)", r"(0x[0-9a-f]+)",
]
_XSS_PATTERNS = [
    r"(<script[^>]*>)", r"(javascript\s*:)", r"(on\w+\s*=)",
    r"(<iframe)", r"(<object)", r"(<embed)", r"(<svg[^>]*onload)",
]
_CMDI_PATTERNS = [
    r"(;\s*(ls|cat|whoami|id|pwd|rm|wget|curl)\b)",
    r"(\|\s*(ls|cat|whoami|id|pwd)\b)", r"(`[^`]*`)", r"(\$\([^)]*\))",
]
_PATH_TRAVERSAL = [
    r"(\.\./)", r"(\.\.\\)", r"(%2e%2e%2f)", r"(%2e%2e/)",
    r"(/etc/passwd)", r"(/etc/shadow)", r"(c:\\windows)",
]


def sanitize_string(value: str, max_length: int = 10000) -> str:
    """Sanitize a general string input."""
    value = value.strip()[:max_length]
    value = html.escape(value)
    return value


def detect_sql_injection(value: str) -> bool:
    lower = value.lower()
    return any(re.search(p, lower, re.IGNORECASE) for p in _SQLI_PATTERNS)


def detect_xss(value: str) -> bool:
    return any(re.search(p, value, re.IGNORECASE) for p in _XSS_PATTERNS)


def detect_command_injection(value: str) -> bool:
    return any(re.search(p, value, re.IGNORECASE) for p in _CMDI_PATTERNS)


def detect_path_traversal(value: str) -> bool:
    return any(re.search(p, value, re.IGNORECASE) for p in _PATH_TRAVERSAL)


def validate_input(value: str, field_name: str = "input") -> str:
    """
    Comprehensive input validation. Raises ValueError on attack detection.
    """
    if detect_sql_injection(value):
        raise ValueError(f"SQL Injection detected in '{field_name}'")
    if detect_xss(value):
        raise ValueError(f"XSS attempt detected in '{field_name}'")
    if detect_command_injection(value):
        raise ValueError(f"Command Injection detected in '{field_name}'")
    if detect_path_traversal(value):
        raise ValueError(f"Path Traversal detected in '{field_name}'")
    return sanitize_string(value)


def validate_email(email: str) -> bool:
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def validate_domain(domain: str) -> bool:
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
    return bool(re.match(pattern, domain))


def validate_ip(ip: str) -> bool:
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    return all(0 <= int(octet) <= 255 for octet in ip.split('.'))
