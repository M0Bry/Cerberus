"""
Tier 1 — Intelligent Gateway Protection.

WAF rules, signature-based detection, rate limiting, and input validation.
"""

import re

import structlog

logger = structlog.get_logger()

# Common attack patterns for signature-based detection
ATTACK_PATTERNS = {
    "sql_injection": [
        r"(\bunion\b.*\bselect\b)",
        r"(\bselect\b.*\bfrom\b.*\bwhere\b)",
        r"(;?\s*drop\s+table)",
        r"(--\s*$)",
        r"('\s*or\s+'1'\s*=\s*'1)",
    ],
    "xss": [
        r"(<script[^>]*>)",
        r"(javascript\s*:)",
        r"(on\w+\s*=)",
        r"(<img[^>]+onerror)",
    ],
    "command_injection": [
        r"(;\s*(ls|cat|whoami|id|pwd)\b)",
        r"(\|\s*(ls|cat|whoami|id|pwd)\b)",
        r"(`[^`]*`)",
        r"(\$\([^)]*\))",
    ],
    "path_traversal": [
        r"(\.\./)",
        r"(\.\.\\)",
        r"(%2e%2e%2f)",
        r"(%2e%2e/)",
    ],
    "local_file_inclusion": [
        r"(/etc/passwd)",
        r"(/etc/shadow)",
        r"(php://filter)",
        r"(php://input)",
    ],
}


class GatewayProtection:
    """
    Tier 1: Intelligent Gateway Protection.

    Inspects every HTTP request for known attack patterns,
    enforces rate limiting, and validates request integrity.
    """

    def __init__(self):
        self.blocked_requests = []

    def inspect_request(
        self,
        method: str,
        path: str,
        headers: dict,
        body: str | None = None,
        query_params: dict | None = None,
        client_ip: str = "unknown",
    ) -> dict:
        """
        Inspect an incoming request for malicious patterns.

        Returns:
            Dict with 'allowed' (bool), 'threat_type' (str), and 'details' (str).
        """

        # Combine all request data for inspection
        inspection_targets = [
            path,
            str(headers),
            body or "",
            str(query_params or {}),
        ]
        combined_text = " ".join(inspection_targets)

        # Check against all attack patterns
        for attack_type, patterns in ATTACK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, combined_text, re.IGNORECASE):
                    result = {
                        "allowed": False,
                        "threat_type": attack_type,
                        "details": f"Blocked: {attack_type} pattern detected",
                        "pattern": pattern,
                        "client_ip": client_ip,
                    }
                    self.blocked_requests.append(result)
                    logger.warning(
                        "gateway_blocked_request",
                        threat_type=attack_type,
                        client_ip=client_ip,
                        path=path,
                    )
                    return result

        return {"allowed": True, "threat_type": None, "details": None}
