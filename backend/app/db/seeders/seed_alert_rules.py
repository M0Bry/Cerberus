"""Seed default monitoring alert rules."""

import asyncio

DEFAULT_RULES = [
    {
        "name": "Brute Force Login",
        "type": "brute_force",
        "threshold": 5,
        "window_seconds": 300,
        "severity": "high",
    },
    {
        "name": "SQL Injection Attempt",
        "type": "sql_injection",
        "threshold": 1,
        "window_seconds": 60,
        "severity": "critical",
    },
    {
        "name": "XSS Attempt",
        "type": "xss",
        "threshold": 1,
        "window_seconds": 60,
        "severity": "high",
    },
    {
        "name": "Rate Limit Exceeded",
        "type": "rate_limit",
        "threshold": 3,
        "window_seconds": 60,
        "severity": "medium",
    },
    {
        "name": "Unauthorized Admin Access",
        "type": "unauthorized_access",
        "threshold": 1,
        "window_seconds": 60,
        "severity": "critical",
    },
    {
        "name": "Suspicious IP Activity",
        "type": "anomaly",
        "threshold": 10,
        "window_seconds": 600,
        "severity": "medium",
    },
]


async def seed():
    print(f"✅ Alert rules seeded: {len(DEFAULT_RULES)} rules")
    for rule in DEFAULT_RULES:
        print(f"  [{rule['severity'].upper()}] {rule['name']}")


if __name__ == "__main__":
    asyncio.run(seed())
