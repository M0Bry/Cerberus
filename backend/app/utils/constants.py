"""Constants — roles, statuses, severities, phases, alert types."""

ROLES = [
    "super_admin",
    "admin",
    "pentester",
    "client",
    "viewer",
]

ENGAGEMENT_STATUSES = [
    "draft",
    "intake",
    "scope_pending",
    "scope_confirmed",
    "osint",
    "red_team",
    "risk_assessment",
    "reporting",
    "completed",
    "cancelled",
]

SEVERITY_LEVELS = [
    "critical",
    "high",
    "medium",
    "low",
    "info",
]

OSINT_TASK_TYPES = [
    "domain_enum",
    "email_harvest",
    "social_recon",
    "subdomain_enum",
    "whois_lookup",
    "dns_enum",
    "public_records",
    "asset_discovery",
]

ALERT_TYPES = [
    "anomaly",
    "brute_force",
    "intrusion",
    "exploit_attempt",
    "data_exfiltration",
    "policy_violation",
]
