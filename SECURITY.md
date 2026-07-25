# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities to **security@cerberus-ai.com**.

We take security seriously and will respond to all reports within 24 hours.

## Security Measures

Cerberus AI implements defense-in-depth:

- **Encryption**: AES-256-GCM at rest, TLS 1.3 in transit
- **Authentication**: JWT with refresh token rotation, OTP verification
- **Authorization**: RBAC with 5 roles and granular permissions
- **Input Validation**: SQLi, XSS, Command Injection, Path Traversal prevention
- **Audit Logging**: Immutable log chain with SHA-256 + HMAC signatures
- **Rate Limiting**: Per-IP, per-user, per-endpoint
- **Auto-Defense**: Three-tier security architecture
- **Monitoring**: Real-time alerts with Prometheus + Grafana

## Compliance

- GDPR compliant
- CCPA compliant
- ISO 27001 mapped
- PCI-DSS mapped
