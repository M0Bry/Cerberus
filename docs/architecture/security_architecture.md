# Security Architecture

## Three-Tier Defense
1. **Tier 1 — Gateway**: WAF rules, signature detection, rate limiting
2. **Tier 2 — Behavioral**: Session monitoring, baseline comparison, risk scoring
3. **Tier 3 — Generative AI**: Virtual patches, dynamic firewall, automated alerts

## Encryption
- Passwords: Argon2id with unique salts
- Data at rest: AES-256-GCM field-level encryption
- Data in transit: TLS 1.3
- Audit logs: SHA-256 chain + HMAC signatures

## Access Control
- JWT with refresh token rotation
- RBAC with 5 roles and granular permissions
- MFA support
- Session tracking with device fingerprinting
