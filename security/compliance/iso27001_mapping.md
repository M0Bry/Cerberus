# ISO 27001 Mapping — Cerberus AI

| ISO 27001 Control | Cerberus AI Implementation |
|---|---|
| A.5.1 Policies for information security | `/security/policies/` directory |
| A.6.1 Internal organization | RBAC with 5 roles + permission matrix |
| A.8.1 Asset management | Engagement-scoped asset inventory |
| A.9.1 Access control | JWT + RBAC + MFA support |
| A.9.2 User access management | Registration → Verification → Login flow |
| A.9.4 System access restriction | Rate limiting + IP blocking + abuse detection |
| A.10.1 Cryptographic controls | AES-256-GCM + Argon2id + HMAC-SHA256 |
| A.12.1 Operational procedures | Automated workflows + audit logging |
| A.12.4 Logging and monitoring | Immutable log chain + Prometheus + Grafana |
| A.12.6 Technical vulnerability management | Automated OSINT + Red Team + Risk Assessment |
| A.14.1 Security in development | Input validation + CSRF + XSS prevention |
| A.14.2 Security in development support | CI/CD security scans (CodeQL, dependency scan) |
| A.16.1 Incident management | Three-tier defense + automated alerting |
| A.17.1 Information security continuity | Database backups + health monitoring |
| A.18.1 Compliance | GDPR, CCPA, PCI-DSS checklists |
