# PCI-DSS Mapping

| PCI-DSS Requirement | Cerberus Implementation |
|---|---|
| 1. Firewall Configuration | Nginx reverse proxy + WAF rules |
| 2. Default Passwords | Forced password change on first login |
| 3. Protect Stored Data | AES-256-GCM field-level encryption |
| 4. Encrypt Transmission | TLS 1.3 for all communications |
| 5. Anti-virus | File upload scanning (ClamAV) |
| 6. Secure Systems | Regular dependency scanning + updates |
| 7. Restrict Access | RBAC with least privilege |
| 8. Authenticate Access | JWT + MFA support |
| 9. Physical Access | Cloud infrastructure provider managed |
| 10. Track Access | Immutable audit log chain |
| 11. Test Security | Automated penetration testing |
| 12. Security Policy | Published security policies |
