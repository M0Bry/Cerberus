# GDPR Compliance Checklist — Cerberus AI

## Data Processing Principles

- [x] **Lawful basis** — Explicit consent for data processing
- [x] **Purpose limitation** — Data collected only for security assessment purposes
- [x] **Data minimization** — Collect only necessary information
- [x] **Accuracy** — Users can update their data at any time
- [x] **Storage limitation** — Data retention policies enforced
- [x] **Integrity & Confidentiality** — AES-256-GCM encryption at rest, TLS in transit

## User Rights

- [x] **Right to access** — Users can export their data
- [x] **Right to rectification** — Users can edit their profile
- [x] **Right to erasure** — Account deletion removes personal data
- [x] **Right to restrict processing** — Users can disable features
- [x] **Right to data portability** — JSON/CSV export available
- [x] **Right to object** — Users can opt out of non-essential processing

## Technical Measures

- [x] Field-level encryption for PII (email, phone, company data)
- [x] One-way password hashing (Argon2id)
- [x] Automatic data purging after engagement completion
- [x] Audit logging of all data access
- [x] Immutable log chain for forensic integrity
- [x] IP logging with consent disclosure

## Data Processing Agreement

- [x] DPA available for all clients
- [x] Sub-processor list maintained and disclosed
- [x] Cross-border transfer safeguards (SCCs where applicable)
