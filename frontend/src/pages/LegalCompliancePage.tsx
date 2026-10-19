/**
 * Compliance / Acceptable Use Page (public) — restyled to the new front-end
 * identity.
 */
import LegalShell from "../components/landing/LegalShell";

const H: React.CSSProperties = {
  fontFamily: "var(--font-display)",
  fontSize: "1.05rem",
  letterSpacing: "1px",
  textTransform: "uppercase",
  color: "var(--accent)",
  marginBottom: 6,
};

export default function LegalCompliancePage() {
  return (
    <LegalShell label="Legal" title="Compliance & Acceptable Use" intro="Ethical hacking principles, compliance frameworks and the legal guardrails of every engagement.">
      <div style={{ display: "grid", gap: 22 }}>
        <section>
          <h2 style={H}>Ethical Hacking Principles</h2>
          <p>Cerberus AI operates strictly within ethical hacking principles. All penetration testing is non-destructive, authorized, and evidence-based. We never access systems without explicit written permission.</p>
        </section>
        <section>
          <h2 style={H}>Compliance Frameworks</h2>
          <p>Our platform maps findings to GDPR, CCPA, ISO 27001, PCI-DSS, and SOC 2 frameworks. Reports include compliance references for each finding.</p>
        </section>
        <section>
          <h2 style={H}>Legal Framework</h2>
          <p>Every engagement requires a digitally signed Rules of Engagement document. This legal agreement defines authorized scope, prohibited actions, and liability limitations.</p>
        </section>
        <section>
          <h2 style={H}>Data Handling</h2>
          <p>All sensitive data is encrypted at rest (AES-256-GCM) and in transit (TLS 1.3). Engagement data is automatically purged after completion. We maintain immutable audit logs for forensic integrity.</p>
        </section>
      </div>
    </LegalShell>
  );
}
