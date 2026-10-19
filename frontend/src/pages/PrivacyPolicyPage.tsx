/**
 * Privacy Policy Page (public) — restyled to the new front-end identity.
 */
import LegalShell from "../components/landing/LegalShell";

export default function PrivacyPolicyPage() {
  return (
    <LegalShell label="Legal" title="Privacy Policy" intro="Effective January 2026. How Cerberus AI collects, uses and protects your data.">
      <div style={{ display: "grid", gap: 22 }}>
        <section>
          <h2 style={{ fontFamily: "var(--font-display)", fontSize: "1.05rem", letterSpacing: "1px", textTransform: "uppercase", color: "var(--accent)", marginBottom: 6 }}>1. Data We Collect</h2>
          <p>We collect personal information (name, email, company), security assessment data, IP addresses, browser fingerprints, and usage analytics to provide and improve our cybersecurity platform.</p>
        </section>
        <section>
          <h2 style={{ fontFamily: "var(--font-display)", fontSize: "1.05rem", letterSpacing: "1px", textTransform: "uppercase", color: "var(--accent)", marginBottom: 6 }}>2. How We Use Your Data</h2>
          <p>Your data is used exclusively for providing penetration testing services, generating security reports, platform security, and compliance with legal obligations.</p>
        </section>
        <section>
          <h2 style={{ fontFamily: "var(--font-display)", fontSize: "1.05rem", letterSpacing: "1px", textTransform: "uppercase", color: "var(--accent)", marginBottom: 6 }}>3. Data Protection</h2>
          <p>All sensitive data is encrypted using AES-256-GCM at rest and TLS 1.3 in transit. Passwords are hashed with Argon2id. We implement field-level encryption for PII.</p>
        </section>
        <section>
          <h2 style={{ fontFamily: "var(--font-display)", fontSize: "1.05rem", letterSpacing: "1px", textTransform: "uppercase", color: "var(--accent)", marginBottom: 6 }}>4. Your Rights (GDPR)</h2>
          <p>You have the right to access, rectify, erase, restrict processing, port your data, and object to processing. Contact us at privacy@cerberus-ai.security.</p>
        </section>
        <section>
          <h2 style={{ fontFamily: "var(--font-display)", fontSize: "1.05rem", letterSpacing: "1px", textTransform: "uppercase", color: "var(--accent)", marginBottom: 6 }}>5. Data Retention</h2>
          <p>Engagement data is retained for the duration of the engagement plus 30 days. Audit logs are retained for 12 months. You may request earlier deletion.</p>
        </section>
      </div>
    </LegalShell>
  );
}
