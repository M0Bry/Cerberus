/**
 * Terms of Service Page (public) — restyled to the new front-end identity.
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

export default function TermsOfServicePage() {
  return (
    <LegalShell label="Legal" title="Terms of Service" intro="The rules that govern your use of the Cerberus AI platform.">
      <div style={{ display: "grid", gap: 22 }}>
        <section>
          <h2 style={H}>1. Acceptance</h2>
          <p>By using Cerberus AI, you agree to these terms and our Privacy Policy. You must be at least 18 years old and authorized to act on behalf of your organization.</p>
        </section>
        <section>
          <h2 style={H}>2. Service Description</h2>
          <p>Cerberus AI provides AI-assisted penetration testing and security assessment services. All testing is non-destructive and conducted within authorized scope.</p>
        </section>
        <section>
          <h2 style={H}>3. User Obligations</h2>
          <p>You must provide accurate information, authorize only systems you own or have permission to test, and comply with all applicable laws.</p>
        </section>
        <section>
          <h2 style={H}>4. Limitation of Liability</h2>
          <p>Cerberus AI operates as a security assessment tool. We are not liable for indirect damages. All activities are conducted within authorized scope using controlled techniques.</p>
        </section>
      </div>
    </LegalShell>
  );
}
