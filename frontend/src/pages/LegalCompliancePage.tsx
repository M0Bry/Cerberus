/**
 * Legal & Compliance Page (Public).
 */

import Navbar from "../components/layout/Navbar";
import Footer from "../components/layout/Footer";

export default function LegalCompliancePage() {
  return (
    <div className="min-h-screen bg-cerberus-dark">
      <Navbar />
      <div className="pt-24 pb-16 px-4 max-w-4xl mx-auto">
        <h1 className="text-4xl font-bold text-white mb-8">Legal & Ethical Compliance</h1>
        <div className="cyber-card space-y-6 text-gray-300 text-sm leading-relaxed">
          <section><h2 className="text-lg text-white font-semibold mb-2">🛡️ Ethical Hacking Principles</h2><p>Cerberus AI operates strictly within ethical hacking principles. All penetration testing is non-destructive, authorized, and evidence-based. We never access systems without explicit written permission.</p></section>
          <section><h2 className="text-lg text-white font-semibold mb-2">📋 Compliance Frameworks</h2><p>Our platform maps findings to GDPR, CCPA, ISO 27001, PCI-DSS, and SOC 2 frameworks. Reports include compliance references for each finding.</p></section>
          <section><h2 className="text-lg text-white font-semibold mb-2">⚖️ Legal Framework</h2><p>Every engagement requires a digitally signed Rules of Engagement document. This legal agreement defines authorized scope, prohibited actions, and liability limitations.</p></section>
          <section><h2 className="text-lg text-white font-semibold mb-2">🔒 Data Handling</h2><p>All sensitive data is encrypted at rest (AES-256-GCM) and in transit (TLS 1.3). Engagement data is automatically purged after completion. We maintain immutable audit logs for forensic integrity.</p></section>
        </div>
      </div>
      <Footer />
    </div>
  );
}
