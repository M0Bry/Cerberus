/**
 * Privacy Policy Page (Public).
 */

import Navbar from "../components/layout/Navbar";
import Footer from "../components/layout/Footer";

export default function PrivacyPolicyPage() {
  return (
    <div className="min-h-screen bg-cerberus-dark">
      <Navbar />
      <div className="pt-24 pb-16 px-4 max-w-4xl mx-auto">
        <h1 className="text-4xl font-bold text-white mb-8">Privacy Policy</h1>
        <div className="cyber-card space-y-6 text-gray-300 text-sm leading-relaxed">
          <section><h2 className="text-lg text-white font-semibold mb-2">1. Data We Collect</h2><p>We collect personal information (name, email, company), security assessment data, IP addresses, browser fingerprints, and usage analytics to provide and improve our cybersecurity platform.</p></section>
          <section><h2 className="text-lg text-white font-semibold mb-2">2. How We Use Your Data</h2><p>Your data is used exclusively for providing penetration testing services, generating security reports, platform security, and compliance with legal obligations.</p></section>
          <section><h2 className="text-lg text-white font-semibold mb-2">3. Data Protection</h2><p>All sensitive data is encrypted using AES-256-GCM at rest and TLS 1.3 in transit. Passwords are hashed with Argon2id. We implement field-level encryption for PII.</p></section>
          <section><h2 className="text-lg text-white font-semibold mb-2">4. Your Rights (GDPR)</h2><p>You have the right to access, rectify, erase, restrict processing, port your data, and object to processing. Contact us at privacy@cerberus-ai.com.</p></section>
          <section><h2 className="text-lg text-white font-semibold mb-2">5. Data Retention</h2><p>Engagement data is retained for the duration of the engagement plus 30 days. Audit logs are retained for 12 months. You may request earlier deletion.</p></section>
        </div>
      </div>
      <Footer />
    </div>
  );
}
