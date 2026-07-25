/**
 * Terms of Service Page (Public).
 */

import Navbar from "../components/layout/Navbar";
import Footer from "../components/layout/Footer";

export default function TermsOfServicePage() {
  return (
    <div className="min-h-screen bg-cerberus-dark">
      <Navbar />
      <div className="pt-24 pb-16 px-4 max-w-4xl mx-auto">
        <h1 className="text-4xl font-bold text-white mb-8">Terms of Service</h1>
        <div className="cyber-card space-y-6 text-gray-300 text-sm leading-relaxed">
          <section><h2 className="text-lg text-white font-semibold mb-2">1. Acceptance</h2><p>By using Cerberus AI, you agree to these terms and our Privacy Policy. You must be at least 18 years old and authorized to act on behalf of your organization.</p></section>
          <section><h2 className="text-lg text-white font-semibold mb-2">2. Service Description</h2><p>Cerberus AI provides AI-assisted penetration testing and security assessment services. All testing is non-destructive and conducted within authorized scope.</p></section>
          <section><h2 className="text-lg text-white font-semibold mb-2">3. User Obligations</h2><p>You must provide accurate information, authorize only systems you own or have permission to test, and comply with all applicable laws.</p></section>
          <section><h2 className="text-lg text-white font-semibold mb-2">4. Limitation of Liability</h2><p>Cerberus AI operates as a security assessment tool. We are not liable for indirect damages. All activities are conducted within authorized scope using controlled techniques.</p></section>
        </div>
      </div>
      <Footer />
    </div>
  );
}
