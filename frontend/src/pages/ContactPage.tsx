/**
 * Contact Page (Public).
 */

import { useState } from "react";
import Navbar from "../components/layout/Navbar";
import Footer from "../components/layout/Footer";

export default function ContactPage() {
  const [form, setForm] = useState({ name: "", email: "", subject: "", message: "" });

  return (
    <div className="min-h-screen bg-cerberus-dark">
      <Navbar />
      <div className="pt-24 pb-16 px-4 max-w-2xl mx-auto">
        <h1 className="text-4xl font-bold text-white mb-4">Contact Us</h1>
        <p className="text-gray-400 mb-8">Have questions about Cerberus AI? Reach out and we'll get back to you within 24 hours.</p>
        <form className="cyber-card space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div><label className="text-sm text-gray-300 mb-1 block">Name</label><input className="cyber-input" value={form.name} onChange={e => setForm({...form, name: e.target.value})} /></div>
            <div><label className="text-sm text-gray-300 mb-1 block">Email</label><input type="email" className="cyber-input" value={form.email} onChange={e => setForm({...form, email: e.target.value})} /></div>
          </div>
          <div><label className="text-sm text-gray-300 mb-1 block">Subject</label><input className="cyber-input" value={form.subject} onChange={e => setForm({...form, subject: e.target.value})} /></div>
          <div><label className="text-sm text-gray-300 mb-1 block">Message</label><textarea className="cyber-input min-h-[120px]" value={form.message} onChange={e => setForm({...form, message: e.target.value})} /></div>
          <button type="submit" className="btn-glow w-full text-center">Send Message</button>
        </form>
      </div>
      <Footer />
    </div>
  );
}
