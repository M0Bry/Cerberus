/** TestimonialsSection — Client testimonials (optional). */
export default function TestimonialsSection() {
  return (
    <section className="py-24 px-4 bg-cerberus-gray-900/50">
      <div className="max-w-4xl mx-auto text-center">
        <h2 className="text-3xl font-bold mb-16"><span className="text-gradient">Trusted by Security Teams</span></h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {[{ quote: "Cerberus AI transformed our security assessment process.", name: "CISO, FinTech Corp" }, { quote: "The AI-guided approach saved us weeks of manual work.", name: "Security Lead, TechCo" }, { quote: "Professional reports that executives actually understand.", name: "CTO, HealthSys" }].map((t) => (
            <div key={t.name} className="cyber-card text-left">
              <p className="text-sm text-gray-300 mb-4">"{t.quote}"</p>
              <p className="text-xs text-cerberus-blue font-medium">— {t.name}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
