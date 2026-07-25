/** 503 Maintenance Page */
export default function MaintenancePage() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-cerberus-dark">
      <div className="text-center">
        <span className="text-6xl">🔧</span>
        <h1 className="text-4xl font-bold text-cerberus-yellow mt-4">Under Maintenance</h1>
        <p className="text-gray-400 mt-4 max-w-md mx-auto">
          Cerberus AI is undergoing scheduled maintenance. We'll be back shortly.
        </p>
        <p className="text-sm text-gray-600 mt-8">Expected completion: Check our status page for updates.</p>
      </div>
    </div>
  );
}
