/** ForgotPasswordPage — Request password reset. */
import AuthLayout from "../components/layout/AuthLayout";
import Button from "../components/ui/Button";

export default function ForgotPasswordPage() {
  return (
    <AuthLayout>
      <div className="text-center space-y-4">
        <h2 className="text-3xl font-bold text-white">Forgot Password</h2>
        <p className="text-gray-400">Enter your email to receive a reset link.</p>
        <div className="cyber-card">
          <input
            type="email"
            placeholder="you@example.com"
            className="w-full p-3 bg-gray-800 border border-gray-700 rounded text-white mb-4"
          />
          <Button className="w-full">Send Reset Link</Button>
        </div>
      </div>
    </AuthLayout>
  );
}
