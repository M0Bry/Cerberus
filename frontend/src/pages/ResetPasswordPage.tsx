/** ResetPasswordPage — Reset password (future). */
import AuthLayout from "../components/layout/AuthLayout";
import PasswordInput from "../components/ui/PasswordInput";
import Button from "../components/ui/Button";

export default function ResetPasswordPage() {
  return (
    <AuthLayout>
      {/* Titles and subtitles are placed as children, since AuthLayout
          currently doesn’t accept `title`/`subtitle` props. */}
      <div className="cyber-card space-y-4">
        <h2 className="text-2xl font-bold text-white">Reset Password</h2>
        <p className="text-gray-400 mb-4">Enter your new password.</p>
        <PasswordInput label="New Password" />
        <PasswordInput label="Confirm New Password" />
        <Button className="w-full">Reset Password</Button>
      </div>
    </AuthLayout>
  );
}
