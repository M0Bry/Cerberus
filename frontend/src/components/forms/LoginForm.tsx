/** LoginForm — Login form with email + password + remember me. */
import { useState } from "react";
import Input from "../ui/Input";
import PasswordInput from "../ui/PasswordInput";
import Button from "../ui/Button";
interface LoginFormProps { onSubmit: (data: { email: string; password: string; remember_me: boolean }) => void; isLoading?: boolean; error?: string; }
export default function LoginForm({ onSubmit, isLoading, error }: LoginFormProps) {
  const [email, setEmail] = useState(""); const [password, setPassword] = useState(""); const [remember, setRemember] = useState(false);
  return (
    <form onSubmit={(e) => { e.preventDefault(); onSubmit({ email, password, remember_me: remember }); }} className="space-y-4">
      {error && <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">{error}</div>}
      <Input label="Email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="your@company.com" required />
      <PasswordInput label="Password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="••••••••" required />
      <label className="flex items-center gap-2 text-sm text-gray-400"><input type="checkbox" checked={remember} onChange={(e) => setRemember(e.target.checked)} className="rounded" />Remember me</label>
      <Button type="submit" loading={isLoading} className="w-full">Sign In</Button>
    </form>
  );
}
