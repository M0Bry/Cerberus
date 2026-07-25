/** RegisterForm — Registration form with all PDF-required fields. */
import { useState } from "react";
import Input from "../ui/Input";
import PasswordInput from "../ui/PasswordInput";
import FileUpload from "../ui/FileUpload";
import Button from "../ui/Button";
import FormField from "./FormField";

interface RegisterFormProps { onSubmit: (data: any) => void; isLoading?: boolean; error?: string; }
export default function RegisterForm({ onSubmit, isLoading, error }: RegisterFormProps) {
  const [form, setForm] = useState({ full_name: "", company_name: "", job_title: "", email: "", phone_number: "", company_location: "", password: "", confirm_password: "" });
  const [logo, setLogo] = useState<File | null>(null);
  const update = (k: string, v: string) => setForm((p) => ({ ...p, [k]: v }));
  return (
    <form onSubmit={(e) => { e.preventDefault(); onSubmit({ ...form, logo }); }} className="space-y-4">
      {error && <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">{error}</div>}
      <div className="grid grid-cols-2 gap-4">
        <FormField label="Full Name" required><Input value={form.full_name} onChange={(e) => update("full_name", e.target.value)} required /></FormField>
        <FormField label="Job Title" required><Input value={form.job_title} onChange={(e) => update("job_title", e.target.value)} required /></FormField>
      </div>
      <FormField label="Company Name" required><Input value={form.company_name} onChange={(e) => update("company_name", e.target.value)} required /></FormField>
      <FormField label="Corporate Email" required><Input type="email" value={form.email} onChange={(e) => update("email", e.target.value)} required /></FormField>
      <div className="grid grid-cols-2 gap-4">
        <FormField label="Phone Number"><Input type="tel" value={form.phone_number} onChange={(e) => update("phone_number", e.target.value)} /></FormField>
        <FormField label="Company Location"><Input value={form.company_location} onChange={(e) => update("company_location", e.target.value)} /></FormField>
      </div>
      <FormField label="Company Logo / Profile Image" hint="Optional. Used to personalize future reports."><FileUpload onFileSelect={setLogo} accept=".png,.jpg,.jpeg,.svg" maxSizeMB={5} /></FormField>
      <div className="grid grid-cols-2 gap-4">
        <FormField label="Password" required><PasswordInput value={form.password} onChange={(e) => update("password", e.target.value)} required /></FormField>
        <FormField label="Confirm Password" required><PasswordInput value={form.confirm_password} onChange={(e) => update("confirm_password", e.target.value)} required /></FormField>
      </div>
      <Button type="submit" loading={isLoading} className="w-full">Create Account</Button>
    </form>
  );
}
