/** ProfileForm — Edit profile form. */
import { useState } from "react";
import Input from "../ui/Input";
import Button from "../ui/Button";
interface ProfileFormProps { initialData?: any; onSubmit: (data: any) => void; isLoading?: boolean; }
export default function ProfileForm({ initialData, onSubmit, isLoading }: ProfileFormProps) {
  const [form, setForm] = useState(initialData || { full_name: "", company_name: "", job_title: "", phone_number: "", company_location: "" });
  const update = (k: string, v: string) => setForm((p: any) => ({ ...p, [k]: v }));
  return (
    <form onSubmit={(e) => { e.preventDefault(); onSubmit(form); }} className="space-y-4">
      <Input label="Full Name" value={form.full_name} onChange={(e) => update("full_name", e.target.value)} />
      <Input label="Company Name" value={form.company_name} onChange={(e) => update("company_name", e.target.value)} />
      <Input label="Job Title" value={form.job_title} onChange={(e) => update("job_title", e.target.value)} />
      <Input label="Phone Number" value={form.phone_number} onChange={(e) => update("phone_number", e.target.value)} />
      <Input label="Company Location" value={form.company_location} onChange={(e) => update("company_location", e.target.value)} />
      <Button type="submit" loading={isLoading}>Save Changes</Button>
    </form>
  );
}
