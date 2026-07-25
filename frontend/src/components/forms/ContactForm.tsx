/** ContactForm — Contact form for landing page. */
import { useState } from "react";
import Input from "../ui/Input";
import TextArea from "../ui/TextArea";
import Button from "../ui/Button";
export default function ContactForm({ onSubmit }: { onSubmit?: (data: any) => void }) {
  const [form, setForm] = useState({ name: "", email: "", subject: "", message: "" });
  const update = (k: string, v: string) => setForm((p) => ({ ...p, [k]: v }));
  return (
    <form onSubmit={(e) => { e.preventDefault(); onSubmit?.(form); }} className="space-y-4">
      <div className="grid grid-cols-2 gap-4">
        <Input label="Name" value={form.name} onChange={(e) => update("name", e.target.value)} required />
        <Input label="Email" type="email" value={form.email} onChange={(e) => update("email", e.target.value)} required />
      </div>
      <Input label="Subject" value={form.subject} onChange={(e) => update("subject", e.target.value)} required />
      <TextArea label="Message" value={form.message} onChange={(e) => update("message", e.target.value)} required />
      <Button type="submit" className="w-full">Send Message</Button>
    </form>
  );
}
