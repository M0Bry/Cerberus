/** ScopeForm — Scope input form (domains, IPs, assets, out-of-scope). */
import { useState } from "react";
import TextArea from "../ui/TextArea";
import Button from "../ui/Button";

interface ScopeFormData {
  domains: string;
  ips: string;
  out_of_scope: string;
}

interface ScopeFormProps {
  onSubmit: (data: ScopeFormData) => void;
  initialData?: Partial<ScopeFormData>;
}

export default function ScopeForm({ onSubmit, initialData }: ScopeFormProps) {
  const [domains, setDomains] = useState(initialData?.domains ?? "");
  const [ips, setIps] = useState(initialData?.ips ?? "");
  const [outOfScope, setOutOfScope] = useState(initialData?.out_of_scope ?? "");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit({ domains, ips, out_of_scope: outOfScope });
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <TextArea
        label="In-Scope Domains"
        value={domains}
        onChange={(e) => setDomains(e.target.value)}
        placeholder="example.com&#10;api.example.com"
      />
      <TextArea
        label="In-Scope IP Addresses"
        value={ips}
        onChange={(e) => setIps(e.target.value)}
        placeholder="192.168.1.0/24&#10;10.0.0.0/8"
      />
      <TextArea
        label="Out-of-Scope Items"
        value={outOfScope}
        onChange={(e) => setOutOfScope(e.target.value)}
        placeholder="payment.example.com&#10;third-party-service.com"
      />
      <Button type="submit" className="w-full">
        Save Scope
      </Button>
    </form>
  );
}
