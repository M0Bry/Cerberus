/** FormField — Wrapper for label + input + error message. */
import { ReactNode } from "react";
interface FormFieldProps { label?: string; error?: string; hint?: string; children: ReactNode; required?: boolean; }
export default function FormField({ label, error, hint, children, required }: FormFieldProps) {
  return (
    <div className="w-full">
      {label && <label className="block text-sm text-gray-300 mb-1.5 font-medium">{label}{required && <span className="text-red-400 ml-1">*</span>}</label>}
      {children}
      {error && <p className="mt-1 text-xs text-red-400">{error}</p>}
      {hint && !error && <p className="mt-1 text-xs text-gray-500">{hint}</p>}
    </div>
  );
}
