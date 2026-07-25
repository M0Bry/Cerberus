/**
 * DigitalSignatureDialog — PDF Page 13: Digital signature with paste-prevention.
 * "the client to manually type their full legal name... Copying and pasting the name is disabled"
 */

import { useState, useRef, ClipboardEvent } from "react";
import { motion, AnimatePresence } from "framer-motion";

interface DigitalSignatureDialogProps {
  isOpen: boolean;
  onClose: () => void;
  onSign: (signedName: string) => void;
  registeredName: string;
  engagementNumber: string;
  isLoading?: boolean;
}

export default function DigitalSignatureDialog({
  isOpen, onClose, onSign, registeredName, engagementNumber, isLoading,
}: DigitalSignatureDialogProps) {
  const [signedName, setSignedName] = useState("");
  const [error, setError] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);

  const handlePaste = (e: ClipboardEvent) => {
    e.preventDefault();
    setError("Copy-paste is disabled. Please type your full legal name manually.");
  };

  const handleSign = () => {
    if (!signedName.trim()) {
      setError("Please type your full legal name");
      return;
    }
    if (signedName.trim().toLowerCase() !== registeredName.toLowerCase()) {
      setError("The name must match your registered name exactly");
      return;
    }
    setError("");
    onSign(signedName.trim());
  };

  return (
    <AnimatePresence>
      {isOpen && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 z-50 flex items-center justify-center p-4"
        >
          <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />

          <motion.div
            initial={{ scale: 0.9, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.9, opacity: 0 }}
            className="relative bg-cerberus-gray-800 border border-cerberus-gray-700 rounded-2xl p-8 max-w-lg w-full"
          >
            <h3 className="text-xl font-bold text-white mb-2">Digital Signature</h3>
            <p className="text-sm text-gray-400 mb-6">
              By signing below, you authorize Cerberus AI to conduct the security assessment
              defined in engagement <span className="text-cerberus-blue font-mono">{engagementNumber}</span>.
            </p>

            <div className="p-4 bg-cerberus-gray-900 rounded-lg border border-cerberus-gray-600 mb-4">
              <p className="text-xs text-gray-500 mb-1">Registered Name</p>
              <p className="text-white font-medium">{registeredName}</p>
            </div>

            <div className="mb-4">
              <label className="block text-sm text-gray-300 mb-1.5">
                Type your full legal name to sign *
              </label>
              <input
                ref={inputRef}
                type="text"
                value={signedName}
                onChange={(e) => { setSignedName(e.target.value); setError(""); }}
                onPaste={handlePaste}
                onCopy={(e) => e.preventDefault()}
                onCut={(e) => e.preventDefault()}
                placeholder="Type your full legal name"
                className="cyber-input"
                autoComplete="off"
              />
              {error && <p className="mt-1 text-xs text-red-400">{error}</p>}
            </div>

            <div className="p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg mb-6">
              <p className="text-xs text-yellow-400">
                ⚠️ Copy-paste is disabled to ensure this is a deliberate action.
                Your signature includes a cryptographic hash, timestamp, and engagement ID.
              </p>
            </div>

            <div className="flex gap-3">
              <button onClick={onClose} className="flex-1 px-4 py-3 border border-cerberus-gray-600 rounded-lg text-gray-300 hover:border-gray-500 transition-colors">
                Cancel
              </button>
              <button
                onClick={handleSign}
                disabled={isLoading || !signedName.trim()}
                className="flex-1 btn-glow text-center disabled:opacity-50"
              >
                {isLoading ? "Signing..." : "Accept and Sign"}
              </button>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
