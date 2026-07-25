/**
 * InitializationProgress — Displays initialization steps with animated progress.
 * PDF Page 15: "Initializing AI Analysis Engine... Loading Client Profile...
 * Verifying Scope of Engagement... Building Internal Knowledge Graph..."
 */

import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";

const INIT_STEPS = [
  "Initializing AI Analysis Engine...",
  "Loading Client Profile...",
  "Verifying Scope of Engagement...",
  "Building Internal Knowledge Graph...",
  "Preparing Assessment Modules...",
  "Synchronizing Security Policies...",
];

interface InitializationProgressProps {
  onComplete: () => void;
}

export default function InitializationProgress({ onComplete }: InitializationProgressProps) {
  const [currentStep, setCurrentStep] = useState(0);
  const [completed, setCompleted] = useState(false);

  useEffect(() => {
    if (currentStep < INIT_STEPS.length) {
      const timer = setTimeout(() => setCurrentStep((s) => s + 1), 1200);
      return () => clearTimeout(timer);
    } else {
      setCompleted(true);
      setTimeout(onComplete, 1500);
    }
  }, [currentStep, onComplete]);

  return (
    <div className="max-w-lg mx-auto text-center py-16">
      <span className="text-5xl mb-6 block">🛡️</span>
      <h2 className="text-2xl font-bold text-white mb-8">Preparing Your Assessment</h2>

      <div className="space-y-3 text-left">
        {INIT_STEPS.map((step, i) => (
          <motion.div
            key={step}
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: i * 0.3 }}
            className={`flex items-center gap-3 px-4 py-2 rounded-lg ${
              i < currentStep
                ? "text-cerberus-green"
                : i === currentStep
                ? "text-cerberus-blue"
                : "text-gray-600"
            }`}
          >
            <span className="text-sm">
              {i < currentStep ? "✓" : i === currentStep ? (
                <span className="animate-spin inline-block">⟳</span>
              ) : "○"}
            </span>
            <span className="text-sm font-mono">{step}</span>
          </motion.div>
        ))}
      </div>

      <AnimatePresence>
        {completed && (
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            className="mt-8"
          >
            <p className="text-cerberus-green font-medium mb-4">
              ✅ Initialization completed successfully. All authorization requirements have been verified.
            </p>
            <p className="text-sm text-gray-400">
              The engagement has officially entered the operational stage.
              Phase One: Open-Source Intelligence Gathering (OSINT) is now ready to begin.
            </p>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
