/**
 * New Assessment Page — Starts a new engagement with AI conversation.
 */

import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation } from "@tanstack/react-query";
import DashboardLayout from "../components/layout/DashboardLayout";
import { engagementService } from "../services/engagement";

// Shape of the response when starting a new engagement
interface StartEngagementResponse {
  engagement_id: string;
  ai_response?: string;
}

export default function NewAssessmentPage() {
  const navigate = useNavigate();
  const [projectName, setProjectName] = useState("");
  const [orgName, setOrgName] = useState("");

  const createMutation = useMutation<StartEngagementResponse>({
    mutationFn: () =>
      engagementService
        .sendMessage("new", "Start new assessment")
        .then((res: { data: StartEngagementResponse }) => res.data),
    onSuccess: (data) => {
      navigate(`/engagement/${data.engagement_id}/conversation`);
    },
  });

  return (
    <DashboardLayout activeItem="new-assessment">
      <div className="max-w-2xl mx-auto">
        <h1 className="text-3xl font-bold text-white mb-2">
          Start New Assessment
        </h1>
        <p className="text-gray-400 mb-8">
          Begin a new penetration testing engagement. The Cerberus AI agent will
          guide you through the entire process.
        </p>

        <div className="cyber-card space-y-6">
          <div>
            <label className="block text-sm text-gray-300 mb-2">
              Project Name
            </label>
            <input
              type="text"
              className="cyber-input"
              placeholder="e.g., Q3 External Security Assessment"
              value={projectName}
              onChange={(e) => setProjectName(e.target.value)}
            />
          </div>

          <div>
            <label className="block text-sm text-gray-300 mb-2">
              Organization Name
            </label>
            <input
              type="text"
              className="cyber-input"
              placeholder="e.g., Acme Corporation"
              value={orgName}
              onChange={(e) => setOrgName(e.target.value)}
            />
          </div>

          <div className="p-4 bg-cerberus-blue/10 border border-cerberus-blue/30 rounded-lg">
            <p className="text-sm text-cerberus-blue">
              After creating the project, Cerberus AI will begin a guided
              conversation to understand your organization, infrastructure, and
              security objectives.
            </p>
          </div>

          <button
            onClick={() => createMutation.mutate()}
            disabled={!projectName || !orgName || createMutation.isPending}
            className="btn-glow w-full text-center disabled:opacity-50"
          >
            {createMutation.isPending
              ? "Initializing..."
              : "Begin AI Conversation →"}
          </button>
        </div>
      </div>
    </DashboardLayout>
  );
}
