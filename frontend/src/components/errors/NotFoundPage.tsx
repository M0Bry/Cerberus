/**
 * 404 Not Found Page.
 */

import { useNavigate } from "react-router-dom";
import ParticleBackground from "../common/ParticleBackground";

export default function NotFoundPage() {
  const navigate = useNavigate();
  return (
    <div className="min-h-screen relative flex items-center justify-center">
      <ParticleBackground />
      <div className="relative z-10 text-center">
        <h1 className="text-8xl font-bold text-cerberus-blue glow-text">404</h1>
        <p className="text-xl text-gray-300 mt-4">Target Not Found</p>
        <p className="text-gray-500 mt-2">The page you're looking for doesn't exist.</p>
        <button onClick={() => navigate("/")} className="btn-glow mt-8">Return to Base</button>
      </div>
    </div>
  );
}
