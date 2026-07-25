/** 403 Unauthorized Page */
import { useNavigate } from "react-router-dom";

export default function UnauthorizedPage() {
  const navigate = useNavigate();
  return (
    <div className="min-h-screen flex items-center justify-center bg-cerberus-dark">
      <div className="text-center">
        <h1 className="text-8xl font-bold text-cerberus-red">403</h1>
        <p className="text-xl text-gray-300 mt-4">Access Denied</p>
        <p className="text-gray-500 mt-2">You don't have permission to access this resource.</p>
        <button onClick={() => navigate("/dashboard")} className="btn-glow mt-8">Back to Dashboard</button>
      </div>
    </div>
  );
}
