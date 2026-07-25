/** 500 Server Error Page */
import { useNavigate } from "react-router-dom";

export default function ServerErrorPage() {
  const navigate = useNavigate();
  return (
    <div className="min-h-screen flex items-center justify-center bg-cerberus-dark">
      <div className="text-center">
        <h1 className="text-8xl font-bold text-cerberus-red">500</h1>
        <p className="text-xl text-gray-300 mt-4">Internal Server Error</p>
        <p className="text-gray-500 mt-2">Something went wrong on our end. Please try again later.</p>
        <button onClick={() => navigate("/")} className="btn-glow mt-8">Return Home</button>
      </div>
    </div>
  );
}
