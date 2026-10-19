/** 500 Page (new design) — ported from the new front-end's server-error.html. */
import { Link } from "react-router-dom";
import SysPanel from "./SysPanel";

export default function ServerErrorPage() {
  return (
    <SysPanel
      icon="fa-triangle-exclamation"
      tag={
        <>
          Error <b>500</b>
        </>
      }
      title="Server Error"
      sub="Something went wrong on our side. The incident has been logged and our team has been notified. Please try again in a few moments."
      actions={
        <>
          <button type="button" className="btn btn-primary" onClick={() => window.location.reload()}>
            <i className="fas fa-rotate-right" /> Try Again
          </button>
          <Link to="/" className="btn btn-outline">
            <i className="fas fa-house" /> Back to Home
          </Link>
        </>
      }
    />
  );
}
