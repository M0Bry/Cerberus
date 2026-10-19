/** 503 Page (new design) — ported from the new front-end's maintenance.html. */
import { Link } from "react-router-dom";
import SysPanel from "./SysPanel";

export default function MaintenancePage() {
  return (
    <SysPanel
      icon="fa-screwdriver-wrench"
      tag={
        <>
          Error <b>503</b>
        </>
      }
      title="Under Maintenance"
      sub="Cerberus AI is undergoing scheduled maintenance to improve the platform. We'll be back shortly. Thank you for your patience."
      actions={
        <>
          <a href="/#contact" className="btn btn-primary">
            <i className="fas fa-headset" /> Contact Support
          </a>
          <Link to="/" className="btn btn-outline">
            <i className="fas fa-house" /> Back to Home
          </Link>
        </>
      }
    />
  );
}
