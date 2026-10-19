/** 404 Page (new design) — ported from the new front-end's 404.html. */
import { Link } from "react-router-dom";
import StateLink from "../common/StateLink";
import SysPanel from "./SysPanel";

export default function NotFoundPage() {
  return (
    <SysPanel
      icon="fa-compass"
      tag={
        <>
          Error <b>404</b>
        </>
      }
      title="Page Not Found"
      sub="The page you're looking for doesn't exist or may have been moved. Check the address, or head back to the platform."
      actions={
        <>
          <Link to="/" className="btn btn-primary">
            <i className="fas fa-house" /> Back to Home
          </Link>
          <StateLink to="/" state={{ scrollTo: "contact" }} className="btn btn-outline">
            <i className="fas fa-headset" /> Contact Support
          </StateLink>
        </>
      }
    />
  );
}
