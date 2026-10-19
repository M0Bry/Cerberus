/** 401 Page (new design) — ported from the new front-end's unauthorized.html. */
import { Link } from "react-router-dom";
import SysPanel from "./SysPanel";

export default function UnauthorizedPage() {
  return (
    <SysPanel
      icon="fa-lock"
      tag={
        <>
          Error <b>401</b>
        </>
      }
      title="Access Denied"
      sub="You need to be signed in with an authorized account to view this page. If you believe this is a mistake, contact your organization's administrator."
      backTo="/"
      backLabel="Home"
      actions={
        <>
          <Link to="/login" className="btn btn-primary">
            <i className="fas fa-right-to-bracket" /> Log In
          </Link>
          <Link to="/" className="btn btn-outline">
            <i className="fas fa-house" /> Back to Home
          </Link>
        </>
      }
    />
  );
}
