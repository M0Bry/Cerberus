/**
 * StateLink — router link that passes history `state`.
 *
 * react-router v7 removed `state` from the `to` object, so this small helper
 * keeps the call sites declarative: <StateLink to="/x" state={{...}}>.
 */
import { CSSProperties, ReactNode } from "react";
import { useNavigate } from "react-router-dom";

interface StateLinkProps {
  to: string;
  state?: Record<string, unknown>;
  className?: string;
  style?: CSSProperties;
  children: ReactNode;
}

export default function StateLink({ to, state, className, style, children }: StateLinkProps) {
  const navigate = useNavigate();
  return (
    <a
      href={to}
      className={className}
      style={style}
      onClick={(e) => {
        e.preventDefault();
        navigate(to, { state });
      }}
    >
      {children}
    </a>
  );
}
