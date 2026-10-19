/**
 * ErrorBoundary — catches uncaught React render errors and renders the new
 * 500 page instead of a blank screen.
 */
import { Component, ReactNode } from "react";
import ServerErrorPage from "../components/errors/ServerErrorPage";

interface Props {
  children: ReactNode;
}
interface State {
  hasError: boolean;
  error: Error | null;
}

export default class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false, error: null };

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: unknown) {
    // eslint-disable-next-line no-console
    console.error("[Cerberus] uncaught error:", error, info);
  }

  render() {
    if (this.state.hasError) {
      return <ServerErrorPage />;
    }
    return this.props.children;
  }
}
