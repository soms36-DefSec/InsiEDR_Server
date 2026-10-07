import { Component, type ReactNode } from 'react';

export class ErrorBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };

  static getDerivedStateFromError() { return { failed: true }; }

  render() {
    if (this.state.failed) return (
      <div role="alert" className="rounded-lg border border-amber-200 bg-amber-50 p-5 text-sm text-amber-900">
        This view could not be displayed.
        <button type="button" className="ml-3 underline" onClick={() => this.setState({ failed: false })}>Retry view</button>
      </div>
    );
    return this.props.children;
  }
}
