// A narrow subscription keeps high-rate invalidations out of the app shell's
// React state. Each view controls its own bounded refresh schedule.
const listeners = new Set<() => void>();

export function subscribeTelemetry(listener: () => void) {
  listeners.add(listener);
  return () => { listeners.delete(listener); };
}

export function notifyTelemetry() {
  listeners.forEach((listener) => listener());
}
