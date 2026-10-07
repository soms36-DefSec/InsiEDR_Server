import { useState } from 'react';
import { createRoot } from 'react-dom/client';
import { VirtualizedLogTable } from '../src/components/telemetry/VirtualizedLogTable';
import { ErrorBoundary } from '../src/components/ui/ErrorBoundary';
import type { TelemetryLog } from '../src/types/telemetry';
import '../src/index.css';

declare global {
  interface Window {
    loadRows: (count: number) => void;
    breakView: () => void;
    selectedRow?: number | string;
  }
}

// Retain the data before baseline measurement: measure viewport overhead
// separately from the caller's 50,000 payload objects.
const records: TelemetryLog[] = Array.from({ length: 50000 }, (_, id) => ({
  id, hostname: `HOST-${id}`, username: 'analyst', collector: 'file-collector',
  collected_at: '2026-10-07T12:00:00Z', status: 'success', payload: { path: `file-${id}.txt` },
}));
const selectRow = (row: TelemetryLog) => { window.selectedRow = row.id; };
function BrokenView() { throw new Error('Controlled regression fixture'); return null; }
function Fixture() {
  const [logs, setLogs] = useState<TelemetryLog[]>([]);
  const [broken, setBroken] = useState(false);
  window.loadRows = (count) => setLogs(records.slice(0, count));
  window.breakView = () => setBroken(true);
  return <ErrorBoundary>{broken ? <BrokenView /> : <VirtualizedLogTable logs={logs} onSelectLog={selectRow} />}</ErrorBoundary>;
}
createRoot(document.getElementById('root')!).render(<Fixture />);
