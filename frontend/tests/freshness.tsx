import React, { useState } from 'react';
import { createRoot } from 'react-dom/client';
import { TelemetryHistogram } from '../src/components/telemetry/TelemetryHistogram';
import { FleetStatusCards } from '../src/components/layout/FleetStatusCards';
import { useRealTimeStream } from '../src/hooks/useRealTimeStream';
import '../src/index.css';

function Fixture() {
  const [collector, setCollector] = useState('process');
  const [version, setVersion] = useState(0);
  const state = useRealTimeStream();
  return <>
    <button onClick={() => setCollector('file')}>Empty filter</button>
    <button onClick={() => setCollector('network')}>Failed filter</button>
    <button onClick={() => setVersion(v => v + 1)}>Refresh chart</button>
    <button onClick={() => void state.refreshAll()}>Refresh fleet</button>
    <output data-testid="updated">{state.lastUpdated?.toISOString() ?? 'unknown'}</output>
    <FleetStatusCards summary={state.summary} stale={Boolean(state.error)} />
    <TelemetryHistogram timeRange="1h" activeCollector={collector} refreshVersion={version} />
  </>;
}
createRoot(document.getElementById('root')!).render(<Fixture />);
