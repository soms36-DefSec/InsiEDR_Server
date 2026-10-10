/**
 * InsiEDR Telemetry Explorer Page
 * ===============================
 *
 * Architectural Role:
 *   Primary forensic observation workspace for endpoint telemetry logs.
 *   Implements the Industrial CQRS pattern:
 *     - Split View Contract: Queries projected scalar columns (< 20KB for 50 rows).
 *     - DOM Virtualization: Windowed table rendering only 15-20 rows in DOM tree (60 FPS scrolling).
 *     - Seek/Cursor Pagination: Deterministic constant-time traversal over ClickHouse sparse indices.
 *     - On-Demand Forensic Inspection: Side drawer loads deep nested payloads only when an event is clicked.
 *     - Server-Side Aggregation: Real-time event ingestion frequency histogram at top.
 */

import React from 'react';
import { TelemetryExplorerPlugin } from '../plugins/telemetry-explorer/TelemetryExplorerPlugin';
import type { PluginProps } from '../plugins/registry';

export interface TelemetryExplorerProps {
  context?: PluginProps['context'];
  useExplorerApi?: boolean;
}

export const TelemetryExplorer: React.FC<TelemetryExplorerProps> = ({ context, useExplorerApi = true }) => {
  const defaultContext: PluginProps['context'] = context || {
    summary: null,
    health: null,
    logs: [],
    isConnected: false,
    autoRefresh: true,
    connectionMode: 'polling',
    onSelectCollector: () => {},
    onNavigatePlugin: () => {},
    onRefresh: async () => {},
  };

  return <TelemetryExplorerPlugin context={defaultContext} useExplorerApi={useExplorerApi} />;
};

export default TelemetryExplorer;
