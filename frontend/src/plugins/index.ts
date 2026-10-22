/**
 * InsiEDR Plugin Bootstrapper
 * ===========================
 *
 * Architectural Role:
 *   Central registry bootstrapper called during application startup (`src/main.tsx`).
 *   Registers all available security plugins in their configured display order.
 *
 * To Add a New Plugin:
 *   1. Import your plugin component.
 *   2. Call `pluginRegistry.register({...})` with a unique ID, icon, category, and order.
 */

import { pluginRegistry } from './registry';
import { SocMatrixPlugin } from './soc-matrix/SocMatrixPlugin';
import { TelemetryExplorerPlugin } from './telemetry-explorer/TelemetryExplorerPlugin';
import { ReviewQueuePlugin } from './review-queue/ReviewQueuePlugin';
import { ShieldAlert, Terminal, ListOrdered } from 'lucide-react';

export function initializePlugins(): void {
  // 1. SOC Threat Matrix: Primary operational overview, live threat feed, and heuristic risk scoring
  pluginRegistry.register({
    id: 'soc-matrix',
    name: 'Insider EDR - Dashboard',
    description: 'Fleet risk posture, real-time threat feed, and heuristic correlation engine',
    icon: ShieldAlert,
    component: SocMatrixPlugin,
    category: 'monitoring',
    badge: (ctx) => {
      const crit = ctx.summary?.risk_counts?.critical || 0;
      return crit > 0 ? crit : undefined;
    },
    order: 1,
  });

  // 2. Telemetry Explorer: Raw event forensics, collector stream inspector, and ML dataset export
  pluginRegistry.register({
    id: 'telemetry-explorer',
    name: 'Telemetry Explorer',
    description: 'Endpoint event streams, forensic log inspector, and ML training dataset export',
    icon: Terminal,
    component: TelemetryExplorerPlugin,
    category: 'investigation',
    order: 2,
  });

  pluginRegistry.register({
    id: 'review-queue',
    name: 'Risk Review',
    description: 'Host-scoped shadow reviews, warmup, and analyst feedback',
    icon: ListOrdered,
    component: ReviewQueuePlugin,
    category: 'investigation',
    order: 3,
  });
}

export * from './registry';
