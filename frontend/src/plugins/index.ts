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
import { TelemetryExplorerPlugin } from './telemetry-explorer/TelemetryExplorerPlugin';
import { Terminal } from 'lucide-react';

export function initializePlugins(): void {
  // Telemetry Explorer Plugin: Raw event stream forensics, live log collection, and ML dataset export
  pluginRegistry.register({
    id: 'telemetry-explorer',
    name: 'Telemetry & Dataset Explorer',
    description: 'Raw event stream, payload inspector, and ML model training dataset export',
    icon: Terminal,
    component: TelemetryExplorerPlugin,
    category: 'investigation',
    order: 1,
  });
}

export * from './registry';
