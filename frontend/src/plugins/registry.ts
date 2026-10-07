/**
 * InsiEDR Modular Security Plugin System
 * ======================================
 *
 * Architectural Role:
 *   Provides an extensible micro-kernel / plugin architecture for the InsiEDR
 *   Threat Defense dashboard. Decouples individual analytical and operational
 *   features (e.g. SOC Matrix, Telemetry Explorer, Incident Response) from the
 *   root layout shell.
 *
 * Key Design Principles:
 *   1. Zero Core Modifications: New security features can be built in isolated
 *      directories (`src/plugins/<feature>/`) and registered dynamically.
 *   2. Unified Data Context: All plugins receive `PluginContextData`, providing
 *      zero-effort access to fleet telemetry, live SSE streams, backend health,
 *      and cross-plugin navigation.
 *   3. Reactive Pub/Sub: The registry notifies subscribers whenever plugins are
 *      registered or unregistered, enabling hot-reloadable module loading.
 */

import React from 'react';
import type { DashboardSummary, SystemHealth, TelemetryLog } from '../types/telemetry';

/**
 * Shared runtime context delivered to all active plugins.
 * Encapsulates read-only state as well as shared navigation actions.
 */
export interface PluginContextData {
  /** Complete fleet telemetry overview, PC statuses, and risk counts */
  summary: DashboardSummary | null;
  /** System subsystem health: database, ML models, and task queues */
  health: SystemHealth | null;
  /** Recent raw telemetry log events */
  logs: TelemetryLog[];
  /** True when real-time SSE stream is actively connected */
  isConnected: boolean;
  autoRefresh?: boolean;
  connectionMode?: 'sse' | 'polling' | 'disconnected';
  /** Triggers deep-dive behavioral drilldown drawer for a specific identity */
  onOpenDrillDown?: (username: string, hostname?: string) => void;
  /** Filters the Telemetry Explorer to a specific collector domain */
  onSelectCollector?: (collectorKey: string) => void;
  /** Switches the active dashboard view to another registered plugin */
  onNavigatePlugin?: (pluginId: string) => void;
  /** Triggers an immediate refresh of all dashboard state */
  onRefresh?: () => Promise<void>;
}

/**
 * Standard component props passed to every registered EDR plugin.
 */
export interface PluginProps {
  context: PluginContextData;
}

/**
 * Definition schema required to register a plugin in the InsiEDR dashboard.
 */
export interface EDRPlugin {
  /** Unique URL/system identifier for the plugin (e.g., 'soc-matrix', 'network-graph') */
  id: string;
  /** Human-readable display name shown in navigation bars and headers */
  name: string;
  /** Brief description explaining the analytical purpose of the plugin */
  description: string;
  /** Lucide icon component representing the plugin in navigation menus */
  icon: React.ComponentType<{ className?: string }>;
  /** React component rendered when this plugin is selected */
  component: React.ComponentType<PluginProps>;
  /** Dynamic badge count or status indicator displayed on the navigation tab */
  badge?: (ctx: PluginContextData) => string | number | null | undefined;
  /** Functional category used for navigation grouping and permissions */
  category?: 'monitoring' | 'investigation' | 'response' | 'analytics' | 'settings';
  /** Display sequence order (lower numbers render first) */
  order: number;
  /** Optional permission scopes required to access this plugin */
  requiredRoles?: string[];
}

/**
 * Thread-safe in-memory registry managing the lifecycle of all dashboard plugins.
 */
class PluginRegistry {
  private plugins: Map<string, EDRPlugin> = new Map();
  private listeners: Set<() => void> = new Set();

  /**
   * Registers a new security plugin. If a plugin with the same ID exists, it is overwritten.
   */
  register(plugin: EDRPlugin): void {
    this.plugins.set(plugin.id, plugin);
    this.notify();
  }

  /**
   * Unregisters a plugin by ID.
   */
  unregister(id: string): void {
    this.plugins.delete(id);
    this.notify();
  }

  /**
   * Retrieves a registered plugin by ID.
   */
  get(id: string): EDRPlugin | undefined {
    return this.plugins.get(id);
  }

  /**
   * Returns all registered plugins sorted by their configured display order.
   */
  getAll(): EDRPlugin[] {
    return Array.from(this.plugins.values()).sort((a, b) => a.order - b.order);
  }

  /**
   * Subscribes to registry mutations (add/remove plugins).
   *
   * @returns Unsubscribe function.
   */
  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  private notify(): void {
    this.listeners.forEach((fn) => fn());
  }
}

export const pluginRegistry = new PluginRegistry();
