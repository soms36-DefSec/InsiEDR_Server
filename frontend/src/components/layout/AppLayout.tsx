import React, { useState, useEffect } from 'react';
import { TopNavbar } from './TopNavbar';
import { pluginRegistry } from '../../plugins/registry';
import type { EDRPlugin, PluginContextData } from '../../plugins/registry';
import { useRealTimeStream } from '../../hooks/useRealTimeStream';
import { FleetStatusCards } from './FleetStatusCards';
import { ErrorBoundary } from '../ui/ErrorBoundary';

export const AppLayout: React.FC = () => {
  const [plugins, setPlugins] = useState<EDRPlugin[]>(() => pluginRegistry.getAll());
  const [activePluginId, setActivePluginId] = useState('telemetry-explorer');

  const {
    summary,
    health,
    logs,
    connectionMode,
    autoRefresh,
    toggleAutoRefresh,
    refreshAll,
    error,
  } = useRealTimeStream();

  useEffect(() => {
    return pluginRegistry.subscribe(() => {
      setPlugins(pluginRegistry.getAll());
    });
  }, []);

  const activePlugin = plugins.find((p) => p.id === activePluginId) || plugins[0];

  const handleSelectCollector = () => {
    setActivePluginId('telemetry-explorer');
  };

  const contextData: PluginContextData = {
    summary,
    health,
    logs,
    isConnected: connectionMode === 'sse',
    autoRefresh,
    connectionMode,
    onSelectCollector: handleSelectCollector,
    onNavigatePlugin: (id) => setActivePluginId(id),
    onRefresh: refreshAll,
  };

  const ActiveComponent = activePlugin?.component;

  return (
    <div className="min-h-screen bg-[#f8fafc] text-slate-900 flex flex-col">
      {/* Top Navigation Bar */}
      <TopNavbar
        plugins={plugins}
        activePluginId={activePluginId}
        onSelectPlugin={setActivePluginId}
        context={contextData}
        connectionMode={connectionMode}
        autoRefresh={autoRefresh}
        onToggleAutoRefresh={toggleAutoRefresh}
        onRefresh={refreshAll}
      />

      {/* Main Content Canvas */}
      <main className="flex-1 overflow-y-auto px-6 sm:px-8 py-6">
        <div className="max-w-[1700px] mx-auto space-y-6">
          {error && <div role="alert" className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">
            Fleet refresh failed: {error}. Previously loaded metrics may be stale.
          </div>}
          {/* View Title & Description + Fleet PC Status Cards */}
          <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-4 pb-1">
            <div>
              <h1 className="text-[28px] font-semibold text-slate-900 tracking-tight leading-tight">
                {activePlugin?.name || 'Telemetry & Dataset Explorer'}
              </h1>
              <p className="text-sm text-slate-500 mt-1 font-normal">
                {activePlugin?.description || 'Endpoint telemetry ingestion and ML model training dataset export'}
              </p>
            </div>

            <FleetStatusCards summary={summary} />
          </div>

          {/* Active Plugin View Content */}
          {ActiveComponent ? (
            <ErrorBoundary key={activePluginId}><ActiveComponent context={contextData} /></ErrorBoundary>
          ) : (
            <div className="p-8 text-center text-slate-400 text-xs">
              No active security view loaded.
            </div>
          )}
        </div>
      </main>
    </div>
  );
};
