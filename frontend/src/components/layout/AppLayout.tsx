import React, { useState, useEffect } from 'react';
import { TopNavbar } from './TopNavbar';
import { pluginRegistry } from '../../plugins/registry';
import type { EDRPlugin, PluginContextData } from '../../plugins/registry';
import { useRealTimeStream } from '../../hooks/useRealTimeStream';
import { ErrorBoundary } from '../ui/ErrorBoundary';

export const AppLayout: React.FC = () => {
  const [plugins, setPlugins] = useState<EDRPlugin[]>(() => pluginRegistry.getAll());
  const [activePluginId, setActivePluginId] = useState('soc-matrix');

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
    onToggleAutoRefresh: toggleAutoRefresh,
    error,
    isStale: Boolean(error && summary),
  };

  const ActiveComponent = activePlugin?.component;

  return (
    <div className="min-h-screen bg-[#f8fafc] text-slate-900 flex flex-col font-sans selection:bg-slate-900 selection:text-white">
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
      <main className="flex-1 overflow-y-auto px-4 sm:px-6 lg:px-8 py-5">
        <div className="max-w-[1700px] mx-auto space-y-5">
          {/* View Title & Description + Fleet PC Status Cards */}
          <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-3 pb-0.5 border-b border-slate-200/60 pb-4">
            <div>
              <div className="flex items-center gap-2.5">
                <h1 className="text-xl sm:text-2xl font-semibold text-slate-900 tracking-tight">
                  {activePlugin?.name || 'Insider EDR - Dashboard'}
                </h1>
                <span className="px-2 py-0.5 text-[11px] font-medium rounded-full bg-slate-100 text-slate-600 border border-slate-200/80">
                  {activePluginId === 'soc-matrix' ? 'Operational View' : 'Forensics View'}
                </span>
              </div>
              <p className="text-xs sm:text-sm text-slate-500 mt-1 font-normal max-w-2xl">
                {activePlugin?.description || 'Fleet risk posture, real-time threat feed, and heuristic correlation engine'}
              </p>
            </div>
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
