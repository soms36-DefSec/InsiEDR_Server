import React, { useState, useEffect } from 'react';
import { TopNavbar } from './TopNavbar';
import { pluginRegistry } from '../../plugins/registry';
import type { EDRPlugin, PluginContextData } from '../../plugins/registry';
import { useRealTimeStream } from '../../hooks/useRealTimeStream';
import { Monitor } from 'lucide-react';

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
  } = useRealTimeStream();

  const pcStatus = summary?.pc_status;
  const totalPCs = pcStatus ? (pcStatus.total_pcs ?? (pcStatus as any).total_count ?? 0) : 0;
  const onlinePCs = pcStatus ? (pcStatus.online_pcs ?? (pcStatus as any).online_count ?? 0) : 0;
  const offlinePCs = pcStatus ? (pcStatus.offline_pcs ?? (pcStatus as any).offline_count ?? 0) : 0;

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
    onSelectCollector: handleSelectCollector,
    onNavigatePlugin: (id) => setActivePluginId(id),
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
          {/* View Title & Description + Fleet PC Status Cards */}
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-1">
            <div>
              <h1 className="text-[28px] font-semibold text-slate-900 tracking-tight leading-tight">
                {activePlugin?.name || 'Telemetry & Dataset Explorer'}
              </h1>
              <p className="text-sm text-slate-500 mt-1 font-normal">
                {activePlugin?.description || 'Endpoint telemetry ingestion and ML model training dataset export'}
              </p>
            </div>

            {/* Fleet Status Metrics: Total PCs Connected, Online, Offline */}
            <div className="flex items-center gap-2.5 sm:gap-3 flex-wrap sm:flex-nowrap shrink-0">
              {/* Total PCs Connected */}
              <div
                className="flex items-center gap-3 px-3.5 py-2 bg-white border border-slate-200 rounded-lg shadow-2xs hover:border-slate-300 transition-colors"
                title="Total endpoints connected to server"
              >
                <div className="w-8 h-8 rounded-md bg-slate-100 border border-slate-200 flex items-center justify-center text-slate-600 shrink-0">
                  <Monitor className="w-4 h-4" />
                </div>
                <div>
                  <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">Total PCs</div>
                  <div className="text-base font-bold text-slate-900 leading-none mt-0.5">
                    {totalPCs}
                  </div>
                </div>
              </div>

              {/* Online PCs */}
              <div
                className="flex items-center gap-3 px-3.5 py-2 bg-white border border-emerald-200/90 rounded-lg shadow-2xs hover:border-emerald-300 transition-colors"
                title="Active endpoints online in last 5 minutes"
              >
                <div className="w-8 h-8 rounded-md bg-emerald-50 border border-emerald-100 flex items-center justify-center text-emerald-600 relative shrink-0">
                  <Monitor className="w-4 h-4" />
                  <span className="absolute top-1 right-1 w-2 h-2 rounded-full bg-emerald-500 ring-2 ring-white animate-pulse" />
                </div>
                <div>
                  <div className="text-[10px] font-semibold uppercase tracking-wider text-emerald-600">Online</div>
                  <div className="text-base font-bold text-emerald-700 leading-none mt-0.5">
                    {onlinePCs}
                  </div>
                </div>
              </div>

              {/* Offline PCs */}
              <div
                className="flex items-center gap-3 px-3.5 py-2 bg-white border border-slate-200 rounded-lg shadow-2xs hover:border-slate-300 transition-colors"
                title="Endpoints inactive or offline"
              >
                <div className="w-8 h-8 rounded-md bg-slate-100 border border-slate-200 flex items-center justify-center text-slate-400 relative shrink-0">
                  <Monitor className="w-4 h-4" />
                  <span className="absolute top-1 right-1 w-2 h-2 rounded-full bg-slate-400 ring-2 ring-white" />
                </div>
                <div>
                  <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">Offline</div>
                  <div className="text-base font-bold text-slate-600 leading-none mt-0.5">
                    {offlinePCs}
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Active Plugin View Content */}
          {ActiveComponent ? (
            <ActiveComponent context={contextData} />
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
