import React, { useState } from 'react';
import type { EDRPlugin, PluginContextData } from '../../plugins/registry';
import { Button } from '../ui/Button';
import { RefreshCw, Download, Monitor, ChevronDown, FileCode, Database, Sparkles } from 'lucide-react';
import { triggerServerExport } from '../../services/api';
import { ExportTrainingDatasetModal } from '../telemetry/ExportTrainingDatasetModal';

export interface TopNavbarProps {
  plugins: EDRPlugin[];
  activePluginId: string;
  onSelectPlugin: (id: string) => void;
  context: PluginContextData;
  connectionMode: 'sse' | 'polling' | 'disconnected';
  autoRefresh: boolean;
  onToggleAutoRefresh: () => void;
  onRefresh: () => Promise<void>;
  onExportCSV?: () => void;
}

export const TopNavbar: React.FC<TopNavbarProps> = ({
  plugins,
  activePluginId,
  onSelectPlugin,
  context,
  connectionMode,
  autoRefresh,
  onToggleAutoRefresh,
  onRefresh,
}) => {
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [showExportMenu, setShowExportMenu] = useState(false);
  const [showTrainingModal, setShowTrainingModal] = useState(false);

  const summary = context.summary;
  const pcStatus = summary?.pc_status;
  const totalPCs = pcStatus ? (pcStatus.total_pcs ?? (pcStatus as any).total_count ?? 0) : 0;
  const onlinePCs = pcStatus ? (pcStatus.online_pcs ?? (pcStatus as any).online_count ?? 0) : 0;
  const offlinePCs = pcStatus ? (pcStatus.offline_pcs ?? (pcStatus as any).offline_count ?? 0) : 0;

  const handleRefresh = async () => {
    setIsRefreshing(true);
    try {
      await onRefresh();
    } finally {
      setTimeout(() => setIsRefreshing(false), 400);
    }
  };

  return (
    <nav className="bg-white text-slate-800 border-b border-slate-200 sticky top-0 z-40 select-none shadow-[0_1px_2px_rgba(0,0,0,0.03)]">
      <div className="max-w-[1700px] mx-auto px-6 h-14 flex items-center justify-between gap-4">
        {/* Brand & Logo */}
        <div className="flex items-center gap-3 shrink-0">
          <div className="w-7 h-7 rounded-md bg-blue-600 flex items-center justify-center text-white font-bold text-xs tracking-tight shadow-xs">
            IE
          </div>
          <div>
            <div className="flex items-center gap-1.5">
              <span className="text-sm font-semibold text-slate-900 tracking-tight">InsiEDR</span>
            </div>
            <div className="text-[11px] text-slate-500 font-normal leading-none mt-0.5">
              Telemetry & Dataset Collection
            </div>
          </div>
        </div>

        {/* Navigation Tabs in Top Bar */}
        <div className="flex items-center gap-1.5 overflow-x-auto py-1">
          {plugins.map((plugin) => {
            const isActive = plugin.id === activePluginId;
            const Icon = plugin.icon;
            const badgeVal = plugin.badge ? plugin.badge(context) : null;

            return (
              <button
                key={plugin.id}
                onClick={() => onSelectPlugin(plugin.id)}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs transition-colors cursor-pointer whitespace-nowrap ${
                  isActive
                    ? 'bg-blue-50 text-blue-700 font-medium border border-blue-200'
                    : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900 border border-transparent font-normal'
                }`}
              >
                <Icon
                  className={`w-3.5 h-3.5 ${isActive ? 'text-blue-600' : 'text-slate-400'}`}
                />
                <span>{plugin.name}</span>
                {badgeVal !== null && badgeVal !== undefined && (
                  <span
                    className={`text-[10px] px-1.5 py-0.2 rounded-full font-medium ${
                      typeof badgeVal === 'number' && badgeVal > 0
                        ? 'bg-red-50 text-red-700 border border-red-200'
                        : 'bg-slate-100 text-slate-600'
                    }`}
                  >
                    {badgeVal}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* Right Section: Fleet Status & Action Controls */}
        <div className="flex items-center gap-3 shrink-0">
          {/* Fleet Status Metrics: Total PCs, Online, Offline */}
          <div className="hidden lg:flex items-center gap-2 text-xs">
            {/* Total PCs Connected */}
            <div
              className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-50 border border-slate-200 text-slate-700 shadow-2xs"
              title="Total Connected PCs"
            >
              <Monitor className="w-3.5 h-3.5 text-slate-500" />
              <span className="text-slate-500 font-medium text-[11px]">Total PCs:</span>
              <span className="font-bold text-slate-900">{totalPCs}</span>
            </div>

            {/* Online Count */}
            <div
              className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-emerald-50/80 border border-emerald-200 text-emerald-800 shadow-2xs"
              title="Online PCs"
            >
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
              <span className="text-emerald-700 font-medium text-[11px]">Online:</span>
              <span className="font-bold text-emerald-800">{onlinePCs}</span>
            </div>

            {/* Offline Count */}
            <div
              className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-50 border border-slate-200 text-slate-600 shadow-2xs"
              title="Offline PCs"
            >
              <span className="w-2 h-2 rounded-full bg-slate-400" />
              <span className="text-slate-500 font-medium text-[11px]">Offline:</span>
              <span className="font-bold text-slate-700">{offlinePCs}</span>
            </div>

            <span className="w-px h-3.5 bg-slate-200" />

            <div className="flex items-center gap-1.5 text-slate-600" title="Telemetry Ingestion Status">
              <Database className="w-3.5 h-3.5 text-emerald-600" />
              <span className="font-semibold uppercase text-[10px] text-emerald-700">
                ACTIVE
              </span>
            </div>
          </div>

          {/* Real-time Stream Status */}
          <div className="flex items-center gap-2 px-2.5 py-1.5 rounded-md border border-slate-200 bg-slate-50 text-xs">
            <span
              className={`w-2 h-2 rounded-full ${
                connectionMode === 'sse'
                  ? 'bg-emerald-600 animate-pulse-subtle'
                  : connectionMode === 'polling'
                  ? 'bg-amber-500'
                  : 'bg-slate-400'
              }`}
            />
            <span className="text-slate-600 text-[11px] font-normal hidden sm:inline">
              {connectionMode === 'sse'
                ? 'Stream Active'
                : autoRefresh
                ? 'Polling 3s'
                : 'Paused'}
            </span>
            <button
              onClick={onToggleAutoRefresh}
              className="text-[11px] font-medium text-blue-600 hover:text-blue-800 cursor-pointer"
            >
              {autoRefresh ? 'Pause' : 'Resume'}
            </button>
          </div>

          {/* Refresh Button */}
          <button
            onClick={handleRefresh}
            disabled={isRefreshing}
            className="p-2 rounded-md bg-white hover:bg-slate-50 text-slate-600 hover:text-slate-900 border border-slate-200 shadow-2xs transition-colors cursor-pointer disabled:opacity-50"
            title="Refresh telemetry"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
          </button>

          {/* Export Dropdown */}
          <div className="relative">
            <Button
              variant="primary"
              size="sm"
              onClick={() => setShowExportMenu((prev) => !prev)}
              icon={<Download className="w-3.5 h-3.5" />}
              className="flex items-center gap-1.5"
            >
              <span>Export</span>
              <ChevronDown className="w-3 h-3 opacity-80" />
            </Button>

            {showExportMenu && (
              <>
                <div
                  className="fixed inset-0 z-40"
                  onClick={() => setShowExportMenu(false)}
                />
                <div className="absolute right-0 mt-2 w-64 bg-white border border-slate-200 rounded-lg shadow-lg z-50 py-1.5 text-xs">
                  {/* ML Model Training Dataset Option */}
                  <div className="px-3 py-1 text-[10px] font-semibold uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
                    <Sparkles className="w-3 h-3 text-blue-600" />
                    Model Training Dataset
                  </div>
                  <button
                    onClick={() => {
                      setShowTrainingModal(true);
                      setShowExportMenu(false);
                    }}
                    className="w-full text-left px-3 py-2 text-slate-800 hover:bg-blue-50/70 flex items-center gap-2.5 transition-colors cursor-pointer border-b border-slate-100"
                  >
                    <Database className="w-4 h-4 text-blue-600 shrink-0" />
                    <div>
                      <div className="font-semibold text-slate-900 text-xs">Export ML Dataset (Excel/CSV)</div>
                      <div className="text-[10px] text-slate-500">User, Parameters & Raw Logs (N Days)</div>
                    </div>
                  </button>

                  <div className="my-1 border-t border-slate-100" />
                  <div className="px-3 py-1 text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                    Raw Telemetry Streams
                  </div>
                  <button
                    onClick={() => {
                      triggerServerExport('logs', 'csv');
                      setShowExportMenu(false);
                    }}
                    className="w-full text-left px-3 py-1.5 text-slate-700 hover:bg-slate-50 hover:text-slate-900 flex items-center gap-2 transition-colors cursor-pointer"
                  >
                    <Download className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                    <span>Stream All Logs (CSV)</span>
                  </button>
                  <button
                    onClick={() => {
                      triggerServerExport('logs', 'json');
                      setShowExportMenu(false);
                    }}
                    className="w-full text-left px-3 py-1.5 text-slate-700 hover:bg-slate-50 hover:text-slate-900 flex items-center gap-2 transition-colors cursor-pointer"
                  >
                    <FileCode className="w-3.5 h-3.5 text-amber-600 shrink-0" />
                    <span>Stream Logs (NDJSON)</span>
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      </div>

      {/* ML Model Training Dataset Export Modal */}
      <ExportTrainingDatasetModal
        isOpen={showTrainingModal}
        onClose={() => setShowTrainingModal(false)}
        availableUsers={summary?.users || []}
      />
    </nav>
  );
};
