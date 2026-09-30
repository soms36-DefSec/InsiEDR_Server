/**
 * InsiEDR Telemetry Explorer Plugin
 * ==================================
 *
 * Architectural Role:
 *   High-throughput forensic telemetry exploration module. Enables analysts to
 *   query, multi-dimensionally filter, and inspect thousands of raw collector events
 *   with a windowed 60 FPS virtualized viewport (<10MB DOM overhead).
 *
 * Filter Pipeline:
 *   1. Server-Side: Queries `/api/telemetry` with collector, username, and limit/offset pagination.
 *   2. Client-Side: Multi-dimensional instant filters across:
 *      - Time Range Cutoff: 15m, 1h, 24h, 7d rolling windows.
 *      - Status: success, warning, error, tampered.
 *      - Collector Domain: logon, file, usb/device, process, network/http.
 *      - Full-Text Search: Hostname, username, and raw JSON payload attributes.
 *   3. Deep Inspection: Opens `LogInspectorDrawer` for structured key-value & raw JSON forensics.
 */

import React, { useState, useEffect, useCallback, useMemo } from 'react';
import type { PluginProps } from '../registry';
import { VirtualizedLogTable } from '../../components/telemetry/VirtualizedLogTable';
import { LogInspectorDrawer } from '../../components/telemetry/LogInspectorDrawer';
import { ExportTrainingDatasetModal } from '../../components/telemetry/ExportTrainingDatasetModal';
import { Button } from '../../components/ui/Button';
import type { TelemetryLog } from '../../types/telemetry';
import { fetchTelemetry, exportTelemetryCSV, exportTelemetryJSON, triggerServerExport } from '../../services/api';
import {
  Search,
  X,
  Download,
  RefreshCw,
  SlidersHorizontal,
  Clock,
  ShieldAlert,
  Activity,
  FileSpreadsheet,
} from 'lucide-react';

export const TelemetryExplorerPlugin: React.FC<PluginProps> = ({ context }) => {
  const [logs, setLogs] = useState<TelemetryLog[]>(context.logs || []);
  const [selectedLog, setSelectedLog] = useState<TelemetryLog | null>(null);
  const [showTrainingModal, setShowTrainingModal] = useState<boolean>(false);

  // Filters State
  const [searchTerm, setSearchTerm] = useState('');
  const [activeCollector, setActiveCollector] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [timeRange, setTimeRange] = useState<string>('all');

  const [offset, setOffset] = useState(0);
  const [isLoading, setIsLoading] = useState(false);
  const [hasMore, setHasMore] = useState(true);

  const PAGE_SIZE = 100;

  const loadLogs = useCallback(
    async (newOffset = 0, append = false) => {
      setIsLoading(true);
      try {
        const collectorParam = activeCollector !== 'all' ? activeCollector : null;
        const searchParam = searchTerm.trim() ? searchTerm.trim() : null;

        const res = await fetchTelemetry(
          PAGE_SIZE,
          newOffset,
          collectorParam,
          searchParam
        );
        const fetched = res.logs || [];
        if (append) {
          setLogs((prev) => [...prev, ...fetched]);
        } else {
          setLogs(fetched);
        }
        setOffset(newOffset);
        setHasMore(fetched.length === PAGE_SIZE);
      } catch (err) {
        console.error('Failed to load telemetry logs:', err);
      } finally {
        setIsLoading(false);
      }
    },
    [activeCollector, searchTerm]
  );

  useEffect(() => {
    loadLogs(0, false);
  }, [loadLogs]);

  // Client-side multi-dimensional filtering
  const filteredLogs = useMemo(() => {
    const now = Date.now();
    let cutoff = 0;
    if (timeRange === '15m') cutoff = now - 15 * 60 * 1000;
    else if (timeRange === '1h') cutoff = now - 60 * 60 * 1000;
    else if (timeRange === '24h') cutoff = now - 24 * 60 * 60 * 1000;
    else if (timeRange === '7d') cutoff = now - 7 * 24 * 60 * 60 * 1000;

    return logs.filter((log) => {
      // Time Range Filter
      if (cutoff > 0 && log.collected_at) {
        const t = new Date(log.collected_at).getTime();
        if (!isNaN(t) && t < cutoff) return false;
      }

      // Status Filter
      if (statusFilter !== 'all') {
        const normStatus = (log.status || '').toLowerCase();
        if (statusFilter === 'error' && normStatus !== 'error' && normStatus !== 'tampered') return false;
        if (statusFilter === 'warning' && normStatus !== 'warning') return false;
        if (statusFilter === 'success' && normStatus !== 'success') return false;
      }

      // Collector Filter
      if (activeCollector !== 'all') {
        if (!log.collector || !log.collector.toLowerCase().includes(activeCollector.toLowerCase())) {
          return false;
        }
      }

      // Search Filter
      if (searchTerm.trim()) {
        const q = searchTerm.toLowerCase().trim();
        const fullText = `${log.hostname} ${log.username} ${log.collector} ${
          typeof log.payload === 'string' ? log.payload : JSON.stringify(log.payload || '')
        }`.toLowerCase();
        if (!fullText.includes(q)) return false;
      }

      return true;
    });
  }, [logs, timeRange, statusFilter, activeCollector, searchTerm]);

  const handleClearAllFilters = () => {
    setSearchTerm('');
    setActiveCollector('all');
    setStatusFilter('all');
    setTimeRange('all');
  };

  const handleLoadMore = () => {
    loadLogs(offset + PAGE_SIZE, true);
  };

  const hasActiveFilters =
    Boolean(searchTerm.trim()) ||
    activeCollector !== 'all' ||
    statusFilter !== 'all' ||
    timeRange !== 'all';

  return (
    <div className="space-y-6">
      {/* Comprehensive Filter Toolbar */}
      <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-[0_1px_3px_rgba(0,0,0,0.06)] space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          {/* Search bar */}
          <div className="relative flex-1 min-w-[240px] max-w-md">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search user, hostname, IP, or payload attribute..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-8 pr-8 h-[38px] text-xs bg-white border border-slate-200 rounded-md outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 text-slate-900 transition-colors shadow-2xs"
            />
            {searchTerm && (
              <button
                onClick={() => setSearchTerm('')}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 cursor-pointer"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          {/* Quick Filter Selectors */}
          <div className="flex items-center gap-2 flex-wrap">
            {/* Collector Dropdown */}
            <div className="flex items-center gap-1.5 bg-white border border-slate-200 rounded-md px-3 h-[38px] text-xs shadow-2xs">
              <Activity className="w-3.5 h-3.5 text-slate-400 shrink-0" />
              <span className="text-slate-500 font-medium">Collector:</span>
              <select
                value={activeCollector}
                onChange={(e) => setActiveCollector(e.target.value)}
                className="bg-transparent font-medium text-slate-800 outline-none cursor-pointer"
              >
                <option value="all">All Watchers</option>
                <option value="logon">Logon Watcher</option>
                <option value="file">File Integrity</option>
                <option value="device">USB & Devices</option>
                <option value="http">HTTP & Web</option>
                <option value="process">Process Watcher</option>
              </select>
            </div>

            {/* Status Dropdown */}
            <div className="flex items-center gap-1.5 bg-white border border-slate-200 rounded-md px-3 h-[38px] text-xs shadow-2xs">
              <ShieldAlert className="w-3.5 h-3.5 text-slate-400 shrink-0" />
              <span className="text-slate-500 font-medium">Status:</span>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="bg-transparent font-medium text-slate-800 outline-none cursor-pointer"
              >
                <option value="all">All Statuses</option>
                <option value="success">Success / Normal</option>
                <option value="warning">Warning</option>
                <option value="error">Error / Tampered</option>
              </select>
            </div>

            {/* Time Window Dropdown */}
            <div className="flex items-center gap-1.5 bg-white border border-slate-200 rounded-md px-3 h-[38px] text-xs shadow-2xs">
              <Clock className="w-3.5 h-3.5 text-slate-400 shrink-0" />
              <span className="text-slate-500 font-medium">Time:</span>
              <select
                value={timeRange}
                onChange={(e) => setTimeRange(e.target.value)}
                className="bg-transparent font-medium text-slate-800 outline-none cursor-pointer"
              >
                <option value="all">All Recorded Time</option>
                <option value="15m">Last 15 Minutes</option>
                <option value="1h">Last 1 Hour</option>
                <option value="24h">Last 24 Hours</option>
                <option value="7d">Last 7 Days</option>
              </select>
            </div>
          </div>

          {/* Export & Refresh Actions */}
          <div className="flex items-center gap-2">
            <Button
              variant="secondary"
              size="sm"
              onClick={() => exportTelemetryCSV(filteredLogs)}
              icon={<Download className="w-3.5 h-3.5" />}
              title="Export filtered logs currently loaded to CSV"
            >
              CSV
            </Button>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => exportTelemetryJSON(filteredLogs)}
              icon={<Download className="w-3.5 h-3.5" />}
              title="Export filtered logs currently loaded to JSON"
            >
              JSON
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={() => triggerServerExport('logs', 'csv', { collector: activeCollector })}
              icon={<Download className="w-3.5 h-3.5" />}
              title="Stream full server telemetry dataset (CSV)"
            >
              Stream All
            </Button>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setShowTrainingModal(true)}
              icon={<FileSpreadsheet className="w-3.5 h-3.5 text-blue-600" />}
              title="Export User, Parameters, and Raw Logs over N days for ML training"
            >
              ML Dataset
            </Button>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => loadLogs(0, false)}
              disabled={isLoading}
              icon={<RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />}
            >
              Refresh
            </Button>
          </div>
        </div>

        {/* Active Filter Badges & Counter */}
        {hasActiveFilters && (
          <div className="pt-2.5 border-t border-slate-100 flex items-center justify-between flex-wrap gap-2 text-xs">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-slate-500 font-medium flex items-center gap-1">
                <SlidersHorizontal className="w-3 h-3" />
                Active Filters:
              </span>

              {searchTerm.trim() && (
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-slate-100 text-slate-700 border border-slate-200">
                  Search: "{searchTerm}"
                  <button onClick={() => setSearchTerm('')} className="hover:text-slate-900 cursor-pointer">
                    <X className="w-2.5 h-2.5" />
                  </button>
                </span>
              )}

              {activeCollector !== 'all' && (
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-blue-50 text-blue-700 border border-blue-200 font-medium">
                  Collector: {activeCollector.toUpperCase()}
                  <button onClick={() => setActiveCollector('all')} className="hover:text-blue-900 cursor-pointer">
                    <X className="w-2.5 h-2.5" />
                  </button>
                </span>
              )}

              {statusFilter !== 'all' && (
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-amber-50 text-amber-800 border border-amber-200 font-medium">
                  Status: {statusFilter.toUpperCase()}
                  <button onClick={() => setStatusFilter('all')} className="hover:text-amber-950 cursor-pointer">
                    <X className="w-2.5 h-2.5" />
                  </button>
                </span>
              )}

              {timeRange !== 'all' && (
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-slate-100 text-slate-700 border border-slate-200 font-medium">
                  Window: {timeRange}
                  <button onClick={() => setTimeRange('all')} className="hover:text-slate-900 cursor-pointer">
                    <X className="w-2.5 h-2.5" />
                  </button>
                </span>
              )}

              <button
                onClick={handleClearAllFilters}
                className="text-blue-600 hover:text-blue-800 font-medium underline underline-offset-2 ml-1 cursor-pointer"
              >
                Clear all
              </button>
            </div>

            <div className="text-slate-500 font-medium">
              Showing <b className="text-slate-900 font-mono">{filteredLogs.length}</b> of{' '}
              <span className="font-mono">{logs.length}</span> loaded records
            </div>
          </div>
        )}
      </div>

      {/* Virtualized Table */}
      <VirtualizedLogTable
        logs={filteredLogs}
        onSelectLog={(log) => setSelectedLog(log)}
        isLoading={isLoading}
      />

      {/* Load More Button */}
      {hasMore && (
        <div className="flex justify-center pt-1 pb-6">
          <Button
            variant="secondary"
            size="sm"
            onClick={handleLoadMore}
            disabled={isLoading}
            isLoading={isLoading}
          >
            Load Next 100 Telemetry Logs from Server...
          </Button>
        </div>
      )}

      {/* Payload Inspector Drawer */}
      <LogInspectorDrawer
        log={selectedLog}
        onClose={() => setSelectedLog(null)}
      />

      {/* ML Training Dataset Export Modal */}
      <ExportTrainingDatasetModal
        isOpen={showTrainingModal}
        onClose={() => setShowTrainingModal(false)}
        availableUsers={context.summary?.users || []}
        defaultUsername={searchTerm.trim() || undefined}
      />
    </div>
  );
};
