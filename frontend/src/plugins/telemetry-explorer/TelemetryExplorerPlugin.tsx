/**
 * InsiEDR Telemetry Explorer Plugin
 * ==================================
 *
 * Architectural Role:
 *   High-throughput forensic telemetry exploration module. Enables analysts to
 *   query, multi-dimensionally filter, and inspect thousands of raw collector events
 *   with a windowed viewport and bounded DOM row count.
 *
 * Filter Pipeline:
 *   1. Server-Side: Applies all filters before limit/offset pagination.
 *   2. Debounced multi-dimensional filters across:
 *      - Time Range Cutoff: 15m, 1h, 24h, 7d rolling windows.
 *      - Status: success, warning, error, tampered.
 *      - Collector Domain: logon, file, usb/device, process, network/http.
 *      - Full-Text Search: Hostname, username, and raw JSON payload attributes.
 *   3. Deep Inspection: Opens `LogInspectorDrawer` for structured key-value & raw JSON forensics.
 */

import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { subscribeTelemetry } from '../../services/telemetryStream';
import type { PluginProps } from '../registry';
import { VirtualizedLogTable } from '../../components/telemetry/VirtualizedLogTable';
import { LogInspectorDrawer } from '../../components/telemetry/LogInspectorDrawer';
import { ExportTrainingDatasetModal } from '../../components/telemetry/ExportTrainingDatasetModal';
import { CollectorDatasetExportModal } from '../../components/telemetry/CollectorDatasetExportModal';
import { Button } from '../../components/ui/Button';
import type { TelemetryLog } from '../../types/telemetry';
import { fetchTelemetry, fetchAvailableCollectors, exportTelemetryCSV, exportTelemetryJSON, triggerServerExport } from '../../services/api';
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
  Layers,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
} from 'lucide-react';

const KNOWN_COLLECTOR_LABELS: Record<string, string> = {
  all: 'All Watchers & Collectors',
  process: 'Process Watcher',
  network: 'Network Connections',
  logon: 'Logon & Authentication',
  file: 'File Integrity (FIM)',
  device: 'USB & Devices',
  http: 'HTTP & Web Traffic',
  'keystroke-collector': 'Keystroke Dynamics',
  'clipboard-monitor': 'Clipboard Monitor',
  driver_monitor: 'Driver Monitor',
  'driver-monitor': 'Driver Monitor',
  dns_monitor: 'DNS Queries',
  'dns-monitor': 'DNS Queries',
  lsass_monitor: 'LSASS Guard',
  'lsass-monitor': 'LSASS Guard',
  persistence_monitor: 'Persistence & Run Keys',
  'persistence-monitor': 'Persistence & Run Keys',
  registry: 'Registry Activity',
  usn_monitor: 'USN Journal Monitor',
  'usn-monitor': 'USN Journal Monitor',
  wmi_activity: 'WMI Activity',
  'wmi-activity': 'WMI Activity',
  'decoy-monitor': 'Decoy Canary Monitor',
  decoy_monitor: 'Decoy Canary Monitor',
  'memory-scanner': 'Memory Scanner',
  'short-Term_EDR_Feature': 'Short-Term Features',
};

const formatCollectorLabel = (key: string): string => {
  if (KNOWN_COLLECTOR_LABELS[key]) return KNOWN_COLLECTOR_LABELS[key];
  return key
    .replace(/[-_]/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase());
};

export const TelemetryExplorerPlugin: React.FC<PluginProps> = ({ context }) => {
  const [logs, setLogs] = useState<TelemetryLog[]>(context.logs || []);
  const [selectedLog, setSelectedLog] = useState<TelemetryLog | null>(null);
  const [showTrainingModal, setShowTrainingModal] = useState<boolean>(false);
  const [showCollectorExportModal, setShowCollectorExportModal] = useState<boolean>(false);
  const [availableCollectors, setAvailableCollectors] = useState<string[]>([]);

  // Filters State
  const [searchTerm, setSearchTerm] = useState('');
  const [activeCollector, setActiveCollector] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [timeRange, setTimeRange] = useState<string>('all');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [loadError, setLoadError] = useState<string | null>(null);
  const request = useRef<AbortController | null>(null);
  const queuedRefresh = useRef(false);
  const scheduleRefresh = useRef<() => void>(() => {});

  useEffect(() => {
    fetchAvailableCollectors()
      .then((res) => {
        if (res.ok && Array.isArray(res.collectors) && res.collectors.length > 0) {
          setAvailableCollectors(res.collectors);
        }
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => setDebouncedSearch(searchTerm.trim()), 250);
    return () => window.clearTimeout(timer);
  }, [searchTerm]);

  // Pagination State
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(50);
  const [totalCount, setTotalCount] = useState<number>(0);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [hasMore, setHasMore] = useState<boolean>(true);

  const loadLogs = useCallback(
    async (pageToLoad = 1, currentSize = pageSize, background = false) => {
      if (background && request.current) { queuedRefresh.current = true; return; }
      request.current?.abort();
      const abort = new AbortController();
      request.current = abort;
      setIsLoading(true);
      const offset = (pageToLoad - 1) * currentSize;
      const periods: Record<string, number> = { '15m': 900, '1h': 3600, '24h': 86400, '7d': 604800 };
      try {
        const response = await fetchTelemetry(currentSize, offset,
          activeCollector === 'all' ? null : activeCollector, null, {
            search: debouncedSearch || undefined,
            status: statusFilter === 'all' ? undefined : statusFilter,
            start_time: periods[timeRange] ? new Date(Date.now() - periods[timeRange] * 1000).toISOString() : undefined,
            signal: abort.signal,
          });
        if (abort.signal.aborted || request.current !== abort) return;
        const fetched = response.logs || [];
        const total = response.total ?? offset + fetched.length;
        setLogs(fetched);
        setCurrentPage(pageToLoad);
        setHasMore(offset + fetched.length < total);
        setTotalCount(total);
        setLoadError(null);
      } catch (error) {
        if (!abort.signal.aborted) setLoadError(error instanceof Error ? error.message : 'Could not load telemetry');
      } finally {
        if (request.current === abort) {
          request.current = null;
          setIsLoading(false);
          if (queuedRefresh.current) { queuedRefresh.current = false; scheduleRefresh.current(); }
        }
      }
    }, [activeCollector, debouncedSearch, statusFilter, timeRange, pageSize]
  );

  useEffect(() => {
    void loadLogs(1, pageSize);
    return () => { request.current?.abort(); request.current = null; queuedRefresh.current = false; };
  }, [loadLogs, pageSize]);

  useEffect(() => {
    if (context.autoRefresh === false) return;
    let timer: number | undefined;
    const schedule = () => {
      if (timer !== undefined) return;
      timer = window.setTimeout(() => {
        timer = undefined;
        void loadLogs(currentPage, pageSize, true);
      }, 50);
    };
    scheduleRefresh.current = schedule;
    const unsubscribe = subscribeTelemetry(schedule);
    const poll = window.setInterval(schedule, context.isConnected ? 30000 : 3000);
    return () => {
      unsubscribe();
      window.clearInterval(poll);
      window.clearTimeout(timer);
      scheduleRefresh.current = () => {};
    };
  }, [context.autoRefresh, context.isConnected, currentPage, pageSize, loadLogs]);

  const totalPages = Math.max(1, Math.ceil((totalCount || logs.length) / pageSize));

  const handlePageSizeChange = (newSize: number) => {
    setPageSize(newSize);

  };

  const handleGoToPage = (newPage: number) => {
    if (newPage < 1 || (totalCount > 0 && newPage > totalPages) || isLoading) return;
    loadLogs(newPage, pageSize);
  };

  const pageNumbers = useMemo(() => {
    const pages: (number | string)[] = [];
    if (totalPages <= 7) {
      for (let i = 1; i <= totalPages; i++) pages.push(i);
    } else {
      pages.push(1);
      if (currentPage > 3) {
        pages.push('...');
      }
      const start = Math.max(2, currentPage - 1);
      const end = Math.min(totalPages - 1, currentPage + 1);
      for (let i = start; i <= end; i++) {
        pages.push(i);
      }
      if (currentPage < totalPages - 2) {
        pages.push('...');
      }
      pages.push(totalPages);
    }
    return pages;
  }, [currentPage, totalPages]);

  const startItem = totalCount === 0 || logs.length === 0 ? 0 : (currentPage - 1) * pageSize + 1;
  const endItem = (currentPage - 1) * pageSize + logs.length;

  // Filters run before database pagination, so rows and totals share semantics.
  const filteredLogs = logs;

  const collectorOptions = useMemo(() => {
    const defaultList = [
      'all',
      'process',
      'network',
      'logon',
      'file',
      'device',
      'http',
      'keystroke-collector',
      'clipboard-monitor',
      'driver_monitor',
      'dns_monitor',
      'lsass_monitor',
      'persistence_monitor',
      'registry',
      'usn_monitor',
      'wmi_activity',
      'decoy-monitor',
    ];
    const combined = [...defaultList];
    for (const c of availableCollectors) {
      if (!combined.includes(c)) {
        combined.push(c);
      }
    }
    return combined;
  }, [availableCollectors]);

  const handleClearAllFilters = () => {
    setSearchTerm('');
    setActiveCollector('all');
    setStatusFilter('all');
    setTimeRange('all');
  };

  const hasActiveFilters =
    Boolean(searchTerm.trim()) ||
    activeCollector !== 'all' ||
    statusFilter !== 'all' ||
    timeRange !== 'all';

  return (
    <div className="space-y-6">
      {loadError && (
        <div role="alert" className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">
          {loadError}. Displaying the last successfully loaded page.
          <button type="button" onClick={() => loadLogs(currentPage, pageSize)} className="ml-3 underline">Retry</button>
        </div>
      )}
      {/* Comprehensive Filter Toolbar */}
      <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-[0_1px_3px_rgba(0,0,0,0.06)] space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          {/* Search bar */}
          <div className="relative flex-1 min-w-[240px] max-w-md">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              aria-label="Search telemetry"
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
                aria-label="Collector"
                value={activeCollector}
                onChange={(e) => setActiveCollector(e.target.value)}
                className="bg-transparent font-medium text-slate-800 outline-none cursor-pointer max-w-[220px]"
              >
                {collectorOptions.map((collectorKey) => (
                  <option key={collectorKey} value={collectorKey}>
                    {formatCollectorLabel(collectorKey)}
                  </option>
                ))}
              </select>
            </div>

            {/* Status Dropdown */}
            <div className="flex items-center gap-1.5 bg-white border border-slate-200 rounded-md px-3 h-[38px] text-xs shadow-2xs">
              <ShieldAlert className="w-3.5 h-3.5 text-slate-400 shrink-0" />
              <span className="text-slate-500 font-medium">Status:</span>
              <select
                aria-label="Status"
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
                aria-label="Time range"
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
              onClick={() => setShowCollectorExportModal(true)}
              icon={<Layers className="w-3.5 h-3.5 text-indigo-600" />}
              title="Export single collector dataset with unrolled feature columns"
            >
              Collector Dataset
            </Button>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => loadLogs(currentPage, pageSize)}
              disabled={isLoading}
              icon={<RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />}
            >
              Refresh
            </Button>
          </div>
        </div>

        {/* Filter Badges & Live Record Counter */}
        <div className="pt-2.5 border-t border-slate-100 flex items-center justify-between flex-wrap gap-2 text-xs">
          <div className="flex items-center gap-2 flex-wrap">
            {hasActiveFilters ? (
              <>
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
                    Collector: {formatCollectorLabel(activeCollector)}
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
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-purple-50 text-purple-700 border border-purple-200 font-medium">
                    Window: {timeRange}
                    <button onClick={() => setTimeRange('all')} className="hover:text-purple-900 cursor-pointer">
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
              </>
            ) : (
              <span className="text-slate-500 font-medium flex items-center gap-1.5">
                <Activity className="w-3.5 h-3.5 text-blue-500" />
                <span>All Watchers & Collectors Active ({collectorOptions.length - 1} telemetry sources available)</span>
              </span>
            )}
          </div>

          <div className="text-slate-600 font-medium flex items-center gap-1.5 bg-slate-50 border border-slate-200 px-2.5 py-1 rounded-md shadow-2xs">
            <span className="text-slate-400 font-normal">Records:</span>
            <span className="text-slate-900 font-mono font-semibold">
              {filteredLogs.length} loaded
            </span>
            <span className="text-slate-400 font-normal">/</span>
            <span className="text-blue-600 font-mono font-bold">
              {totalCount > 0 ? totalCount.toLocaleString() : (logs.length || 0)} total in database
            </span>
          </div>
        </div>
      </div>

      {/* Virtualized Table */}
      <VirtualizedLogTable
        logs={filteredLogs}
        resetKey={`${activeCollector}:${debouncedSearch}:${statusFilter}:${timeRange}:${currentPage}:${pageSize}`}
        onSelectLog={(log) => setSelectedLog(log)}
        isLoading={isLoading}
      />

      {/* Interactive Pagination Bar */}
      <div className="bg-white border border-slate-200 rounded-lg p-3.5 flex flex-wrap items-center justify-between gap-4 shadow-2xs text-xs">
        {/* Left: Rows Per Page Selector & Record Range Summary */}
        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex items-center gap-1.5 text-slate-600">
            <span className="font-medium">Rows per page:</span>
            <select
              value={pageSize}
              onChange={(e) => handlePageSizeChange(Number(e.target.value))}
              disabled={isLoading}
              className="bg-slate-50 border border-slate-200 rounded px-2.5 py-1 font-semibold text-slate-800 outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 cursor-pointer text-xs shadow-2xs"
            >
              <option value={25}>25</option>
              <option value={50}>50</option>
              <option value={100}>100</option>
              <option value={200}>200</option>
            </select>
          </div>

          <span className="text-slate-300">|</span>

          <div className="text-slate-600 font-medium">
            Showing <b className="text-slate-900 font-mono">{startItem}</b> –{' '}
            <b className="text-slate-900 font-mono">{endItem}</b> of{' '}
            <b className="text-slate-900 font-mono">
              {totalCount > 0 ? totalCount.toLocaleString() : (logs.length || 0)}
            </b>{' '}
            records
          </div>
        </div>

        {/* Right: Page Navigation Controls */}
        <div className="flex items-center gap-1">
          {/* First Page */}
          <Button
            variant="secondary"
            size="sm"
            onClick={() => handleGoToPage(1)}
            disabled={currentPage <= 1 || isLoading}
            title="First Page (Page 1)"
            className="px-2"
          >
            <ChevronsLeft className="w-4 h-4" />
          </Button>

          {/* Previous Page */}
          <Button
            variant="secondary"
            size="sm"
            onClick={() => handleGoToPage(currentPage - 1)}
            disabled={currentPage <= 1 || isLoading}
            title="Previous Page"
            className="px-2.5"
          >
            <ChevronLeft className="w-4 h-4 mr-0.5" />
            Prev
          </Button>

          {/* Page Numbers */}
          <div className="flex items-center gap-1 px-1">
            {pageNumbers.map((p, idx) => {
              if (p === '...') {
                return (
                  <span key={`dots-${idx}`} className="px-1.5 text-slate-400 select-none font-bold">
                    …
                  </span>
                );
              }
              const pageNum = p as number;
              const isActive = pageNum === currentPage;
              return (
                <button
                  key={pageNum}
                  onClick={() => handleGoToPage(pageNum)}
                  disabled={isLoading}
                  className={`min-w-8 h-8 px-2 rounded-md font-mono text-xs transition-colors cursor-pointer flex items-center justify-center ${
                    isActive
                      ? 'bg-blue-600 text-white font-semibold shadow-2xs'
                      : 'text-slate-700 hover:bg-slate-100 hover:text-slate-900 border border-slate-200/70 font-medium'
                  }`}
                >
                  {pageNum}
                </button>
              );
            })}
          </div>

          {/* Next Page */}
          <Button
            variant="secondary"
            size="sm"
            onClick={() => handleGoToPage(currentPage + 1)}
            disabled={(currentPage >= totalPages && !hasMore) || isLoading}
            title="Next Page"
            className="px-2.5"
          >
            Next
            <ChevronRight className="w-4 h-4 ml-0.5" />
          </Button>

          {/* Last Page */}
          <Button
            variant="secondary"
            size="sm"
            onClick={() => handleGoToPage(totalPages)}
            disabled={currentPage >= totalPages || isLoading}
            title={`Last Page (Page ${totalPages})`}
            className="px-2"
          >
            <ChevronsRight className="w-4 h-4" />
          </Button>
        </div>
      </div>

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

      {/* Collector-Specific Dataset Export Modal */}
      <CollectorDatasetExportModal
        isOpen={showCollectorExportModal}
        onClose={() => setShowCollectorExportModal(false)}
        defaultCollector={activeCollector !== 'all' ? activeCollector : 'logon'}
        defaultUsername={searchTerm.trim() || undefined}
      />
    </div>
  );
};
