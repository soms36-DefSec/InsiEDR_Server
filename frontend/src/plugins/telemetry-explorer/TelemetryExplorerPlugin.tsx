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
import { CollectorDatasetExportModal } from '../../components/telemetry/CollectorDatasetExportModal';
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
  Layers,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
} from 'lucide-react';

export const TelemetryExplorerPlugin: React.FC<PluginProps> = ({ context }) => {
  const [logs, setLogs] = useState<TelemetryLog[]>(context.logs || []);
  const [selectedLog, setSelectedLog] = useState<TelemetryLog | null>(null);
  const [showTrainingModal, setShowTrainingModal] = useState<boolean>(false);
  const [showCollectorExportModal, setShowCollectorExportModal] = useState<boolean>(false);

  // Filters State
  const [searchTerm, setSearchTerm] = useState('');
  const [activeCollector, setActiveCollector] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [timeRange, setTimeRange] = useState<string>('all');

  // Pagination State
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(50);
  const [totalCount, setTotalCount] = useState<number>(0);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [hasMore, setHasMore] = useState<boolean>(true);

  const loadLogs = useCallback(
    async (pageToLoad = 1, currentSize = pageSize) => {
      setIsLoading(true);
      try {
        const collectorParam = activeCollector !== 'all' ? activeCollector : null;
        const searchParam = searchTerm.trim() ? searchTerm.trim() : null;
        const newOffset = (pageToLoad - 1) * currentSize;

        const res = await fetchTelemetry(
          currentSize,
          newOffset,
          collectorParam,
          searchParam
        );
        const fetched = res.logs || [];
        setLogs(fetched);
        setCurrentPage(pageToLoad);
        setHasMore(fetched.length === currentSize);
        if (typeof res.total === 'number') {
          setTotalCount(res.total);
        } else {
          setTotalCount(newOffset + fetched.length + (fetched.length === currentSize ? currentSize : 0));
        }
      } catch (err) {
        console.error('Failed to load telemetry logs:', err);
      } finally {
        setIsLoading(false);
      }
    },
    [activeCollector, searchTerm, pageSize]
  );

  useEffect(() => {
    loadLogs(1, pageSize);
  }, [loadLogs]);

  const totalPages = Math.max(1, Math.ceil((totalCount || logs.length) / pageSize));

  const handlePageSizeChange = (newSize: number) => {
    setPageSize(newSize);
    loadLogs(1, newSize);
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
