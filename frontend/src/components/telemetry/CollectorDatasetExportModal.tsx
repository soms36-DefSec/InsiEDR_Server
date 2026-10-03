/**
 * InsiEDR Collector-Specific Dataset Export Modal
 * =================================================
 *
 * Flow:
 *   Select Collector
 *         ↓
 *   Select Date / Date Range
 *         ↓
 *   Select Username
 *         ↓
 *   Preview Matching Records (with unrolled feature columns)
 *         ↓
 *   Export Dataset (CSV with dynamic feature columns)
 */

import React, { useState, useEffect, useCallback } from 'react';
import { Button } from '../ui/Button';
import {
  fetchAvailableCollectors,
  fetchCollectorPreview,
  triggerCollectorDatasetExport,
  type CollectorPreviewResponse,
} from '../../services/api';
import {
  X,
  Download,
  Calendar,
  User,
  Layers,
  Database,
  Table,
  RefreshCw,
  AlertCircle,
} from 'lucide-react';

export interface CollectorDatasetExportModalProps {
  isOpen: boolean;
  onClose: () => void;
  defaultCollector?: string;
  defaultUsername?: string;
}

export const CollectorDatasetExportModal: React.FC<CollectorDatasetExportModalProps> = ({
  isOpen,
  onClose,
  defaultCollector = 'logon',
  defaultUsername = '',
}) => {
  // Filters state
  const [selectedCollector, setSelectedCollector] = useState<string>(defaultCollector);
  const [availableCollectors, setAvailableCollectors] = useState<string[]>([]);
  const [availableUsers, setAvailableUsers] = useState<string[]>([]);

  // Date range state
  const [dateMode, setDateMode] = useState<'all' | 'today' | '7d' | '30d' | 'custom'>('all');
  const [startDate, setStartDate] = useState<string>('');
  const [endDate, setEndDate] = useState<string>('');

  // User filter state
  const [selectedUser, setSelectedUser] = useState<string>(defaultUsername);

  // Preview & Schema state
  const [previewData, setPreviewData] = useState<CollectorPreviewResponse | null>(null);
  const [isPreviewLoading, setIsPreviewLoading] = useState<boolean>(false);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [isExporting, setIsExporting] = useState<boolean>(false);

  // Initialize collectors and usernames on open
  useEffect(() => {
    if (isOpen) {
      fetchAvailableCollectors()
        .then((res) => {
          if (res.ok) {
            setAvailableCollectors(res.collectors || []);
            setAvailableUsers(res.usernames || []);
          }
        })
        .catch((err) => {
          console.warn('Failed to load collectors list:', err);
        });
    }
  }, [isOpen]);

  // Sync date range inputs based on selected mode
  useEffect(() => {
    const today = new Date().toISOString().split('T')[0];
    if (dateMode === 'today') {
      setStartDate(today);
      setEndDate(today);
    } else if (dateMode === '7d') {
      const past = new Date(Date.now() - 7 * 86400000).toISOString().split('T')[0];
      setStartDate(past);
      setEndDate(today);
    } else if (dateMode === '30d') {
      const past = new Date(Date.now() - 30 * 86400000).toISOString().split('T')[0];
      setStartDate(past);
      setEndDate(today);
    } else if (dateMode === 'all') {
      setStartDate('');
      setEndDate('');
    }
  }, [dateMode]);

  // Fetch preview matching records
  const handleLoadPreview = useCallback(async () => {
    if (!selectedCollector) return;
    setIsPreviewLoading(true);
    setPreviewError(null);

    try {
      const res = await fetchCollectorPreview({
        collector: selectedCollector,
        startDate: startDate || undefined,
        endDate: endDate || undefined,
        username: selectedUser.trim() || undefined,
        limit: 50,
      });

      if (res.ok) {
        setPreviewData(res);
      } else {
        setPreviewError('Failed to fetch preview data');
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setPreviewError(msg);
    } finally {
      setIsPreviewLoading(false);
    }
  }, [selectedCollector, startDate, endDate, selectedUser]);

  // Auto-refresh preview when collector changes
  useEffect(() => {
    if (isOpen && selectedCollector) {
      handleLoadPreview();
    }
  }, [isOpen, selectedCollector, handleLoadPreview]);

  if (!isOpen) return null;

  // Trigger CSV export download
  const handleExport = () => {
    setIsExporting(true);
    try {
      triggerCollectorDatasetExport({
        collector: selectedCollector,
        startDate: startDate || undefined,
        endDate: endDate || undefined,
        username: selectedUser.trim() || undefined,
      });
      setTimeout(() => {
        setIsExporting(false);
      }, 1000);
    } catch (err) {
      console.error('Export failed:', err);
      setIsExporting(false);
    }
  };

  // Known collectors list fallback
  const standardCollectors = [
    'logon',
    'file',
    'process',
    'network',
    'device',
    'http',
    'lsass_monitor',
    'registry',
    'keystroke-collector',
    'decoy-monitor',
    'clipboard-monitor',
    'persistence_monitor',
    'dns_monitor',
    'driver_monitor',
    'wmi_activity',
    'usn_monitor',
  ];
  const allKnownCollectors = Array.from(new Set([...standardCollectors, ...availableCollectors])).sort();

  // Generated filename preview
  const displayFilename =
    previewData?.filename ||
    `${selectedCollector || 'collector'}${startDate && endDate ? `_${startDate}_to_${endDate}` : ''}.csv`;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-xs animate-in fade-in duration-150">
      <div className="fixed inset-0" onClick={onClose} />

      <div className="relative w-full max-w-4xl bg-white border border-slate-200 rounded-xl shadow-2xl overflow-hidden z-10 text-slate-900 flex flex-col max-h-[90vh]">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-200 bg-white flex items-center justify-between shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-indigo-50 border border-indigo-100 flex items-center justify-center text-indigo-600">
              <Layers className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-semibold text-slate-900 tracking-tight flex items-center gap-2">
                Collector-Specific Dataset Export
                <span className="text-[11px] font-medium px-2 py-0.5 rounded-full bg-indigo-50 text-indigo-700 border border-indigo-100">
                  Feature Matrix
                </span>
              </h3>
              <p className="text-xs text-slate-500 mt-0.5">
                Export one collector at a time with individual features unrolled into dedicated CSV columns
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-600 p-1.5 rounded-lg hover:bg-slate-100 transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="px-6 py-5 overflow-y-auto space-y-5 text-xs">
          {/* Top Control Bar: Filters Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 p-4 rounded-lg bg-slate-50 border border-slate-200/80">
            {/* 1. Collector Selection */}
            <div className="space-y-1.5">
              <label className="font-semibold text-slate-700 flex items-center gap-1.5">
                <Layers className="w-3.5 h-3.5 text-indigo-600" />
                1. Target Collector <span className="text-red-500">*</span>
              </label>
              <select
                value={selectedCollector}
                onChange={(e) => setSelectedCollector(e.target.value)}
                className="w-full h-9 bg-white border border-slate-300 rounded-md px-3 text-xs font-medium text-slate-800 outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 cursor-pointer shadow-2xs"
              >
                {allKnownCollectors.map((col) => (
                  <option key={col} value={col}>
                    {col.toUpperCase()} {availableCollectors.includes(col) ? '●' : ''}
                  </option>
                ))}
              </select>
            </div>

            {/* 2. Date / Date Range */}
            <div className="space-y-1.5">
              <label className="font-semibold text-slate-700 flex items-center gap-1.5">
                <Calendar className="w-3.5 h-3.5 text-blue-600" />
                2. Date / Range
              </label>
              <div className="flex gap-1.5">
                <select
                  value={dateMode}
                  onChange={(e) => setDateMode(e.target.value as 'all' | 'today' | '7d' | '30d' | 'custom')}
                  className="h-9 bg-white border border-slate-300 rounded-md px-2 text-xs font-medium text-slate-800 outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 cursor-pointer shadow-2xs shrink-0"
                >
                  <option value="all">All Dates</option>
                  <option value="today">Today</option>
                  <option value="7d">Last 7d</option>
                  <option value="30d">Last 30d</option>
                  <option value="custom">Custom...</option>
                </select>

                {dateMode === 'custom' && (
                  <div className="flex items-center gap-1 flex-1 min-w-0">
                    <input
                      type="date"
                      value={startDate}
                      onChange={(e) => setStartDate(e.target.value)}
                      className="w-full h-9 bg-white border border-slate-300 rounded-md px-1.5 text-[11px] font-mono outline-none focus:border-blue-500"
                      title="Start Date"
                    />
                    <span className="text-slate-400 font-bold">-</span>
                    <input
                      type="date"
                      value={endDate}
                      onChange={(e) => setEndDate(e.target.value)}
                      className="w-full h-9 bg-white border border-slate-300 rounded-md px-1.5 text-[11px] font-mono outline-none focus:border-blue-500"
                      title="End Date"
                    />
                  </div>
                )}
              </div>
            </div>

            {/* 3. Username Filter */}
            <div className="space-y-1.5">
              <label className="font-semibold text-slate-700 flex items-center gap-1.5">
                <User className="w-3.5 h-3.5 text-emerald-600" />
                3. User Identity
              </label>
              <div className="flex gap-1.5">
                <select
                  value={selectedUser}
                  onChange={(e) => setSelectedUser(e.target.value)}
                  className="flex-1 h-9 bg-white border border-slate-300 rounded-md px-3 text-xs font-medium text-slate-800 outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500 cursor-pointer shadow-2xs"
                >
                  <option value="">All Fleet Users</option>
                  {availableUsers.map((u) => (
                    <option key={u} value={u}>
                      {u}
                    </option>
                  ))}
                </select>

                <Button
                  variant="secondary"
                  size="sm"
                  onClick={handleLoadPreview}
                  disabled={isPreviewLoading}
                  className="h-9 px-3 shrink-0"
                  icon={<RefreshCw className={`w-3.5 h-3.5 ${isPreviewLoading ? 'animate-spin' : ''}`} />}
                  title="Reload preview records with current filters"
                >
                  Preview
                </Button>
              </div>
            </div>
          </div>

          {/* Feature Schema Badge Chips */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-slate-700 flex items-center gap-1.5">
                <Database className="w-3.5 h-3.5 text-indigo-500" />
                Discovered Columns ({previewData?.columns?.length || 5}) for{' '}
                <span className="font-mono text-indigo-700 uppercase font-bold">{selectedCollector}</span>:
              </span>
              {previewData && (
                <span className="text-slate-500">
                  <b className="text-slate-900 font-mono">{previewData.total_samples}</b> sample records found
                </span>
              )}
            </div>

            {previewData?.feature_columns && previewData.feature_columns.length > 0 ? (
              <div className="flex flex-wrap gap-1.5 max-h-24 overflow-y-auto p-2.5 rounded-lg bg-slate-50 border border-slate-200">
                <span className="px-2 py-0.5 rounded bg-slate-200 text-slate-700 font-mono text-[10px] font-semibold">
                  timestamp
                </span>
                <span className="px-2 py-0.5 rounded bg-slate-200 text-slate-700 font-mono text-[10px] font-semibold">
                  username
                </span>
                <span className="px-2 py-0.5 rounded bg-slate-200 text-slate-700 font-mono text-[10px] font-semibold">
                  hostname
                </span>
                <span className="px-2 py-0.5 rounded bg-slate-200 text-slate-700 font-mono text-[10px] font-semibold">
                  status
                </span>
                {previewData.feature_columns.map((col) => (
                  <span
                    key={col}
                    className="px-2 py-0.5 rounded bg-indigo-50 text-indigo-700 border border-indigo-100 font-mono text-[10px] font-medium"
                  >
                    {col}
                  </span>
                ))}
              </div>
            ) : (
              <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 text-slate-500 italic flex items-center gap-2">
                <AlertCircle className="w-3.5 h-3.5 text-slate-400" />
                {isPreviewLoading
                  ? 'Analyzing collector feature schema...'
                  : 'No feature columns discovered yet. Click "Preview" to inspect records.'}
              </div>
            )}
          </div>

          {/* Preview Table */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-slate-700 flex items-center gap-1.5">
                <Table className="w-3.5 h-3.5 text-slate-500" />
                Preview Records (First 50 Rows)
              </span>
              {previewError && <span className="text-rose-600 font-medium">{previewError}</span>}
            </div>

            <div className="border border-slate-200 rounded-lg overflow-hidden bg-white shadow-2xs max-h-60 overflow-x-auto overflow-y-auto">
              {previewData?.preview_rows && previewData.preview_rows.length > 0 ? (
                <table className="w-full text-left border-collapse text-[11px]">
                  <thead className="bg-slate-50 border-b border-slate-200 sticky top-0 z-10">
                    <tr>
                      {previewData.columns.map((col) => (
                        <th
                          key={col}
                          className="px-3 py-2 font-mono font-semibold text-slate-700 whitespace-nowrap bg-slate-50"
                        >
                          {col}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {previewData.preview_rows.map((row, idx) => (
                      <tr key={idx} className="hover:bg-slate-50/70 transition-colors">
                        {previewData.columns.map((col) => {
                          const val = row[col];
                          const displayVal =
                            typeof val === 'boolean'
                              ? String(val)
                              : typeof val === 'number'
                              ? val
                              : val === null || val === undefined || val === ''
                              ? '-'
                              : String(val);
                          return (
                            <td
                              key={col}
                              className={`px-3 py-1.5 font-mono whitespace-nowrap ${
                                typeof val === 'number'
                                  ? 'text-right text-blue-700 font-medium'
                                  : typeof val === 'boolean'
                                  ? 'text-emerald-700 font-semibold'
                                  : 'text-slate-800'
                              }`}
                            >
                              {displayVal}
                            </td>
                          );
                        })}
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <div className="p-8 text-center text-slate-400 space-y-2">
                  <Database className="w-8 h-8 mx-auto text-slate-300" />
                  <p className="text-slate-500 font-medium">No records found matching current filters</p>
                  <p className="text-slate-400 text-[11px]">
                    Try selecting a different date range or verifying that the collector is active.
                  </p>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-3.5 border-t border-slate-200 bg-slate-50 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2 text-slate-500 font-mono text-[11px]">
            <span className="font-semibold text-slate-700">Filename:</span>
            <span className="px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-800">
              {displayFilename}
            </span>
          </div>

          <div className="flex items-center gap-2">
            <Button variant="secondary" size="sm" onClick={onClose}>
              Cancel
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={handleExport}
              disabled={isExporting}
              icon={<Download className="w-3.5 h-3.5" />}
              className="bg-indigo-600 hover:bg-indigo-700 text-white"
            >
              {isExporting ? 'Exporting CSV...' : 'Export Dataset (CSV)'}
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
};
