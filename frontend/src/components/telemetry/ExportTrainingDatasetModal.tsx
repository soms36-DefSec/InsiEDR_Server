/**
 * InsiEDR ML Training Dataset Export Modal
 * =========================================
 *
 * Architectural Role:
 *   Provides an intuitive dialog for exporting telemetry datasets specifically
 *   curated for training and fine-tuning machine learning models (Domain Isolation Forest,
 *   Scenario XGBoost, and RedRVFL sequence models).
 *
 * Options:
 *   1. Target User: Filter by specific username or export all users across the fleet.
 *   2. Time Horizon (N Days): Rolling historical time window (e.g., 7d, 14d, 30d, 90d, or custom).
 *   3. Format: Native Excel spreadsheet (.xlsx with multi-tab feature matrix), CSV, or NDJSON.
 *   4. Content Guarantee: User - Parameters (Extracted Features) - Raw Logs.
 */

import React, { useState } from 'react';
import { Button } from '../ui/Button';
import { triggerTrainingDatasetExport } from '../../services/api';
import {
  X,
  Download,
  FileSpreadsheet,
  FileText,
  FileCode,
  Calendar,
  User,
  Layers,
  Database,
  CheckCircle2,
  Cpu,
} from 'lucide-react';

export interface ExportTrainingDatasetModalProps {
  isOpen: boolean;
  onClose: () => void;
  availableUsers?: string[];
  defaultUsername?: string;
}

export const ExportTrainingDatasetModal: React.FC<ExportTrainingDatasetModalProps> = ({
  isOpen,
  onClose,
  availableUsers = [],
  defaultUsername = '',
}) => {
  const [selectedUser, setSelectedUser] = useState<string>(defaultUsername);
  const [days, setDays] = useState<number>(30);
  const [format, setFormat] = useState<'xlsx' | 'csv' | 'json'>('xlsx');
  const [limit, setLimit] = useState<number>(10000);
  const [isExporting, setIsExporting] = useState<boolean>(false);

  if (!isOpen) return null;

  const quickDays = [7, 14, 30, 60, 90, 180];

  const handleExport = () => {
    setIsExporting(true);
    try {
      triggerTrainingDatasetExport({
        username: selectedUser.trim() || undefined,
        days: days > 0 ? days : 30,
        format,
        limit,
      });
      setTimeout(() => {
        setIsExporting(false);
        onClose();
      }, 800);
    } catch (err) {
      console.error('Failed to trigger dataset export:', err);
      setIsExporting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/30 select-none animate-in fade-in duration-150">
      <div
        className="fixed inset-0"
        onClick={onClose}
      />

      <div className="relative w-full max-w-xl bg-white border border-slate-200 rounded-xl shadow-xl overflow-hidden z-10 text-slate-900">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-200 bg-white flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-blue-50 border border-blue-100 flex items-center justify-center text-blue-600">
              <Database className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-base font-semibold text-slate-900 tracking-tight">
                Export ML Model Training Dataset
              </h3>
              <p className="text-xs text-slate-500 mt-0.5">
                Collect User, Parameters, and Raw Logs for training InsiEDR ML models
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-md text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors cursor-pointer"
            aria-label="Close dialog"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-5 max-h-[80vh] overflow-y-auto">
          {/* 1. Target User Filter */}
          <div>
            <label className="block text-xs font-medium text-slate-700 mb-1.5 flex items-center gap-1.5">
              <User className="w-3.5 h-3.5 text-slate-400" />
              Target User (Optional)
            </label>
            <div className="space-y-2">
              <div className="flex gap-2">
                <input
                  type="text"
                  value={selectedUser}
                  onChange={(e) => setSelectedUser(e.target.value)}
                  placeholder="Enter username (e.g., alice) or leave blank for All Users"
                  className="flex-1 bg-white border border-slate-200 rounded-md px-3 h-[38px] text-xs text-slate-900 placeholder-slate-400 focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 shadow-2xs"
                />
                {selectedUser && (
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setSelectedUser('')}
                    className="text-xs text-slate-500 hover:text-slate-900"
                  >
                    Clear
                  </Button>
                )}
              </div>

              {availableUsers.length > 0 && (
                <div className="flex items-center gap-1.5 flex-wrap pt-1">
                  <span className="text-xs text-slate-500">Fleet Users:</span>
                  <button
                    type="button"
                    onClick={() => setSelectedUser('')}
                    className={`px-2.5 py-1 text-xs rounded-md transition-colors cursor-pointer ${
                      !selectedUser
                        ? 'bg-blue-600 text-white font-medium shadow-2xs'
                        : 'bg-slate-50 text-slate-600 hover:bg-slate-100 border border-slate-200'
                    }`}
                  >
                    All Users
                  </button>
                  {availableUsers.slice(0, 6).map((u) => (
                    <button
                      key={u}
                      type="button"
                      onClick={() => setSelectedUser(u)}
                      className={`px-2.5 py-1 text-xs rounded-md transition-colors cursor-pointer ${
                        selectedUser === u
                          ? 'bg-blue-600 text-white font-medium shadow-2xs'
                          : 'bg-slate-50 text-slate-600 hover:bg-slate-100 border border-slate-200'
                      }`}
                    >
                      {u}
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* 2. Rolling Time Window (N Days) */}
          <div>
            <label className="block text-xs font-medium text-slate-700 mb-1.5 flex items-center gap-1.5">
              <Calendar className="w-3.5 h-3.5 text-slate-400" />
              History Window (N Days)
            </label>
            <div className="flex items-center gap-2 flex-wrap mb-2.5">
              {quickDays.map((d) => (
                <button
                  key={d}
                  type="button"
                  onClick={() => setDays(d)}
                  className={`px-3 py-1.5 rounded-md text-xs font-medium border transition-colors cursor-pointer ${
                    days === d
                      ? 'bg-blue-600 text-white border-blue-600 shadow-2xs'
                      : 'bg-white text-slate-700 border-slate-200 hover:bg-slate-50'
                  }`}
                >
                  {d} Days
                </button>
              ))}
            </div>
            <div className="flex items-center gap-3">
              <span className="text-xs text-slate-500">Custom Days:</span>
              <input
                type="number"
                min="1"
                max="365"
                value={days}
                onChange={(e) => setDays(Math.max(1, Math.min(365, parseInt(e.target.value) || 1)))}
                className="w-20 bg-white border border-slate-200 rounded-md px-2.5 h-[34px] text-xs text-slate-900 text-center focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 shadow-2xs"
              />
              <span className="text-xs text-slate-400">Extracts telemetry collected in the past {days} days.</span>
            </div>
          </div>

          {/* 3. Export Format Selection */}
          <div>
            <label className="block text-xs font-medium text-slate-700 mb-1.5 flex items-center gap-1.5">
              <Layers className="w-3.5 h-3.5 text-slate-400" />
              Dataset Format
            </label>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
              {/* Excel Card */}
              <button
                type="button"
                onClick={() => setFormat('xlsx')}
                className={`p-3.5 rounded-lg border text-left transition-all cursor-pointer flex flex-col justify-between ${
                  format === 'xlsx'
                    ? 'bg-blue-50/50 border-blue-500 ring-1 ring-blue-500/30'
                    : 'bg-white border-slate-200 hover:border-slate-300'
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <FileSpreadsheet className="w-4 h-4 text-emerald-600" />
                  {format === 'xlsx' && <CheckCircle2 className="w-4 h-4 text-blue-600" />}
                </div>
                <div>
                  <div className="text-xs font-semibold text-slate-900">Excel Sheet (.xlsx)</div>
                  <div className="text-[11px] text-slate-500 mt-0.5 leading-snug">
                    Includes Overview & Exploded Feature Matrix sheets
                  </div>
                </div>
              </button>

              {/* CSV Card */}
              <button
                type="button"
                onClick={() => setFormat('csv')}
                className={`p-3.5 rounded-lg border text-left transition-all cursor-pointer flex flex-col justify-between ${
                  format === 'csv'
                    ? 'bg-blue-50/50 border-blue-500 ring-1 ring-blue-500/30'
                    : 'bg-white border-slate-200 hover:border-slate-300'
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <FileText className="w-4 h-4 text-blue-600" />
                  {format === 'csv' && <CheckCircle2 className="w-4 h-4 text-blue-600" />}
                </div>
                <div>
                  <div className="text-xs font-semibold text-slate-900">CSV Stream (.csv)</div>
                  <div className="text-[11px] text-slate-500 mt-0.5 leading-snug">
                    Standard tabular format with User, Parameters & Raw Logs
                  </div>
                </div>
              </button>

              {/* NDJSON Card */}
              <button
                type="button"
                onClick={() => setFormat('json')}
                className={`p-3.5 rounded-lg border text-left transition-all cursor-pointer flex flex-col justify-between ${
                  format === 'json'
                    ? 'bg-blue-50/50 border-blue-500 ring-1 ring-blue-500/30'
                    : 'bg-white border-slate-200 hover:border-slate-300'
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <FileCode className="w-4 h-4 text-amber-600" />
                  {format === 'json' && <CheckCircle2 className="w-4 h-4 text-blue-600" />}
                </div>
                <div>
                  <div className="text-xs font-semibold text-slate-900">NDJSON (.jsonl)</div>
                  <div className="text-[11px] text-slate-500 mt-0.5 leading-snug">
                    Line-delimited JSON objects for pipeline streaming
                  </div>
                </div>
              </button>
            </div>
          </div>

          {/* 4. Sample Limit */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="text-xs font-medium text-slate-700">
                Sample Record Limit
              </label>
              <span className="text-xs text-blue-600 font-mono font-medium">{limit.toLocaleString()} rows</span>
            </div>
            <select
              value={limit}
              onChange={(e) => setLimit(parseInt(e.target.value) || 10000)}
              className="w-full bg-white border border-slate-200 rounded-md px-3 h-[38px] text-xs text-slate-800 focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 cursor-pointer shadow-2xs"
            >
              <option value={5000}>5,000 Samples</option>
              <option value={10000}>10,000 Samples (Recommended)</option>
              <option value={25000}>25,000 Samples</option>
              <option value={50000}>50,000 Samples</option>
              <option value={100000}>100,000 Samples (Full Batch)</option>
            </select>
          </div>

          {/* Information & Column Preview Callout */}
          <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-700 space-y-2">
            <div className="flex items-center gap-1.5 text-blue-700 font-semibold text-xs">
              <Cpu className="w-3.5 h-3.5" />
              Machine Learning Dataset Guarantee
            </div>
            <p className="text-xs text-slate-600 leading-relaxed">
              Export is structured for training InsiEDR G-Models (Domain Isolation Forest, Scenario XGBoost, and RedRVFL).
              Contains:
            </p>
            <div className="flex items-center gap-1.5 flex-wrap">
              <span className="px-2 py-0.5 rounded bg-white text-slate-700 border border-slate-200 text-[11px] font-mono">
                User
              </span>
              <span className="text-slate-400">•</span>
              <span className="px-2 py-0.5 rounded bg-white text-slate-700 border border-slate-200 text-[11px] font-mono">
                Parameters (Features)
              </span>
              <span className="text-slate-400">•</span>
              <span className="px-2 py-0.5 rounded bg-white text-slate-700 border border-slate-200 text-[11px] font-mono">
                Raw Telemetry Logs
              </span>
              <span className="text-slate-400">•</span>
              <span className="px-2 py-0.5 rounded bg-white text-slate-700 border border-slate-200 text-[11px] font-mono">
                Collected At
              </span>
              <span className="text-slate-400">•</span>
              <span className="px-2 py-0.5 rounded bg-white text-slate-700 border border-slate-200 text-[11px] font-mono">
                Hostname
              </span>
            </div>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-4 border-t border-slate-200 bg-slate-50/80 flex items-center justify-between gap-3">
          <Button
            variant="secondary"
            size="sm"
            onClick={onClose}
          >
            Cancel
          </Button>

          <Button
            variant="primary"
            size="sm"
            onClick={handleExport}
            disabled={isExporting}
            isLoading={isExporting}
            icon={<Download className="w-3.5 h-3.5" />}
          >
            <span>Download Dataset ({format.toUpperCase()})</span>
          </Button>
        </div>
      </div>
    </div>
  );
};
