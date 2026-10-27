/**
 * InsiEDR Top Navigation Bar
 * ==========================
 *
 * Professional, human-crafted command header providing:
 * - Brand identity with subtle security monogram
 * - Contextual security plugin tabs with live severity badges
 * - Fleet endpoint inventory overview
 * - Live real-time connection status
 * - Consolidated operations & forensic export menu
 */

import React, { useState } from 'react';
import type { EDRPlugin, PluginContextData } from '../../plugins/registry';
import { Button } from '../ui/Button';
import {
  RefreshCw,
  Download,
  ChevronDown,
  FileCode,
  Layers,
  Shield,
  ShieldAlert,
  FileSpreadsheet,
} from 'lucide-react';
import { triggerServerExport, exportFleetRiskCSV } from '../../services/api';
import { CollectorDatasetExportModal } from '../telemetry/CollectorDatasetExportModal';
import type { EndpointRow, RiskEvent } from '../../types/telemetry';
import { getRiskLevel, THREAT_DECAY_WINDOW_MS } from '../../utils/formatters';

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
  const [showCollectorModal, setShowCollectorModal] = useState(false);

  const summary = context.summary;

  const handleRefresh = async () => {
    setIsRefreshing(true);
    try {
      await onRefresh();
    } finally {
      setTimeout(() => setIsRefreshing(false), 400);
    }
  };

  const handleExportFleetRisk = () => {
    if (!summary?.agents) return;
    const now = Date.now();
    const hostRiskMap: Record<string, RiskEvent> = {};
    const agentRiskMap: Record<string, RiskEvent> = {};
    (summary.risk_events || []).forEach((ev) => {
      if (ev.hostname && !hostRiskMap[ev.hostname]) hostRiskMap[ev.hostname] = ev;
      if (ev.agent_id && !agentRiskMap[ev.agent_id]) agentRiskMap[ev.agent_id] = ev;
    });

    const rows: EndpointRow[] = summary.agents.filter((agent) => !agent.is_test).map((agent) => {
      const hostname = agent.hostname || '—';
      const user = agent.username_last_seen || '—';
      const agentId = agent.agent_id || `${hostname}_${user}`;
      const risk = agent.agent_id ? agentRiskMap[agent.agent_id] : hostRiskMap[hostname];
      const historicalScore = risk ? parseFloat(String(risk.risk_score || 0)) : undefined;
      const eventAge = risk ? now - new Date(risk.created_at).getTime() : Infinity;
      const isActive = risk?.is_active ?? (eventAge >= -120000 && eventAge <= THREAT_DECAY_WINDOW_MS);
      const score = isActive ? historicalScore || 0 : 0;
      const isOnline =
        agent.status === 'active' ||
        (agent.last_seen_at && now - new Date(agent.last_seen_at).getTime() < 300000);

      return {
        agentId,
        hostname,
        user,
        score,
        level: getRiskLevel(score),
        isDecayed: Boolean(risk && !isActive),
        historicalScore,
        isTest: false,
        scenarios: [],
        lastSeen: agent.last_seen_at,
        isOnline: Boolean(isOnline),
      };
    });

    exportFleetRiskCSV(rows);
    setShowExportMenu(false);
  };

  return (
    <nav className="bg-white text-slate-800 border-b border-slate-200/90 sticky top-0 z-40 select-none shadow-[0_1px_2px_rgba(0,0,0,0.03)]">
      <div className="max-w-[1700px] mx-auto px-4 sm:px-6 lg:px-8 min-h-14 py-2 sm:py-0 flex flex-wrap sm:flex-nowrap items-center justify-between gap-3">
        {/* Brand & Identity */}
        <div className="flex items-center gap-3 shrink-0">
          <div className="w-7 h-7 rounded-md bg-slate-900 flex items-center justify-center text-white font-bold text-xs tracking-tight shadow-xs border border-slate-800">
            <Shield className="w-4 h-4 text-slate-100" />
          </div>
          <div>
            <div className="flex items-center gap-1.5">
              <span className="text-sm font-bold text-slate-900 tracking-tight">InsiEDR</span>
              <span className="text-[10px] font-semibold text-slate-500 bg-slate-100 px-1.5 py-0.2 rounded border border-slate-200">
                v2.1
              </span>
            </div>
            <div className="text-[10px] text-slate-500 font-normal leading-none mt-0.5 hidden sm:block">
              Threat Operations & Telemetry Console
            </div>
          </div>
        </div>

        {/* Operational Navigation Tabs */}
        <div role="tablist" aria-label="Security Modules" className="flex items-center gap-1 overflow-x-auto py-1 scrollbar-none order-last sm:order-none w-full sm:w-auto">
          {plugins.map((plugin) => {
            const isActive = plugin.id === activePluginId;
            const Icon = plugin.icon;
            const badgeVal = plugin.badge ? plugin.badge(context) : null;

            return (
              <button
                key={plugin.id}
                role="tab"
                aria-selected={isActive}
                onClick={() => onSelectPlugin(plugin.id)}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs transition-all cursor-pointer whitespace-nowrap ${
                  isActive
                    ? 'bg-slate-900 text-white font-medium shadow-xs'
                    : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900 font-normal'
                }`}
              >
                <Icon
                  className={`w-3.5 h-3.5 ${isActive ? 'text-white' : 'text-slate-400'}`}
                />
                <span>{plugin.name}</span>
                {badgeVal !== null && badgeVal !== undefined && (
                  <span
                    className={`text-[10px] px-1.5 py-0.2 rounded-full font-bold tabular-nums ${
                      isActive
                        ? 'bg-rose-500 text-white'
                        : 'bg-rose-50 text-rose-700 border border-rose-200'
                    }`}
                  >
                    {badgeVal}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* Right Controls: Real-time Toggle & Export Menu */}
        <div className="flex items-center gap-2.5 shrink-0">
          {/* Real-time Ingestion Pipeline Toggle */}
          <div
            className={`flex items-center gap-2 px-2.5 py-1 rounded-md border text-xs transition-colors shadow-2xs ${
              autoRefresh
                ? 'bg-emerald-50/70 border-emerald-200 text-emerald-900'
                : 'bg-slate-100 border-slate-200 text-slate-600'
            }`}
            title={
              autoRefresh
                ? (connectionMode === 'sse' ? 'Pipeline actively receiving telemetry via live stream. Click Pause to stop.' : 'Pipeline actively polling telemetry. Click Pause to stop.')
                : 'Pipeline stopped. Click Resume to start receiving telemetry.'
            }
          >
            <span className="relative flex h-2 w-2 shrink-0">
              {autoRefresh && (
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
              )}
              <span
                className={`relative inline-flex rounded-full h-2 w-2 ${
                  autoRefresh ? 'bg-emerald-500' : 'bg-slate-400'
                }`}
              />
            </span>
            <span className="text-[11px] font-medium hidden sm:inline">
              {autoRefresh ? (connectionMode === 'sse' ? 'Pipeline: Receiving' : 'Polling: Receiving') : 'Pipeline: Stopped'}
            </span>
            <button
              type="button"
              role="button"
              onClick={onToggleAutoRefresh}
              className={`text-[11px] font-semibold px-2 py-0.5 rounded transition-all cursor-pointer ${
                autoRefresh
                  ? 'bg-white hover:bg-emerald-100 text-emerald-800 border border-emerald-300 shadow-2xs'
                  : 'bg-white hover:bg-slate-200 text-slate-700 border border-slate-300 shadow-2xs'
              }`}
            >
              {autoRefresh ? 'Pause' : 'Resume'}
            </button>
          </div>

          {/* Refresh Button */}
          <button
            onClick={handleRefresh}
            disabled={isRefreshing}
            className="p-1.5 rounded-md bg-white hover:bg-slate-50 text-slate-600 hover:text-slate-900 border border-slate-200 shadow-2xs transition-colors cursor-pointer disabled:opacity-50"
            title="Refresh current state"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
          </button>

          {/* Export Dropdown */}
          <div className="relative">
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setShowExportMenu((prev) => !prev)}
              icon={<Download className="w-3.5 h-3.5 text-slate-500" />}
              className="flex items-center gap-1.5 text-slate-800 font-medium"
            >
              <span>Export</span>
              <ChevronDown className="w-3 h-3 text-slate-400" />
            </Button>

            {showExportMenu && (
              <>
                <div
                  className="fixed inset-0 z-40"
                  onClick={() => setShowExportMenu(false)}
                />
                <div className="absolute right-0 mt-2 w-72 bg-white border border-slate-200 rounded-lg shadow-lg z-50 py-1.5 text-xs">
                  {/* Forensic Collector Datasets Section */}
                  <div className="px-3 py-1 text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                    Forensic Datasets
                  </div>
                  <button
                    onClick={() => {
                      setShowCollectorModal(true);
                      setShowExportMenu(false);
                    }}
                    className="w-full text-left px-3 py-2 text-slate-800 hover:bg-slate-50 flex items-center gap-2.5 transition-colors cursor-pointer border-b border-slate-100"
                  >
                    <Layers className="w-4 h-4 text-indigo-600 shrink-0" />
                    <div>
                      <div className="font-semibold text-slate-900 text-xs flex items-center gap-1.5">
                        Collector Dataset Export
                        <span className="text-[9px] bg-slate-100 text-slate-700 font-bold px-1.5 py-0.2 rounded-full border border-slate-200">
                          500k+
                        </span>
                      </div>
                      <div className="text-[10px] text-slate-500">Unrolled feature columns per collector</div>
                    </div>
                  </button>

                  {/* Security Telemetry Section */}
                  <div className="px-3 py-1 text-[10px] font-semibold uppercase tracking-wider text-slate-400 mt-1">
                    Security Operations
                  </div>
                  <button
                    onClick={() => {
                      triggerServerExport('threats', 'csv');
                      setShowExportMenu(false);
                    }}
                    className="w-full text-left px-3 py-1.5 text-slate-700 hover:bg-slate-50 hover:text-slate-900 flex items-center gap-2 transition-colors cursor-pointer"
                  >
                    <ShieldAlert className="w-3.5 h-3.5 text-rose-600 shrink-0" />
                    <span>Export Threat Events (CSV)</span>
                  </button>

                  <button
                    onClick={handleExportFleetRisk}
                    className="w-full text-left px-3 py-1.5 text-slate-700 hover:bg-slate-50 hover:text-slate-900 flex items-center gap-2 transition-colors cursor-pointer border-b border-slate-100"
                  >
                    <FileSpreadsheet className="w-3.5 h-3.5 text-amber-600 shrink-0" />
                    <span>Export Fleet Risk Matrix (CSV)</span>
                  </button>

                  {/* Raw Stream Section */}
                  <div className="px-3 py-1 text-[10px] font-semibold uppercase tracking-wider text-slate-400 mt-1">
                    Raw Telemetry Streams
                  </div>
                  <button
                    onClick={() => {
                      triggerServerExport('logs', 'csv');
                      setShowExportMenu(false);
                    }}
                    className="w-full text-left px-3 py-1.5 text-slate-700 hover:bg-slate-50 hover:text-slate-900 flex items-center gap-2 transition-colors cursor-pointer"
                  >
                    <Download className="w-3.5 h-3.5 text-slate-600 shrink-0" />
                    <span>Stream All Logs (CSV)</span>
                  </button>
                  <button
                    onClick={() => {
                      triggerServerExport('logs', 'json');
                      setShowExportMenu(false);
                    }}
                    className="w-full text-left px-3 py-1.5 text-slate-700 hover:bg-slate-50 hover:text-slate-900 flex items-center gap-2 transition-colors cursor-pointer"
                  >
                    <FileCode className="w-3.5 h-3.5 text-slate-600 shrink-0" />
                    <span>Stream Logs (NDJSON)</span>
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      </div>

      {/* Collector-Specific Dataset Export Modal */}
      <CollectorDatasetExportModal
        isOpen={showCollectorModal}
        onClose={() => setShowCollectorModal(false)}
      />
    </nav>
  );
};
