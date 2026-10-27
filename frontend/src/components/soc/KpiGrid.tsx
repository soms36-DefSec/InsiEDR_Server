/**
 * InsiEDR Security Operations Posture Ribbon
 * ===========================================
 *
 * Replaces repetitive AI template card grids with an intentional, high-density
 * enterprise command ribbon displaying overall fleet posture, risk stratification,
 * and detection engine health.
 */

import React from 'react';
import type { DashboardSummary, SystemHealth } from '../../types/telemetry';
import { Monitor, Activity } from 'lucide-react';

export interface KpiGridProps {
  summary: DashboardSummary | null;
  health: SystemHealth | null;
  activeFilter?: string | null;
  onFilterLevel?: (level: string | null) => void;
}

export const KpiGrid: React.FC<KpiGridProps> = ({
  summary,
  health,
  activeFilter,
  onFilterLevel,
}) => {
  const pc = summary?.pc_status || { total_pcs: 0, online_pcs: 0, offline_pcs: 0 };
  const rc = summary?.risk_counts || { critical: 0, high: 0, medium: 0, low: 0 };
  const totalEvents = summary?.total_risk_events ?? summary?.stats?.risk_events ?? 0;
  const modelStatus = health?.model_pipeline || 'unknown';
  const detectionDisabled = health?.detection_pipeline_enabled === false || health?.detection_pipeline === 'disabled';
  const agentSync = health === null ? 'Unknown' :
    health.database === 'error' ? 'Degraded' :
      health.log_ingestion_enabled === false ? 'Paused' :
        health.log_ingestion_enabled === true ? 'Enabled' : 'Unknown';
  const agentSyncClass = agentSync === 'Enabled' ? 'text-emerald-700' :
    agentSync === 'Paused' ? 'text-amber-700' : 'text-rose-700';

  const totalEvaluated = (rc.critical + rc.high + rc.medium + rc.low) || (pc.total_pcs || 1);
  const critPct = Math.round((rc.critical / totalEvaluated) * 100);
  const highPct = Math.round((rc.high / totalEvaluated) * 100);
  const medPct = Math.round((rc.medium / totalEvaluated) * 100);
  const lowPct = Math.max(0, 100 - (critPct + highPct + medPct));

  // Determine overall fleet risk posture
  let postureStatus = {
    title: 'Nominal Baseline',
    desc: 'No critical threat thresholds crossed',
    color: 'text-emerald-700 bg-emerald-50 border-emerald-200/80',
    indicator: 'bg-emerald-500',
  };

  if (rc.critical > 0) {
    postureStatus = {
      title: 'Action Required',
      desc: `${rc.critical} endpoint${rc.critical > 1 ? 's' : ''} in critical risk breach`,
      color: 'text-rose-800 bg-rose-50 border-rose-200',
      indicator: 'bg-rose-600',
    };
  } else if (rc.high > 0) {
    postureStatus = {
      title: 'Elevated Threat Activity',
      desc: `${rc.high} endpoint${rc.high > 1 ? 's' : ''} exhibit severe anomaly signals`,
      color: 'text-amber-800 bg-amber-50 border-amber-200',
      indicator: 'bg-amber-500',
    };
  }

  const handleToggleFilter = (filterKey: string) => {
    if (!onFilterLevel) return;
    if (activeFilter === filterKey) {
      onFilterLevel(null);
    } else {
      onFilterLevel(filterKey);
    }
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-3.5">
      {/* 1. Overall Threat Posture & Endpoint Health (4 cols) */}
      <div className="lg:col-span-4 bg-white rounded-lg border border-slate-200/90 p-4 shadow-[0_1px_2px_rgba(0,0,0,0.03)] flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">
              Fleet Threat Posture
            </span>
            <div className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-semibold border ${postureStatus.color}`}>
              <span className={`w-1.5 h-1.5 rounded-full ${postureStatus.indicator}`} />
              {postureStatus.title}
            </div>
          </div>

          <div className="mt-3 flex items-baseline gap-3">
            <span className="text-3xl font-bold tracking-tight text-slate-900 tabular-nums">
              {pc.total_pcs}
            </span>
            <span className="text-xs text-slate-500 font-normal">
              Total Endpoints
            </span>
          </div>

          <p className="text-xs text-slate-500 mt-1 font-normal">
            {postureStatus.desc}
          </p>
        </div>

        <div className="mt-4 pt-3 border-t border-slate-100 flex items-center justify-between text-xs text-slate-600">
          <div className="flex items-center gap-2">
            <Monitor className="w-3.5 h-3.5 text-slate-400" />
            <span className="tabular-nums font-medium text-slate-800">{pc.online_pcs}</span>
            <span className="text-slate-400">Online</span>
          </div>
          <span className="text-slate-300">|</span>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-slate-300" />
            <span className="tabular-nums font-medium text-slate-800">{pc.offline_pcs}</span>
            <span className="text-slate-400">Offline</span>
          </div>
          <span className="text-slate-300">|</span>
          <div className="flex items-center gap-1.5 text-slate-500">
            <span>Ingestion:</span>
            <span className={`font-semibold ${agentSyncClass}`}>{agentSync}</span>
          </div>
          <span className="text-slate-300">|</span>
          <div className="flex items-center gap-1.5 text-slate-500">
            <span>Detection:</span>
            <span className={`font-semibold ${detectionDisabled ? 'text-indigo-600' : 'text-emerald-700'}`}>
              {detectionDisabled ? 'OFF' : 'ON'}
            </span>
          </div>
        </div>
      </div>

      {/* 2. Fleet Risk Severity Stratification & Distribution (5 cols) */}
      <div className="lg:col-span-5 bg-white rounded-lg border border-slate-200/90 p-4 shadow-[0_1px_2px_rgba(0,0,0,0.03)] flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">
              Risk Severity Breakdown
            </span>
            <span className="text-[11px] text-slate-400">
              {activeFilter ? (
                <button
                  onClick={() => onFilterLevel && onFilterLevel(null)}
                  className="text-blue-600 hover:text-blue-800 underline font-medium cursor-pointer"
                >
                  Clear filter ({activeFilter})
                </button>
              ) : (
                'Click level to filter'
              )}
            </span>
          </div>

          {/* 4 Interactive Risk Metric Blocks */}
          <div className="grid grid-cols-4 gap-2 mt-3">
            {/* Critical */}
            <div
              onClick={() => handleToggleFilter('CRITICAL')}
              className={`p-2.5 rounded-md border transition-all cursor-pointer ${
                activeFilter === 'CRITICAL'
                  ? 'bg-rose-50 border-rose-300 ring-1 ring-rose-300 shadow-2xs'
                  : 'bg-slate-50/60 border-slate-200/80 hover:bg-rose-50/40 hover:border-rose-200'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold text-rose-700 uppercase tracking-tight">Critical</span>
                <span className="text-[10px] text-slate-400 tabular-nums">≥85</span>
              </div>
              <div className="text-lg font-bold text-rose-900 mt-1 tabular-nums">
                {rc.critical}
              </div>
            </div>

            {/* High */}
            <div
              onClick={() => handleToggleFilter('HIGH')}
              className={`p-2.5 rounded-md border transition-all cursor-pointer ${
                activeFilter === 'HIGH'
                  ? 'bg-amber-50 border-amber-300 ring-1 ring-amber-300 shadow-2xs'
                  : 'bg-slate-50/60 border-slate-200/80 hover:bg-amber-50/40 hover:border-amber-200'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold text-amber-700 uppercase tracking-tight">High</span>
                <span className="text-[10px] text-slate-400 tabular-nums">60-84</span>
              </div>
              <div className="text-lg font-bold text-amber-900 mt-1 tabular-nums">
                {rc.high}
              </div>
            </div>

            {/* Medium */}
            <div
              onClick={() => handleToggleFilter('MEDIUM')}
              className={`p-2.5 rounded-md border transition-all cursor-pointer ${
                activeFilter === 'MEDIUM'
                  ? 'bg-yellow-50 border-yellow-300 ring-1 ring-yellow-300 shadow-2xs'
                  : 'bg-slate-50/60 border-slate-200/80 hover:bg-yellow-50/40 hover:border-yellow-200'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold text-yellow-800 uppercase tracking-tight">Medium</span>
                <span className="text-[10px] text-slate-400 tabular-nums">35-59</span>
              </div>
              <div className="text-lg font-bold text-yellow-950 mt-1 tabular-nums">
                {rc.medium}
              </div>
            </div>

            {/* Low / Baseline */}
            <div
              onClick={() => handleToggleFilter('LOW')}
              className={`p-2.5 rounded-md border transition-all cursor-pointer ${
                activeFilter === 'LOW'
                  ? 'bg-emerald-50 border-emerald-300 ring-1 ring-emerald-300 shadow-2xs'
                  : 'bg-slate-50/60 border-slate-200/80 hover:bg-emerald-50/40 hover:border-emerald-200'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold text-emerald-700 uppercase tracking-tight">Nominal</span>
                <span className="text-[10px] text-slate-400 tabular-nums">&lt;35</span>
              </div>
              <div className="text-lg font-bold text-emerald-900 mt-1 tabular-nums">
                {rc.low}
              </div>
            </div>
          </div>
        </div>

        {/* Proportional Segmented Risk Distribution Track */}
        <div className="mt-3 pt-2">
          <div className="h-2 w-full rounded-full bg-slate-100 flex overflow-hidden">
            {rc.critical > 0 && (
              <div
                style={{ width: `${Math.max(critPct, 5)}%` }}
                className="bg-rose-500 transition-all duration-300"
                title={`Critical: ${rc.critical} (${critPct}%)`}
              />
            )}
            {rc.high > 0 && (
              <div
                style={{ width: `${Math.max(highPct, 5)}%` }}
                className="bg-amber-500 transition-all duration-300"
                title={`High: ${rc.high} (${highPct}%)`}
              />
            )}
            {rc.medium > 0 && (
              <div
                style={{ width: `${Math.max(medPct, 5)}%` }}
                className="bg-yellow-400 transition-all duration-300"
                title={`Medium: ${rc.medium} (${medPct}%)`}
              />
            )}
            <div
              style={{ width: `${lowPct}%` }}
              className="bg-emerald-500 transition-all duration-300"
              title={`Nominal / Clean: ${rc.low} (${lowPct}%)`}
            />
          </div>
        </div>
      </div>

      {/* 3. Detection Engine & Telemetry Signals (3 cols) */}
      <div className="lg:col-span-3 bg-white rounded-lg border border-slate-200/90 p-4 shadow-[0_1px_2px_rgba(0,0,0,0.03)] flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">
              Telemetry & Engine
            </span>
            <span className={`inline-flex items-center gap-1 text-[11px] font-semibold px-2 py-0.5 rounded-full border ${
              detectionDisabled
                ? 'bg-indigo-50 text-indigo-700 border-indigo-200/80'
                : 'bg-emerald-50 text-emerald-700 border-emerald-200/80'
            }`}>
              {detectionDisabled ? 'Log Harvester Mode' : (modelStatus === 'ready' ? 'Active' : modelStatus)}
            </span>
          </div>

          <div className="mt-3">
            <div className="flex items-baseline justify-between">
              <span className="text-2xl font-bold tracking-tight text-slate-900 tabular-nums">
                {totalEvents.toLocaleString()}
              </span>
              <Activity className="w-4 h-4 text-blue-600" />
            </div>
            <div className="text-[11px] text-slate-500 mt-0.5">Retained Event Rows</div>
          </div>
        </div>

        <div className="mt-4 pt-3 border-t border-slate-100 space-y-1.5 text-[11px]">
          <div className="flex items-center justify-between text-slate-600">
            <span className="text-slate-400">Detection Status:</span>
            <span className={`font-semibold ${detectionDisabled ? 'text-indigo-600' : 'text-emerald-700'}`}>
              {detectionDisabled ? 'OFF (Scenario Mode)' : 'Active Heuristics'}
            </span>
          </div>
          <div className="flex items-center justify-between text-slate-600">
            <span className="text-slate-400">Log Export:</span>
            <span className="font-medium text-emerald-700">Ready for Scenario Mapping</span>
          </div>
        </div>
      </div>
    </div>
  );
};
