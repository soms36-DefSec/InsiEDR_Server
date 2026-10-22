/**
 * InsiEDR SOC Threat Matrix
 * =========================
 *
 * Operational Command View for Security Analysts:
 *   1. Security Posture Ribbon (Fleet posture, risk stratification, detection engine health)
 *   2. Telemetry Ingestion Histogram (Live event volume, frequency spikes, rolling windows)
 *   3. Real-Time Threat Stream & Behavioral Attack Surface Charts
 *   4. Endpoint Fleet Risk Matrix with threat decay and forensic investigation drawer
 */

import React, { useState } from 'react';
import type { PluginProps } from '../registry';
import { KpiGrid } from '../../components/soc/KpiGrid';
import { ThreatFeed } from '../../components/soc/ThreatFeed';
import { ChartsSection } from '../../components/soc/ChartsSection';
import { UserRiskTable } from '../../components/soc/UserRiskTable';
import { DrillDownDrawer } from '../../components/soc/DrillDownDrawer';
import { TelemetryHistogram } from '../../components/telemetry/TelemetryHistogram';
import { Card } from '../../components/ui/Card';
import { Download, BarChart3 } from 'lucide-react';
import { triggerServerExport } from '../../services/api';

export const SocMatrixPlugin: React.FC<PluginProps> = ({ context }) => {
  const { summary, health, onOpenDrillDown, autoRefresh } = context;
  const [drillUser, setDrillUser] = useState<string | null>(null);
  const [drillHostname, setDrillHostname] = useState<string | null>(null);
  const [filterLevel, setFilterLevel] = useState<string | null>(null);
  const [timeRange, setTimeRange] = useState<string>('1h');
  const [historyStart, setHistoryStart] = useState(() => new Date(Date.now() - 30 * 86400000).toISOString().slice(0, 10));
  const [historyEnd, setHistoryEnd] = useState(() => new Date(Date.now() - 86400000).toISOString().slice(0, 10));

  const handleSelectEndpoint = (user: string, host?: string) => {
    setDrillUser(user);
    setDrillHostname(host || null);
    if (onOpenDrillDown) onOpenDrillDown(user, host);
  };

  const handleCloseDrillDown = () => {
    setDrillUser(null);
    setDrillHostname(null);
  };

  const timeRanges = [
    { key: '15m', label: '15m' },
    { key: '1h', label: '1h' },
    { key: '24h', label: '24h' },
    { key: '7d', label: '7d' },
    { key: 'custom', label: 'UTC dates' },
  ];

  return (
    <div className="space-y-5">
      {/* 1. Security Operations Posture Ribbon */}
      <KpiGrid
        summary={summary}
        health={health}
        activeFilter={filterLevel}
        onFilterLevel={setFilterLevel}
      />

      {/* 2. Real-Time Telemetry Ingestion Histogram */}
      <Card
        title={
          <div className="flex items-center gap-2">
            <BarChart3 className="w-4 h-4 text-blue-600" />
            <span className="font-semibold text-slate-900 text-sm">
              Telemetry Ingestion Velocity & Event Histogram
            </span>
          </div>
        }
        subtitle="Chronological frequency and ingestion rate of raw endpoint telemetry"
        action={
          <div className="flex flex-wrap items-center gap-2">
            {/* Time Range Selector */}
            <div className="flex items-center bg-slate-100 p-0.5 rounded-md border border-slate-200/80">
              {timeRanges.map((r) => (
                <button
                  key={r.key}
                  onClick={() => setTimeRange(r.key)}
                  className={`px-2 py-0.5 text-xs font-medium rounded transition-colors cursor-pointer ${
                    timeRange === r.key
                      ? 'bg-white text-slate-900 shadow-2xs'
                      : 'text-slate-500 hover:text-slate-900'
                  }`}
                >
                  {r.label}
                </button>
              ))}
            </div>
            {timeRange === 'custom' && <div className="flex items-center gap-1 text-xs">
              <input aria-label="History start date UTC" type="date" value={historyStart}
                onChange={(event) => setHistoryStart(event.target.value)} className="rounded border px-1 py-0.5" />
              <span>to</span>
              <input aria-label="History end date UTC" type="date" value={historyEnd}
                onChange={(event) => setHistoryEnd(event.target.value)} className="rounded border px-1 py-0.5" />
            </div>}
          </div>
        }
      >
        <TelemetryHistogram
          timeRange={timeRange}
          startTime={timeRange === 'custom' && historyStart ? `${historyStart}T00:00:00Z` : undefined}
          endTime={timeRange === 'custom' && historyEnd
            ? new Date(Date.parse(`${historyEnd}T00:00:00Z`) + 86400000).toISOString() : undefined}
          autoRefresh={autoRefresh}
        />
      </Card>

      {/* 3. Operational Grid: Live Threat Feed & Attack Surface Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Real-time Live Threat Detection Stream */}
        <div className="lg:col-span-1">
          <Card
            title={
              <div className="flex items-center justify-between w-full">
                <span>Threat Detection Stream</span>
              </div>
            }
            subtitle="Heuristic triggers and correlated anomalies in real time"
            action={
              <button
                onClick={() => triggerServerExport('threats', 'csv')}
                className="flex items-center gap-1 px-2 py-1 text-[11px] font-semibold text-slate-700 hover:text-slate-900 bg-slate-100 hover:bg-slate-200/80 rounded border border-slate-200/80 transition-colors cursor-pointer"
                title="Stream all correlated threat detections to CSV"
              >
                <Download className="w-3 h-3 text-slate-500" />
                <span>Export Threats</span>
              </button>
            }
          >
            <ThreatFeed
              events={summary?.risk_events || []}
              onSelectThreat={handleSelectEndpoint}
            />
          </Card>
        </div>

        {/* Security Visualizations: Domain Vectors, Severity Donut & Velocity Timeline */}
        <div className="lg:col-span-2">
          <ChartsSection
            riskCounts={summary?.risk_counts || null}
            riskEvents={summary?.risk_events || []}
          />
        </div>
      </div>

      {/* 4. Endpoint Fleet Risk Matrix */}
      <UserRiskTable
        agents={summary?.agents || []}
        riskEvents={summary?.risk_events || []}
        selectedUser={drillUser}
        selectedHostname={drillHostname}
        filterLevel={filterLevel}
        onClearFilterLevel={() => setFilterLevel(null)}
        onSelectEndpoint={handleSelectEndpoint}
      />

      {/* 5. Deep-Dive Forensic Investigation Drawer */}
      <DrillDownDrawer
        username={drillUser}
        hostname={drillHostname}
        riskEvents={summary?.risk_events || []}
        onClose={handleCloseDrillDown}
      />
    </div>
  );
};
