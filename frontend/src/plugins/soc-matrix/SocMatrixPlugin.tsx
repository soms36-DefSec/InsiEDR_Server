/**
 * InsiEDR SOC Threat Matrix
 * =========================
 *
 * Operational Command View for Security Analysts:
 *   1. Security Posture Ribbon (Fleet posture, risk stratification, detection engine health)
 *   2. Real-Time Threat Stream & Behavioral Attack Surface Charts
 *   3. Endpoint Fleet Risk Matrix with threat decay and forensic investigation drawer
 */

import React, { useState } from 'react';
import type { PluginProps } from '../registry';
import { KpiGrid } from '../../components/soc/KpiGrid';
import { ThreatFeed } from '../../components/soc/ThreatFeed';
import { ChartsSection } from '../../components/soc/ChartsSection';
import { UserRiskTable } from '../../components/soc/UserRiskTable';
import { DrillDownDrawer } from '../../components/soc/DrillDownDrawer';
import { Card } from '../../components/ui/Card';
import { Download } from 'lucide-react';
import { triggerServerExport } from '../../services/api';

export const SocMatrixPlugin: React.FC<PluginProps> = ({ context }) => {
  const { summary, health, onOpenDrillDown } = context;
  const [drillUser, setDrillUser] = useState<string | null>(null);
  const [drillHostname, setDrillHostname] = useState<string | null>(null);
  const [drillAgentId, setDrillAgentId] = useState<string | null>(null);
  const [filterLevel, setFilterLevel] = useState<string | null>(null);

  const handleSelectEndpoint = (user: string, host?: string, agentId?: string) => {
    setDrillUser(user);
    setDrillHostname(host || null);
    setDrillAgentId(agentId || summary?.agents?.find((agent) => agent.hostname === host && agent.username_last_seen === user)?.agent_id || null);
    if (onOpenDrillDown) onOpenDrillDown(user, host);
  };

  const handleCloseDrillDown = () => {
    setDrillUser(null);
    setDrillHostname(null);
    setDrillAgentId(null);
  };

  return (
    <div className="space-y-5">
      {/* 1. Security Operations Posture Ribbon */}
      <KpiGrid
        summary={summary}
        health={health}
        activeFilter={filterLevel}
        onFilterLevel={setFilterLevel}
      />

      {/* 2. Operational Grid: Live Threat Feed & Attack Surface Breakdown */}
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
        agentId={drillAgentId}
        riskEvents={summary?.risk_events || []}
        onClose={handleCloseDrillDown}
      />
    </div>
  );
};
