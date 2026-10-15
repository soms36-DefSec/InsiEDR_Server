/**
 * InsiEDR SOC Visual Analytics & Threat Charts
 * =============================================
 *
 * Architectural Role:
 *   Renders high-density visual telemetry for the SOC Matrix view:
 *     1. Domain Vectors Breakdown: Normalized risk score across Logon, File,
 *        USB/Device, and HTTP/Network domains (0–100 scale).
 *     2. Fleet Severity Distribution: SVG Donut chart displaying endpoints
 *        categorized by Critical, High, Medium, and Low severity.
 *     3. Threat Score Timeline: High-resolution chronological SVG path showing
 *        temporal threat velocity against critical/high/medium baseline thresholds.
 */

import React, { useMemo } from 'react';
import { Card } from '../ui/Card';
import type { RiskCounts, RiskEvent } from '../../types/telemetry';
import { parseCorrelatedSignals, formatScore } from '../../utils/formatters';

export interface ChartsSectionProps {
  riskCounts: RiskCounts | null;
  riskEvents: RiskEvent[];
}

export const ChartsSection: React.FC<ChartsSectionProps> = ({ riskCounts, riskEvents }) => {
  // Domain risk extraction matching heuristics/detector.py and model_bridge.py
  const domainAverages = useMemo(() => {
    const domains = { Logon: [] as number[], File: [] as number[], Device: [] as number[], HTTP: [] as number[] };

    riskEvents.forEach((ev) => {
      const signals = parseCorrelatedSignals(ev.correlated_signals_json);
      if (signals) {
        // 1. Direct domain risk features from model bridge
        if (signals.logon_risk != null) domains.Logon.push(Number(signals.logon_risk));
        if (signals.file_risk != null) domains.File.push(Number(signals.file_risk));
        if (signals.device_risk != null) domains.Device.push(Number(signals.device_risk));
        if (signals.http_risk != null) domains.HTTP.push(Number(signals.http_risk));

        // 2. Heuristics domain scores from heuristics/detector.py
        const hDomain = signals.heuristics?.domain_scores || signals.domain_scores;
        if (hDomain) {
          const lScore = hDomain.LOGON ?? hDomain.logon;
          const fScore = hDomain.FILE ?? hDomain.file;
          const dScore = hDomain.DEVICE ?? hDomain.device;
          const hScore = hDomain.HTTP ?? hDomain.http;

          if (lScore != null) domains.Logon.push(Number(lScore));
          if (fScore != null) domains.File.push(Number(fScore));
          if (dScore != null) domains.Device.push(Number(dScore));
          if (hScore != null) domains.HTTP.push(Number(hScore));
        }
      }
    });

    const avg = (arr: number[]) => (arr.length ? arr.reduce((a, b) => a + b, 0) / arr.length : 0);
    const dLogon = avg(domains.Logon);
    const dFile = avg(domains.File);
    const dDevice = avg(domains.Device);
    const dHTTP = avg(domains.HTTP);

    const hasData = dLogon > 0 || dFile > 0 || dDevice > 0 || dHTTP > 0;
    return [
      { name: 'Logon Vectors', score: hasData ? dLogon : 12.5, color: 'bg-blue-600', fill: '#2563eb' },
      { name: 'File I/O Activity', score: hasData ? dFile : 8.0, color: 'bg-indigo-600', fill: '#4f46e5' },
      { name: 'USB / Devices', score: hasData ? dDevice : 4.5, color: 'bg-amber-600', fill: '#d97706' },
      { name: 'HTTP & Web Traffic', score: hasData ? dHTTP : 10.2, color: 'bg-cyan-600', fill: '#0891b2' },
    ];
  }, [riskEvents]);

  // Severity counts for Donut Chart
  const severityData = useMemo(() => {
    const rc = riskCounts;
    const crit = Number(rc?.critical) || 0;
    const high = Number(rc?.high) || 0;
    const med = Number(rc?.medium) || 0;
    const low = Number(rc?.low) || 0;
    const total = (crit + high + med + low) || 1;
    return [
      { label: 'Low (Baseline)', count: low, color: '#10b981', pct: (low / total) * 100 },
      { label: 'Medium', count: med, color: '#f59e0b', pct: (med / total) * 100 },
      { label: 'High', count: high, color: '#f97316', pct: (high / total) * 100 },
      { label: 'Critical', count: crit, color: '#e11d48', pct: (crit / total) * 100 },
    ];
  }, [riskCounts]);

  // Timeline points
  const timelinePoints = useMemo(() => {
    const sorted = [...riskEvents]
      .filter((e) => e.created_at)
      .sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime())
      .slice(-24);

    return sorted.map((e) => ({
      user: e.username,
      score: Math.min(100, Math.max(0, parseFloat(String(e.risk_score || 0)))),
      time: new Date(e.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    }));
  }, [riskEvents]);

  // Donut SVG circumference calculation
  const radius = 38;
  const circumference = 2 * Math.PI * radius;
  let accumulatedAngle = 0;

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      {/* Domain Risk Breakdown */}
      <Card title="Attack Surface & Domain Vectors" subtitle="Aggregated risk by collector domain telemetry">
        <div className="space-y-4 pt-1">
          {domainAverages.map((domain, idx) => (
            <div key={idx} className="space-y-1.5">
              <div className="flex items-center justify-between text-xs">
                <span className="font-medium text-slate-700">{domain.name}</span>
                <span className="font-mono font-semibold text-slate-900">{formatScore(domain.score)}</span>
              </div>
              <div className="w-full bg-slate-100 rounded-full h-2 overflow-hidden border border-slate-200/60">
                <div
                  className={`h-full rounded-full ${domain.color} transition-all duration-500`}
                  style={{ width: `${Math.min(100, Math.max(4, domain.score))}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      </Card>

      {/* Severity Distribution Donut */}
      <Card title="Fleet Severity Distribution" subtitle="Active endpoints categorized by risk posture">
        <div className="flex items-center justify-center gap-8 py-2">
          {/* SVG Donut */}
          <div className="relative w-36 h-36 shrink-0">
            <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90 transform">
              <circle
                cx="50"
                cy="50"
                r={radius}
                className="stroke-slate-100"
                strokeWidth="12"
                fill="transparent"
              />
              {severityData.map((item, idx) => {
                const pct = Number.isFinite(item.pct) ? item.pct : 0;
                const strokeDasharray = `${(pct / 100) * circumference} ${circumference}`;
                const strokeDashoffset = Number.isFinite(accumulatedAngle) ? -accumulatedAngle : 0;
                accumulatedAngle += (pct / 100) * circumference;

                return (
                  <circle
                    key={idx}
                    cx="50"
                    cy="50"
                    r={radius}
                    stroke={item.color}
                    strokeWidth="12"
                    strokeDasharray={strokeDasharray}
                    strokeDashoffset={strokeDashoffset}
                    fill="transparent"
                    className="transition-all duration-500"
                  />
                );
              })}
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
              <span className="text-xl font-bold text-slate-900">
                {(riskCounts?.critical || 0) +
                  (riskCounts?.high || 0) +
                  (riskCounts?.medium || 0) +
                  (riskCounts?.low || 0)}
              </span>
              <span className="text-[10px] uppercase font-medium text-slate-400 tracking-wider">
                Fleet Nodes
              </span>
            </div>
          </div>

          {/* Legend */}
          <div className="space-y-2">
            {severityData.map((item, idx) => (
              <div key={idx} className="flex items-center justify-between gap-4 text-xs">
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: item.color }} />
                  <span className="text-slate-600 font-medium">{item.label}</span>
                </div>
                <span className="font-semibold text-slate-900 font-mono">{item.count}</span>
              </div>
            ))}
          </div>
        </div>
      </Card>

      {/* Risk Score Timeline */}
      <div className="md:col-span-2">
        <Card
          title="Telemetry Risk Score Timeline"
          subtitle="Chronological sequence of calibrated threat scores (0–100 scale)"
        >
          {timelinePoints.length === 0 ? (
            <div className="p-8 text-center text-xs text-slate-400">
              No historical timeline points recorded yet.
            </div>
          ) : (
            <div className="h-44 w-full pt-4">
              <svg className="w-full h-full overflow-visible" viewBox="0 0 800 120" preserveAspectRatio="none">
                {/* Horizontal reference lines */}
                <line x1="0" y1="18" x2="800" y2="18" stroke="#fee2e2" strokeDasharray="3 3" strokeWidth="1" />
                <line x1="0" y1="48" x2="800" y2="48" stroke="#ffedd5" strokeDasharray="3 3" strokeWidth="1" />
                <line x1="0" y1="78" x2="800" y2="78" stroke="#fef3c7" strokeDasharray="3 3" strokeWidth="1" />

                {/* Score trend path */}
                {(() => {
                  let pathD: string;
                  let areaD: string;

                  if (timelinePoints.length === 1) {
                    const y = 115 - (timelinePoints[0].score / 100) * 105;
                    pathD = `M 0,${y} L 800,${y}`;
                    areaD = `M 0,${y} L 800,${y} L 800,120 L 0,120 Z`;
                  } else {
                    const points = timelinePoints.map((p, i) => {
                      const x = (i / (timelinePoints.length - 1)) * 800;
                      const y = 115 - (p.score / 100) * 105;
                      return `${x},${y}`;
                    });
                    pathD = `M ${points.join(' L ')}`;
                    areaD = `M ${points[0]} L ${points.join(' L ')} L 800,120 L 0,120 Z`;
                  }

                  return (
                    <>
                      <defs>
                        <linearGradient id="scoreGradient" x1="0%" y1="0%" x2="0%" y2="100%">
                          <stop offset="0%" stopColor="#2563eb" stopOpacity="0.18" />
                          <stop offset="100%" stopColor="#2563eb" stopOpacity="0.0" />
                        </linearGradient>
                      </defs>
                      <path d={areaD} fill="url(#scoreGradient)" />
                      <path d={pathD} fill="none" stroke="#2563eb" strokeWidth="2.5" strokeLinecap="round" />
                      {timelinePoints.map((p, i) => {
                        const x = (i / Math.max(1, timelinePoints.length - 1)) * 800;
                        const y = 115 - (p.score / 100) * 105;
                        const ptColor = p.score >= 85 ? '#e11d48' : p.score >= 60 ? '#f97316' : '#2563eb';
                        return (
                          <circle
                            key={i}
                            cx={x}
                            cy={y}
                            r="3.5"
                            fill={ptColor}
                            stroke="#ffffff"
                            strokeWidth="1.5"
                          />
                        );
                      })}
                    </>
                  );
                })()}
              </svg>
              <div className="flex justify-between items-center text-[10px] text-slate-400 mt-2 px-1">
                <span>{timelinePoints[0]?.time || 'Past'}</span>
                <div className="flex gap-4 font-mono text-[10px]">
                  <span className="text-rose-600 font-medium">-- 85 Critical</span>
                  <span className="text-orange-600 font-medium">-- 60 High</span>
                  <span className="text-amber-600 font-medium">-- 35 Medium</span>
                </div>
                <span>{timelinePoints[timelinePoints.length - 1]?.time || 'Now'}</span>
              </div>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
};
