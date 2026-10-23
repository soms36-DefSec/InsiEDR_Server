/**
 * InsiEDR Real-Time Threat Activity Stream
 * ========================================
 *
 * Architectural Role:
 *   Chronological live-feed component displaying the most recent 30 anomalous
 *   incidents, heuristic detections, and machine-learning risk spikes.
 *
 * Interactivity:
 *   Clicking any threat item triggers `onSelectThreat(username, hostname)`,
 *   opening the forensic DrillDownDrawer for deep-dive root cause analysis.
 */

import React from 'react';
import type { RiskEvent } from '../../types/telemetry';
import { Badge } from '../ui/Badge';
import { formatScore, getRiskLevel, extractEventSummary, timeAgo, THREAT_DECAY_WINDOW_MS } from '../../utils/formatters';
import { AlertCircle } from 'lucide-react';

export interface ThreatFeedProps {
  events: RiskEvent[];
  onSelectThreat: (username: string, hostname?: string) => void;
  isLoading?: boolean;
}

export const ThreatFeed: React.FC<ThreatFeedProps> = ({
  events,
  onSelectThreat,
  isLoading = false,
}) => {
  const activeEvents = (events || []).filter((event) => {
    const age = Date.now() - new Date(event.created_at).getTime();
    const active = event.is_active ?? (age >= -120000 && age <= THREAT_DECAY_WINDOW_MS);
    return active && !event.is_test && Number(event.risk_score || 0) >= 40;
  });
  if (isLoading && activeEvents.length === 0) {
    return (
      <div className="flex items-center justify-center p-8 text-xs text-slate-400">
        <span className="w-4 h-4 border-2 border-slate-300 border-t-blue-600 rounded-full animate-spin mr-2" />
        Synchronizing threat telemetry...
      </div>
    );
  }

  if (activeEvents.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center p-8 text-center bg-slate-50/50 rounded-lg border border-dashed border-slate-200">
        <AlertCircle className="w-6 h-6 text-slate-400 mb-2" />
        <div className="text-xs font-semibold text-slate-700">All Systems Nominal</div>
        <div className="text-[11px] text-slate-500 mt-0.5">
          No anomalous threats or heuristic rule violations currently flagged.
        </div>
      </div>
    );
  }

  return (
    <div className="divide-y divide-slate-100 max-h-[380px] overflow-y-auto pr-1">
      {activeEvents.slice(0, 30).map((ev, idx) => {
        const score = parseFloat(String(ev.risk_score || 0));
        const level = getRiskLevel(score);
        const summary = extractEventSummary(ev);
        const host = ev.hostname || ev.agent_id || 'Endpoint';
        const user = ev.username || 'unknown';

        return (
          <div
            key={idx}
            onClick={() => onSelectThreat(user, ev.hostname)}
            className="py-2.5 px-2 flex items-start gap-2.5 hover:bg-slate-50 rounded-md transition-colors cursor-pointer group border-b border-slate-100/80 last:border-b-0"
          >
            <div className="shrink-0 mt-0.5">
              <Badge level={level} size="sm" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-semibold font-mono text-slate-900 group-hover:text-blue-600 transition-colors truncate">
                  {host}
                </span>
                <span className="text-[11px] font-mono tabular-nums text-slate-500 shrink-0">
                  Risk: <span className="font-semibold text-slate-900">{formatScore(score)}</span>
                </span>
              </div>
              <div className="text-[11px] text-slate-600 truncate mt-0.5 leading-snug" title={summary}>
                {summary}
              </div>
              <div className="text-[10px] text-slate-400 mt-1 flex items-center gap-2">
                <span>{timeAgo(ev.created_at)}</span>
                {user && (
                  <>
                    <span>·</span>
                    <span className="text-slate-500">User: {user}</span>
                  </>
                )}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
};
