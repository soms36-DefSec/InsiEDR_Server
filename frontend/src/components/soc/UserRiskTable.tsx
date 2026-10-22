/**
 * InsiEDR Endpoint Fleet Risk Matrix
 * ==================================
 *
 * Architectural Role:
 *   Core operational grid displaying all monitored endpoints across the fleet.
 *   Correlates real-time agent registration, heartbeat telemetry, and the latest
 *   AI/heuristic risk assessments into a searchable, sortable, and paginated table.
 *
 * Domain Calibration & Threat Decay:
 *   - Correlates latest risk events by agent ID or hostname via `riskEvents`.
 *   - Implements a 30-minute threat decay model (`THREAT_DECAY_WINDOW_MS`): if an endpoint
 *     had a historical alert but no malicious signals in the past 30 minutes, active
 *     indicators transition to decayed nominal status to prevent analyst fatigue.
 *   - Merges multi-model signals: CERT scenario IDs, heuristic detections, RVFL/XGBoost
 *     predictions, and cryptographic tamper detection flags.
 */

import React, { useState, useMemo } from 'react';
import type { AgentEndpoint, RiskEvent, EndpointRow } from '../../types/telemetry';
import { Card } from '../ui/Card';
import { Badge } from '../ui/Badge';
import { Button } from '../ui/Button';
import {
  formatScore,
  getRiskLevel,
  timeAgo,
  parseCorrelatedSignals,
  THREAT_DECAY_WINDOW_MS,
} from '../../utils/formatters';
import { Search, ChevronLeft, ChevronRight, ArrowUpDown, Monitor } from 'lucide-react';

export interface UserRiskTableProps {
  agents: AgentEndpoint[];
  riskEvents: RiskEvent[];
  selectedUser?: string | null;
  selectedHostname?: string | null;
  filterLevel?: string | null;
  onClearFilterLevel?: () => void;
  onSelectEndpoint: (username: string, hostname?: string) => void;
}

export const UserRiskTable: React.FC<UserRiskTableProps> = ({
  agents,
  riskEvents,
  selectedUser,
  selectedHostname,
  filterLevel,
  onClearFilterLevel,
  onSelectEndpoint,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [sortField, setSortField] = useState<'user' | 'hostname' | 'score' | 'lastSeen'>('score');
  const [sortAsc, setSortAsc] = useState(false);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);

  // Compute endpoint rows with latest risk scores and 30-min decay
  const endpointRows = useMemo<EndpointRow[]>(() => {
    const hostRiskMap: Record<string, RiskEvent> = {};
    const agentRiskMap: Record<string, RiskEvent> = {};

    riskEvents.forEach((ev) => {
      const h = ev.hostname;
      const aid = ev.agent_id;
      if (h && !hostRiskMap[h]) hostRiskMap[h] = ev;
      if (aid && !agentRiskMap[aid]) agentRiskMap[aid] = ev;
    });

    const now = Date.now();
    const rows: EndpointRow[] = agents.map((agent) => {
      const hostname = agent.hostname || '—';
      const user = agent.username_last_seen || '—';
      const agentId = agent.agent_id || `${hostname}_${user}`;

      const risk = (agent.agent_id && agentRiskMap[agent.agent_id]) ||
                   (hostname !== '—' && hostRiskMap[hostname]);
      let score = 0;
      let level = getRiskLevel(0);
      let isDecayed = false;

      if (risk) {
        score = parseFloat(String(risk.risk_score || 0));
        level = getRiskLevel(score);
        const eventTime = new Date(risk.created_at).getTime();
        if (!isNaN(eventTime) && now - eventTime > THREAT_DECAY_WINDOW_MS) {
          isDecayed = true;
        }
      }

      const scenarioTags: Array<{ id: string; desc: string }> = [];
      if (risk && risk.correlated_signals_json && !isDecayed) {
        const signals = parseCorrelatedSignals(risk.correlated_signals_json);
        if (signals?.cert_scenarios) {
          signals.cert_scenarios.forEach((s) => {
            scenarioTags.push({ id: s.id, desc: s.description });
          });
        }
        if (signals?.heuristics?.detections) {
          signals.heuristics.detections.forEach((d) => {
            if (d.scenario && !scenarioTags.some((t) => t.id === d.scenario)) {
              scenarioTags.push({ id: d.scenario, desc: d.scenario });
            }
          });
        }
        if (signals?.heuristics?.detected_scenarios) {
          signals.heuristics.detected_scenarios.forEach((sc) => {
            if (sc && !scenarioTags.some((t) => t.id === sc)) {
              scenarioTags.push({ id: sc, desc: sc });
            }
          });
        }
        if (signals?.predicted_scenario?.scenario && signals.predicted_scenario.scenario !== 'normal') {
          if (!scenarioTags.some((t) => t.id === signals.predicted_scenario?.scenario)) {
            scenarioTags.push({
              id: signals.predicted_scenario.scenario,
              desc: signals.predicted_scenario.scenario,
            });
          }
        }
        if (signals?.tamper_detector?.is_anomaly) {
          scenarioTags.push({
            id: 'Tamper Alert',
            desc: signals.tamper_detector.reason || 'Agent tamper anomaly detected',
          });
        }
      }

      if (scenarioTags.length === 0 && score >= 35.0) {
        scenarioTags.push({ id: 'Anomaly', desc: 'Anomaly Pattern Detected' });
      }

      const isOnline =
        agent.status === 'active' ||
        (agent.last_seen_at && now - new Date(agent.last_seen_at).getTime() < 300000);

      return {
        agentId,
        hostname,
        user,
        score,
        level,
        isDecayed,
        scenarios: scenarioTags,
        lastSeen: agent.last_seen_at,
        isOnline: Boolean(isOnline),
      };
    });

    // Deduplicate uniquely by Agent ID / Hostname
    const unique: EndpointRow[] = [];
    const seen = new Set<string>();
    rows.forEach((r) => {
      const key = r.agentId || r.hostname;
      if (!seen.has(key)) {
        seen.add(key);
        unique.push(r);
      }
    });

    return unique;
  }, [agents, riskEvents]);

  // Filter
  const filtered = useMemo(() => {
    let list = endpointRows;
    if (filterLevel) {
      list = list.filter((r) => r.level.toUpperCase() === filterLevel.toUpperCase());
    }
    const q = searchTerm.toLowerCase().trim();
    if (!q) return list;
    return list.filter(
      (r) =>
        r.user.toLowerCase().includes(q) ||
        r.hostname.toLowerCase().includes(q) ||
        r.level.toLowerCase().includes(q)
    );
  }, [endpointRows, searchTerm, filterLevel]);

  // Sort
  const sorted = useMemo(() => {
    return [...filtered].sort((a, b) => {
      let cmp = 0;
      if (sortField === 'score') cmp = a.score - b.score;
      else if (sortField === 'user') cmp = a.user.localeCompare(b.user);
      else if (sortField === 'hostname') cmp = a.hostname.localeCompare(b.hostname);
      else if (sortField === 'lastSeen')
        cmp = new Date(a.lastSeen || 0).getTime() - new Date(b.lastSeen || 0).getTime();

      return sortAsc ? cmp : -cmp;
    });
  }, [filtered, sortField, sortAsc]);

  // Pagination
  const totalItems = sorted.length;
  const totalPages = Math.max(1, Math.ceil(totalItems / pageSize));
  const currentPage = Math.min(page, totalPages);
  const startIdx = (currentPage - 1) * pageSize;
  const paginated = sorted.slice(startIdx, startIdx + pageSize);

  const toggleSort = (field: 'user' | 'hostname' | 'score' | 'lastSeen') => {
    if (sortField === field) {
      setSortAsc(!sortAsc);
    } else {
      setSortField(field);
      setSortAsc(false);
    }
  };

  return (
    <Card
      title={
        <div className="flex items-center gap-2">
          <span>Endpoint Fleet Risk Matrix</span>
          <span className="text-xs px-2 py-0.5 rounded-full bg-slate-100 text-slate-600 font-semibold tabular-nums">
            {endpointRows.length} endpoints
          </span>
          {filterLevel && (
            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-semibold bg-rose-50 text-rose-800 border border-rose-200">
              Severity: {filterLevel} ({filtered.length})
              {onClearFilterLevel && (
                <button
                  onClick={onClearFilterLevel}
                  className="hover:text-rose-950 font-bold ml-0.5 cursor-pointer"
                  title="Clear filter"
                >
                  ×
                </button>
              )}
            </span>
          )}
        </div>
      }
      subtitle="Live risk calibration and anomalous scenario posture across connected devices"
      action={
        <div className="flex items-center gap-2">
          {filterLevel && onClearFilterLevel && (
            <button
              onClick={onClearFilterLevel}
              className="text-[11px] text-slate-500 hover:text-slate-800 font-medium cursor-pointer"
            >
              Reset filter
            </button>
          )}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Filter hostname or user..."
              value={searchTerm}
              onChange={(e) => {
                setSearchTerm(e.target.value);
                setPage(1);
              }}
              className="w-56 pl-8 pr-3 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-md outline-none focus:border-blue-500 focus:bg-white text-slate-900 transition-colors"
            />
          </div>
        </div>
      }
      noPadding
    >
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse text-xs">
          <thead>
            <tr className="border-b border-slate-200 bg-slate-50/70 text-slate-600 font-semibold">
              <th className="py-2.5 px-4 w-16">Status</th>
              <th
                className="py-2.5 px-4 cursor-pointer hover:text-slate-900 select-none"
                onClick={() => toggleSort('hostname')}
              >
                <div className="flex items-center gap-1">
                  Hostname <ArrowUpDown className="w-3 h-3 text-slate-400" />
                </div>
              </th>
              <th
                className="py-2.5 px-4 cursor-pointer hover:text-slate-900 select-none"
                onClick={() => toggleSort('user')}
              >
                <div className="flex items-center gap-1">
                  User <ArrowUpDown className="w-3 h-3 text-slate-400" />
                </div>
              </th>
              <th
                className="py-2.5 px-4 cursor-pointer hover:text-slate-900 select-none w-48"
                onClick={() => toggleSort('score')}
              >
                <div className="flex items-center gap-1">
                  Risk Score <ArrowUpDown className="w-3 h-3 text-slate-400" />
                </div>
              </th>
              <th className="py-2.5 px-4 w-28">Risk Level</th>
              <th className="py-2.5 px-4">Active Scenarios</th>
              <th
                className="py-2.5 px-4 cursor-pointer hover:text-slate-900 select-none w-32"
                onClick={() => toggleSort('lastSeen')}
              >
                <div className="flex items-center gap-1">
                  Last Active <ArrowUpDown className="w-3 h-3 text-slate-400" />
                </div>
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {paginated.length === 0 ? (
              <tr>
                <td colSpan={7} className="py-8 text-center text-slate-400 text-xs">
                  No endpoint records matching filter criteria.
                </td>
              </tr>
            ) : (
              paginated.map((row) => {
                const isSelected = selectedHostname ? selectedHostname === row.hostname : (selectedUser === row.user);
                const scoreColor =
                  row.score >= 85
                    ? 'text-rose-700'
                    : row.score >= 60
                    ? 'text-orange-700'
                    : row.score >= 35
                    ? 'text-amber-800'
                    : 'text-emerald-700';

                const progressBg =
                  row.score >= 85
                    ? 'bg-rose-500'
                    : row.score >= 60
                    ? 'bg-orange-500'
                    : row.score >= 35
                    ? 'bg-amber-500'
                    : 'bg-emerald-500';

                return (
                  <tr
                    key={row.agentId}
                    onClick={() => onSelectEndpoint(row.user, row.hostname)}
                    className={`transition-colors cursor-pointer hover:bg-slate-50/80 ${
                      isSelected ? 'bg-blue-50/60 font-medium' : ''
                    }`}
                  >
                    {/* Online status */}
                    <td className="py-3 px-4">
                      <span
                        className={`inline-block w-2 h-2 rounded-full ${
                          row.isOnline ? 'bg-emerald-500' : 'bg-slate-300'
                        }`}
                        title={row.isOnline ? 'Online (Heartbeat Active)' : 'Offline'}
                      />
                    </td>

                    {/* Hostname (Primary Identifier) */}
                    <td className="py-3 px-4 font-mono font-semibold text-slate-900 flex items-center gap-1.5">
                      <Monitor className="w-3.5 h-3.5 text-blue-600" />
                      {row.hostname}
                    </td>

                    {/* User */}
                    <td className="py-3 px-4 text-slate-600 font-medium">{row.user}</td>

                    {/* Score + Progress Bar */}
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2.5">
                        <span className={`font-mono font-bold w-10 shrink-0 ${scoreColor}`}>
                          {formatScore(row.score)}
                        </span>
                        <div className="flex-1 bg-slate-100 h-1.5 rounded-full overflow-hidden border border-slate-200/50">
                          <div
                            className={`h-full rounded-full ${progressBg}`}
                            style={{ width: `${Math.min(100, Math.max(2, row.score))}%` }}
                          />
                        </div>
                      </div>
                    </td>

                    {/* Level */}
                    <td className="py-3 px-4">
                      <Badge level={row.level} size="sm" />
                    </td>

                    {/* Scenarios */}
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-1.5 flex-wrap">
                        {row.scenarios.length > 0 ? (
                          row.scenarios.slice(0, 3).map((s, idx) => (
                            <span
                              key={idx}
                              className={`text-[10px] px-1.5 py-0.5 rounded truncate max-w-[140px] border ${
                                s.id.includes('Tamper')
                                  ? 'bg-rose-50 text-rose-700 border-rose-200 font-semibold'
                                  : 'bg-slate-100 text-slate-700 border-slate-200'
                              }`}
                              title={s.desc}
                            >
                              {s.id}
                            </span>
                          ))
                        ) : (
                          <span className="text-[10px] text-slate-400">
                            {row.isDecayed ? 'Decayed (Nominal)' : 'Nominal'}
                          </span>
                        )}
                        {row.scenarios.length > 3 && (
                          <span className="text-[10px] text-slate-400 font-mono">
                            +{row.scenarios.length - 3}
                          </span>
                        )}
                      </div>
                    </td>

                    {/* Last seen */}
                    <td className="py-3 px-4 text-slate-500">{timeAgo(row.lastSeen)}</td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Footer */}
      <div className="px-5 py-3 border-t border-slate-200 bg-slate-50/50 flex items-center justify-between flex-wrap gap-3 text-xs">
        <div className="text-slate-500">
          Showing <span className="font-semibold text-slate-900">{totalItems === 0 ? 0 : startIdx + 1}</span> to{' '}
          <span className="font-semibold text-slate-900">{Math.min(startIdx + pageSize, totalItems)}</span> of{' '}
          <span className="font-semibold text-slate-900">{totalItems}</span> endpoints
        </div>

        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1.5 text-slate-600">
            <span>Rows:</span>
            <select
              value={pageSize}
              onChange={(e) => {
                setPageSize(Number(e.target.value));
                setPage(1);
              }}
              className="bg-white border border-slate-200 rounded px-2 py-1 text-xs outline-none cursor-pointer"
            >
              <option value={10}>10</option>
              <option value={25}>25</option>
              <option value={50}>50</option>
              <option value={100}>100</option>
            </select>
          </div>

          <div className="flex items-center gap-1">
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={currentPage <= 1}
              icon={<ChevronLeft className="w-3.5 h-3.5" />}
            >
              Prev
            </Button>
            <span className="px-2 text-slate-600 font-medium">
              Page {currentPage} of {totalPages}
            </span>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={currentPage >= totalPages}
              icon={<ChevronRight className="w-3.5 h-3.5" />}
            >
              Next
            </Button>
          </div>
        </div>
      </div>
    </Card>
  );
};
