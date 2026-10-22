import { useCallback, useEffect, useState } from 'react';
import type { PluginProps } from '../registry';
import { fetchApi } from '../../services/api';
import { subscribeTelemetry } from '../../services/telemetryStream';
import type { TelemetryExplorerEvent } from '../../types/telemetry';

type Status = 'needs_investigation' | 'benign_context' | 'confirmed_incident' | 'acknowledged_suppressed';
type Candidate = {
  as_of_date: string; rank: number; agent_id: string; hostname: string;
  pair_threat_score: number; primary_hypothesis: string;
  evidence_dates: Array<string | { date: string; threat_score?: number; temporal_error?: number }>;
  analyst_status: Status; analyst_note: string | null;
};
type QueueResponse = { ok: boolean; as_of: string | null; queue: Candidate[] };
type Trajectory = {
  as_of: string; consecutive_complete_days: number; review_eligible: boolean;
  history: Array<{ review_date: string; observation_complete: boolean; selection_status: string;
    missing_sensors: string[]; threat_probability?: number | null; if_risk?: number | null;
    fused_risk?: number | null; drift_error?: number | null; predicted_scenario?: string | null }>;
};
type ScenarioHost = {
  agent_id: string; hostname: string; rank: number | null; pair_threat_score: number | null;
  live_risk_score: number | null; live_peak_risk_score: number | null;
  live_risk_level: string | null; live_summary: string | null;
  model: { threat_probability: number | null; if_risk: number | null; fused_risk: number | null;
    drift_error: number | null; predicted_scenario: string | null };
};

const labels: Record<Status, string> = {
  needs_investigation: 'Needs Investigation',
  benign_context: 'Benign Context / FP',
  confirmed_incident: 'Confirmed Incident',
  acknowledged_suppressed: 'Acknowledged / Suppressed',
};
const base = '/api/v1/detection/ml';
const evidenceLabel = (item: Candidate['evidence_dates'][number]) => typeof item === 'string' ? item : item.date;
const percentScore = (value: number | null | undefined) => value == null ? '—' : `${(value * 100).toFixed(1)}/100`;

export function ReviewQueuePlugin(_props: PluginProps) {
  const [operatorKey, setOperatorKey] = useState('');
  const [queue, setQueue] = useState<Candidate[]>([]);
  const [asOf, setAsOf] = useState<string | null>(null);
  const [selectedAgent, setSelectedAgent] = useState('');
  const [agentInput, setAgentInput] = useState('');
  const [trajectory, setTrajectory] = useState<Trajectory | null>(null);
  const [note, setNote] = useState('');
  const [status, setStatus] = useState<Status>('needs_investigation');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [scenarioHosts, setScenarioHosts] = useState<ScenarioHost[] | null>(null);
  const [hostLogs, setHostLogs] = useState<TelemetryExplorerEvent[]>([]);
  const [provenance, setProvenance] = useState<{ event_id: string; payload_id: string; provenance: Record<string, unknown> } | null>(null);
  const headers: Record<string, string> = operatorKey ? { 'X-Operator-Key': operatorKey } : {};
  const apiBase = scenarioHosts === null ? base : `${base}/scenario`;

  useEffect(() => {
    let active = true;
    const refresh = () => fetchApi<{ ok: boolean; hosts: ScenarioHost[] }>(`${base}/scenario/hosts`, { headers })
      .then((response) => { if (active) setScenarioHosts(response.hosts); })
      .catch(() => {});
    void refresh();
    const timer = window.setInterval(() => void refresh(), 3000);
    return () => { active = false; window.clearInterval(timer); };
  }, [operatorKey]);

  useEffect(() => {
    if (scenarioHosts === null || !selectedAgent) { setHostLogs([]); return; }
    let active = true;
    const refresh = () => fetchApi<{ events: TelemetryExplorerEvent[] }>(
      `/api/v1/telemetry/explorer?limit=12&agent_id=${encodeURIComponent(selectedAgent)}`,
      { headers },
    ).then((response) => { if (active) setHostLogs(response.events); }).catch(() => {});
    void refresh();
    const unsubscribe = subscribeTelemetry(() => void refresh());
    const timer = window.setInterval(() => void refresh(), 4000);
    return () => { active = false; unsubscribe(); window.clearInterval(timer); };
  }, [operatorKey, selectedAgent, scenarioHosts === null]);

  const loadQueue = useCallback(async () => {
    const response = await fetchApi<QueueResponse>(`${apiBase}/review-queue`, { headers });
    setQueue(response.queue);
    setAsOf(response.as_of);
  }, [operatorKey, apiBase]);

  useEffect(() => {
    let active = true;
    fetchApi<QueueResponse>(`${apiBase}/review-queue`, { headers })
      .then((response) => { if (active) { setQueue(response.queue); setAsOf(response.as_of); setError(''); } })
      .catch((reason) => { if (active) setError(String(reason)); });
    return () => { active = false; };
  }, [operatorKey, apiBase]);

  useEffect(() => {
    if (!selectedAgent) { setTrajectory(null); return; }
    let active = true;
    fetchApi<Trajectory>(`${apiBase}/endpoints/${encodeURIComponent(selectedAgent)}/trajectory`, { headers })
      .then((response) => { if (active) { setTrajectory(response); setError(''); } })
      .catch((reason) => { if (active) setError(String(reason)); });
    return () => { active = false; };
  }, [operatorKey, selectedAgent, apiBase]);

  const selectCandidate = (candidate: Candidate) => {
    setSelectedAgent(candidate.agent_id);
    setProvenance(null);
    setAgentInput(candidate.agent_id);
    setStatus(candidate.analyst_status);
    setNote(candidate.analyst_note || '');
  };

  const showProvenance = async (eventId: string) => {
    try {
      const details = await fetchApi<{ event_id: string; payload_id: string; provenance: Record<string, unknown> }>(
        `${base}/scenario/events/${encodeURIComponent(eventId)}/provenance`, { headers });
      setProvenance(details);
    } catch (reason) { setError(String(reason)); }
  };

  const saveTriage = async () => {
    if (scenarioHosts !== null) return;
    const candidate = queue.find((row) => row.agent_id === selectedAgent);
    if (!candidate) return;
    setBusy(true); setError('');
    try {
      await fetchApi(`${base}/review-queue/${encodeURIComponent(candidate.as_of_date)}/${encodeURIComponent(candidate.agent_id)}`, {
        method: 'PATCH',
        headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify({ analyst_status: status, analyst_note: note.trim() || null }),
      });
      await loadQueue();
    } catch (reason) { setError(String(reason)); }
    finally { setBusy(false); }
  };

  return <div className="space-y-5 text-slate-900">
    <div className="rounded-lg border border-slate-200 bg-white p-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div><h2 className="text-lg font-semibold">Risk Review</h2>
          <p className="text-sm text-slate-600">Read-only shadow scoring. Candidates describe host behavior and require forensic review.</p></div>
        <button className="rounded border px-3 py-2 text-sm" onClick={() => void loadQueue().catch((reason) => setError(String(reason)))}>Refresh</button>
      </div>
      <label className="mt-4 block text-xs font-medium text-slate-700">Operator key (held in this tab only)
        <input type="password" autoComplete="off" value={operatorKey} onChange={(event) => setOperatorKey(event.target.value)}
          className="mt-1 block w-full max-w-sm rounded border border-slate-300 px-3 py-2 text-sm" placeholder="Enter operator key if required" />
      </label>
      {error && <p role="alert" className="mt-3 text-sm text-red-700">{error}</p>}
    </div>

    {scenarioHosts !== null && <div className="rounded-lg border border-slate-200 bg-white p-5">
      <h3 className="font-semibold">Scenario hosts</h3>
      <div className="mt-3 grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
        {scenarioHosts.map((host) => <button key={host.agent_id} onClick={() => {
          setSelectedAgent(host.agent_id); setAgentInput(host.agent_id); setProvenance(null);
        }} className={`rounded border p-3 text-left text-sm ${selectedAgent === host.agent_id ? 'border-blue-600 bg-blue-50' : 'border-slate-200'}`}>
          <span className="font-medium">{host.hostname}</span><span className="block text-xs text-slate-500">{host.agent_id}</span>
          <span className="mt-2 block">Live peak: {host.live_peak_risk_score == null ? 'Waiting for logs' : `${host.live_peak_risk_score.toFixed(1)}/100`}</span>
          <span className="block">Model threat: {percentScore(host.model.threat_probability)}</span>
        </button>)}
      </div>
      {scenarioHosts.find((host) => host.agent_id === selectedAgent) && (() => {
        const host = scenarioHosts.find((row) => row.agent_id === selectedAgent)!;
        return <div className="mt-4 grid gap-3 text-sm md:grid-cols-2">
          <div className="rounded border p-3"><strong>Live detection</strong><p>Current risk: {host.live_risk_score == null ? 'Waiting for logs' : `${host.live_risk_score.toFixed(1)}/100`}</p>
            <p>Session peak: {host.live_peak_risk_score == null ? '—' : `${host.live_peak_risk_score.toFixed(1)}/100`}</p>
            <p>Severity: {host.live_risk_level || '—'}</p><p>{host.live_summary || 'No live risk event yet.'}</p></div>
          <div className="rounded border p-3"><strong>Model V3 completed-day review</strong><p>Threat score: {percentScore(host.model.threat_probability)}</p>
            <p>IF risk: {percentScore(host.model.if_risk)}</p><p>Fused risk: {percentScore(host.model.fused_risk)}</p>
            <p>Drift error: {percentScore(host.model.drift_error)}</p><p>Hypothesis: {host.model.predicted_scenario?.replaceAll('_', ' ') || '—'}</p>
            <p>Pair score: {host.pair_threat_score?.toFixed(4) || '—'} · {host.rank ? `Review #${host.rank}` : 'Below review threshold'}</p></div>
          <div className="rounded border p-3 md:col-span-2"><strong>Incoming collector logs</strong>
            {hostLogs.length === 0 ? <p className="mt-2 text-slate-500">Waiting for collector events.</p> :
              <div className="mt-2 max-h-64 overflow-auto"><table className="w-full text-left text-xs">
                <thead><tr><th className="py-1">UTC time</th><th>Collector</th><th>Status</th><th>Summary</th><th>Source</th></tr></thead>
                <tbody>{hostLogs.map((entry) => <tr key={entry.event_id} className="border-t">
                  <td className="py-1">{entry.timestamp}</td><td>{entry.collector_name}</td>
                  <td>{entry.status}</td><td>{entry.summary_preview}</td>
                  <td><button className="text-blue-700 underline" onClick={() => void showProvenance(entry.event_id)}>Details</button></td>
                </tr>)}</tbody>
              </table></div>}
            {provenance && <pre className="mt-3 overflow-auto rounded bg-slate-50 p-2 text-xs">{JSON.stringify(provenance, null, 2)}</pre>}
          </div>
        </div>;
      })()}
    </div>}

    <div className="rounded-lg border border-slate-200 bg-white p-5">
      <h3 className="font-semibold">Candidates {asOf ? `· ${asOf} UTC` : ''}</h3>
      {queue.length === 0 ? <p className="mt-3 text-sm text-slate-600">No review candidates yet. Endpoints need 22 consecutive complete UTC days before review.</p> :
        <div className="mt-3 overflow-x-auto"><table className="w-full text-left text-sm">
          <thead><tr className="border-b text-slate-600"><th className="p-2">Rank</th><th className="p-2">Host</th><th className="p-2">Pair score</th><th className="p-2">Hypothesis</th><th className="p-2">Evidence dates</th><th className="p-2">Status</th></tr></thead>
          <tbody>{queue.map((item) => <tr key={`${item.as_of_date}:${item.agent_id}`} className="border-b hover:bg-slate-50">
            <td className="p-2">#{item.rank}</td>
            <td className="p-2"><button className="text-left text-blue-700 underline" onClick={() => selectCandidate(item)}>{item.hostname}<span className="block text-xs text-slate-500">{item.agent_id}</span></button></td>
            <td className="p-2 font-mono">{item.pair_threat_score.toFixed(4)}</td>
            <td className="p-2">{item.primary_hypothesis.replaceAll('_', ' ')}</td>
            <td className="p-2">{item.evidence_dates.map(evidenceLabel).join(', ') || '—'}</td>
            <td className="p-2">{labels[item.analyst_status]}</td>
          </tr>)}</tbody>
        </table></div>}
    </div>

    <div className="rounded-lg border border-slate-200 bg-white p-5">
      <h3 className="font-semibold">Endpoint warmup and review</h3>
      <form className="mt-3 flex gap-2" onSubmit={(event) => { event.preventDefault(); setSelectedAgent(agentInput.trim()); }}>
        <input aria-label="Agent ID" value={agentInput} onChange={(event) => setAgentInput(event.target.value)} placeholder="AGENT-hostname"
          className="min-w-0 flex-1 rounded border border-slate-300 px-3 py-2 text-sm" />
        <button className="rounded border px-3 py-2 text-sm">Look up</button>
      </form>
      {trajectory && <div className="mt-4 text-sm">
        <p className="font-medium">Day {Math.min(trajectory.consecutive_complete_days, 22)} of 22 · {trajectory.review_eligible ? 'Review eligible' : 'Warming up'}</p>
        <p className="text-slate-600">Completed UTC day: {trajectory.as_of}. A missing day or journal gap resets the consecutive count.</p>
        {trajectory.history[0]?.threat_probability != null && <p className="mt-1">Latest Model V3 threat score: {percentScore(trajectory.history[0].threat_probability)} · {trajectory.history[0].predicted_scenario?.replaceAll('_', ' ')}</p>}
        <div className="mt-3 max-h-64 overflow-auto rounded border border-slate-200">
          <table className="w-full text-left text-xs">
            <thead><tr><th className="p-2">UTC day</th><th>Coverage</th><th>Model threat</th><th>Hypothesis</th></tr></thead>
            <tbody>{trajectory.history.map((day) => <tr key={day.review_date} className="border-t">
              <td className="p-2">{day.review_date}</td>
              <td>{day.observation_complete ? 'Complete' : `Incomplete · ${day.missing_sensors.join(', ') || day.selection_status}`}</td>
              <td>{percentScore(day.threat_probability)}</td>
              <td>{day.predicted_scenario?.replaceAll('_', ' ') || '—'}</td>
            </tr>)}</tbody>
          </table>
        </div>
      </div>}
      {scenarioHosts === null && queue.some((row) => row.agent_id === selectedAgent) && <div className="mt-5 grid gap-3 border-t pt-4">
        <label className="text-sm">Analyst status
          <select value={status} onChange={(event) => setStatus(event.target.value as Status)} className="mt-1 block w-full rounded border px-3 py-2">
            {Object.entries(labels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
          </select>
        </label>
        <label className="text-sm">Forensic note
          <textarea value={note} onChange={(event) => setNote(event.target.value)} maxLength={2000} rows={3}
            className="mt-1 block w-full rounded border px-3 py-2" />
        </label>
        <button disabled={busy} onClick={() => void saveTriage()} className="w-fit rounded bg-blue-700 px-4 py-2 text-sm text-white disabled:opacity-50">Save analyst feedback</button>
      </div>}
    </div>
  </div>;
}
