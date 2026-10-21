import { useCallback, useEffect, useState } from 'react';
import type { PluginProps } from '../registry';
import { fetchApi } from '../../services/api';

type Status = 'needs_investigation' | 'benign_context' | 'confirmed_incident' | 'acknowledged_suppressed';
type Candidate = {
  as_of_date: string; rank: number; agent_id: string; hostname: string;
  pair_threat_score: number; primary_hypothesis: string;
  evidence_dates: string[]; analyst_status: Status; analyst_note: string | null;
};
type QueueResponse = { ok: boolean; as_of: string | null; queue: Candidate[] };
type Trajectory = {
  as_of: string; consecutive_complete_days: number; review_eligible: boolean;
  history: Array<{ review_date: string; observation_complete: boolean; selection_status: string; missing_sensors: string[] }>;
};

const labels: Record<Status, string> = {
  needs_investigation: 'Needs Investigation',
  benign_context: 'Benign Context / FP',
  confirmed_incident: 'Confirmed Incident',
  acknowledged_suppressed: 'Acknowledged / Suppressed',
};
const base = '/api/v1/detection/ml';

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
  const headers: Record<string, string> = operatorKey ? { 'X-Operator-Key': operatorKey } : {};

  const loadQueue = useCallback(async () => {
    const response = await fetchApi<QueueResponse>(`${base}/review-queue`, { headers });
    setQueue(response.queue);
    setAsOf(response.as_of);
  }, [operatorKey]);

  useEffect(() => {
    let active = true;
    fetchApi<QueueResponse>(`${base}/review-queue`, { headers })
      .then((response) => { if (active) { setQueue(response.queue); setAsOf(response.as_of); setError(''); } })
      .catch((reason) => { if (active) setError(String(reason)); });
    return () => { active = false; };
  }, [operatorKey]);

  useEffect(() => {
    if (!selectedAgent) { setTrajectory(null); return; }
    let active = true;
    fetchApi<Trajectory>(`${base}/endpoints/${encodeURIComponent(selectedAgent)}/trajectory`, { headers })
      .then((response) => { if (active) { setTrajectory(response); setError(''); } })
      .catch((reason) => { if (active) setError(String(reason)); });
    return () => { active = false; };
  }, [operatorKey, selectedAgent]);

  const selectCandidate = (candidate: Candidate) => {
    setSelectedAgent(candidate.agent_id);
    setAgentInput(candidate.agent_id);
    setStatus(candidate.analyst_status);
    setNote(candidate.analyst_note || '');
  };

  const saveTriage = async () => {
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
        <div><h2 className="text-lg font-semibold">Model V3 host review queue</h2>
          <p className="text-sm text-slate-600">Read-only shadow scoring. Candidates describe host behavior and require forensic review.</p></div>
        <button className="rounded border px-3 py-2 text-sm" onClick={() => void loadQueue().catch((reason) => setError(String(reason)))}>Refresh</button>
      </div>
      <label className="mt-4 block text-xs font-medium text-slate-700">Operator key (held in this tab only)
        <input type="password" autoComplete="off" value={operatorKey} onChange={(event) => setOperatorKey(event.target.value)}
          className="mt-1 block w-full max-w-sm rounded border border-slate-300 px-3 py-2 text-sm" placeholder="Enter operator key if required" />
      </label>
      {error && <p role="alert" className="mt-3 text-sm text-red-700">{error}</p>}
    </div>

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
            <td className="p-2">{item.evidence_dates.join(', ') || '—'}</td>
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
        {trajectory.history.slice(0, 8).map((day) => <p key={day.review_date} className="mt-1 text-xs text-slate-600">
          {day.review_date}: {day.observation_complete ? day.selection_status : `Incomplete · ${day.missing_sensors.join(', ') || day.selection_status}`}
        </p>)}
      </div>}
      {queue.some((row) => row.agent_id === selectedAgent) && <div className="mt-5 grid gap-3 border-t pt-4">
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
