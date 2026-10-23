/**
 * InsiEDR Deep-Dive Behavioral Drilldown Drawer
 * ===============================================
 *
 * Architectural Role:
 *   Forensic investigation panel for a specific user identity or host endpoint.
 *   Correlates two independent analytical intelligence streams:
 *     1. Machine Learning Bridge (`/api/user-predictions/{user}`):
 *        - RVFL Drift Error: Measures behavioral drift from historical baseline.
 *        - XGBoost Classifier: Scenario classification confidence (e.g. Exfiltration, Sabotage).
 *     2. Heuristics & Correlated Events (`/api/user-risk-scores/{user}`):
 *        - Rule violations, CERT scenario tags, and domain score breakdowns.
 *
 * Fix Note:
 *   Sorts historical scores by `created_at DESC` defensively to guarantee index 0
 *   always references the most recent event regardless of backend cursor ordering.
 */

import React, { useState, useEffect } from 'react';
import { Drawer } from '../ui/Drawer';
import { Badge } from '../ui/Badge';
import { Button } from '../ui/Button';
import { fetchEndpointTrajectory, fetchUserRiskScores, exportAssessmentJSON } from '../../services/api';
import type { EndpointModelPrediction, EndpointTrajectoryResponse } from '../../services/api';
import type { RiskEvent, HeuristicDetection } from '../../types/telemetry';
import { formatScore, getRiskLevel, parseCorrelatedSignals, THREAT_DECAY_WINDOW_MS, formatDateTime } from '../../utils/formatters';
import { Download, ShieldAlert, CheckCircle } from 'lucide-react';

export interface DrillDownDrawerProps {
  username: string | null;
  hostname?: string | null;
  agentId?: string | null;
  riskEvents?: RiskEvent[];
  onClose: () => void;
}

const EMPTY_RISK_EVENTS: RiskEvent[] = [];

export const DrillDownDrawer: React.FC<DrillDownDrawerProps> = ({
  username,
  hostname,
  agentId,
  riskEvents = EMPTY_RISK_EVENTS,
  onClose,
}) => {
  const [trajectory, setTrajectory] = useState<EndpointTrajectoryResponse | null>(null);
  const [prediction, setPrediction] = useState<EndpointModelPrediction | null>(null);
  const [latestEvent, setLatestEvent] = useState<RiskEvent | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!username) {
      setPrediction(null);
      setTrajectory(null);
      setLatestEvent(null);
      return;
    }

    let active = true;
    setIsLoading(true);
    setError(null);
    setPrediction(null);
    setTrajectory(null);

    Promise.allSettled([
      agentId ? fetchEndpointTrajectory(agentId) : Promise.resolve(null),
      hostname ? Promise.resolve({ ok: true, username, risk_scores: riskEvents.filter(
        (event) => event.hostname === hostname,
      ) }) : fetchUserRiskScores(username, 20),
    ])
      .then(([predResult, scoresResult]) => {
        if (!active) return;
        if (predResult.status === 'rejected') setError(`Model prediction unavailable: ${predResult.reason?.message || 'request failed'}`);
        if (predResult.status === 'fulfilled' && predResult.value) {
          setTrajectory(predResult.value);
          setPrediction(predResult.value.prediction);
        }
        if (scoresResult.status === 'rejected') setError((previous) => [previous, `Heuristic request failed: ${scoresResult.reason?.message || 'request failed'}`].filter(Boolean).join(' '));
        const scoresRes = scoresResult.status === 'fulfilled' ? scoresResult.value : { risk_scores: [] };
        const rawScores = scoresRes.risk_scores || [];
        // Defensively sort newest first to ensure index 0 is always the latest event
        const sortedScores = [...rawScores].sort(
          (a, b) => new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime()
        );
        setLatestEvent(sortedScores.length > 0 ? sortedScores[0] : null);
      })
      .finally(() => {
        if (active) setIsLoading(false);
      });

    return () => {
      active = false;
    };
  }, [username, hostname, agentId, riskEvents]);

  if (!username) return null;

  const currentScore = latestEvent && latestEvent.risk_score != null
    ? parseFloat(String(latestEvent.risk_score))
    : undefined;
  const currentLevel = getRiskLevel(currentScore ?? 0);
  const eventAge = latestEvent ? Date.now() - new Date(latestEvent.created_at).getTime() : Infinity;
  const isActive = latestEvent?.is_active ?? (eventAge >= -120000 && eventAge <= THREAT_DECAY_WINDOW_MS);
  const evaluatedPrediction = trajectory?.model_state === 'available' ? prediction : null;
  const signals = parseCorrelatedSignals(latestEvent?.correlated_signals_json);

  // Extract detections from latest signals
  const detections: HeuristicDetection[] = signals?.heuristics?.detections || [];
  const certScenarios = signals?.cert_scenarios || [];
  const processEvidence = signals?.process_evidence || [];
  const honeytoken = certScenarios.some((scenario) => scenario.id === 'HONEYTOKEN') ||
    detections.some((detection) => detection.scenario.toLowerCase().includes('honeytoken'));
  const tunneling = certScenarios.some((scenario) => scenario.id === 'NETWORK_TUNNELING') ||
    detections.some((detection) => detection.scenario.toLowerCase().includes('tunnel'));
  const recommendedAction = currentScore === undefined
    ? 'Risk assessment unavailable. Inspect the available telemetry and refresh the endpoint assessment.'
    : !isActive
    ? 'Historical finding. Review its evidence and event time before taking action.'
    : honeytoken && currentLevel === 'CRITICAL'
      ? 'Verify the decoy interaction and promptly contain the endpoint under the incident response procedure.'
      : tunneling
        ? 'Check the matched process name, command line, user, and time. Escalate confirmed unauthorized tunneling before containment.'
        : currentLevel === 'CRITICAL'
          ? 'Escalate immediately, verify the supporting evidence, and follow the containment procedure.'
          : currentLevel === 'HIGH'
            ? 'Investigate the supporting evidence and escalate confirmed suspicious activity.'
            : 'Review the finding and continue monitoring.';

  const handleExportJSON = () => {
    exportAssessmentJSON({
      username,
      hostname,
      timestamp: new Date().toISOString(),
      score: currentScore ?? null,
      level: currentLevel,
      prediction,
      latestEvent,
      heuristicDetections: detections,
    });
  };

  return (
    <Drawer
      isOpen={Boolean(username)}
      onClose={onClose}
      title={
        <div className="flex items-center gap-3">
          <span className="font-bold text-slate-900">{username}</span>
          {currentScore === undefined ? <span className="text-xs text-slate-500">Risk unavailable</span> : <Badge level={currentLevel} size="md" />}
          {latestEvent && !isActive && <span className="text-xs text-slate-500">Historical</span>}
        </div>
      }
      subtitle={`Target Identity: ${username} ${hostname ? `· Host: ${hostname}` : ''}`}
      width="2xl"
      footer={
        <>
          <Button variant="secondary" size="sm" onClick={handleExportJSON} icon={<Download className="w-3.5 h-3.5" />}>
            Export JSON
          </Button>
          <Button variant="primary" size="sm" onClick={onClose}>
            Close Assessment
          </Button>
        </>
      }
    >
      {isLoading ? (
        <div className="p-12 flex flex-col items-center justify-center text-slate-500 text-xs">
          <span className="w-5 h-5 border-2 border-slate-300 border-t-blue-600 rounded-full animate-spin mb-3" />
          Loading deep behavioral assessment...
        </div>
      ) : (
        <div className="space-y-6">
          {error && <div className="p-3 bg-amber-50 border border-amber-200 rounded-lg text-amber-800 text-xs">{error}. Heuristic evidence remains available below.</div>}
          {/* Metrics Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {/* Score */}
            <div className="bg-slate-50 border border-slate-200 rounded-lg p-3.5">
              <div className="text-[10px] uppercase font-semibold text-slate-500 tracking-wider">
                Heuristic Risk Score
              </div>
              <div className="text-xl font-bold font-mono text-slate-900 mt-1">
                {currentScore === undefined ? 'Unavailable' : formatScore(currentScore)}
                <span className="text-xs font-normal text-slate-400 ml-1">/ 100</span>
              </div>
            </div>

            {/* Risk Category */}
            <div className="bg-slate-50 border border-slate-200 rounded-lg p-3.5">
              <div className="text-[10px] uppercase font-semibold text-slate-500 tracking-wider">
                Risk Level
              </div>
              <div className="mt-1.5">
                {currentScore === undefined ? <span className="text-xs text-slate-500">Unavailable</span> : <Badge level={currentLevel} size="sm" />}
              </div>
            </div>

            {/* Behavioral Drift (RVFL) */}
            <div className="bg-slate-50 border border-slate-200 rounded-lg p-3.5">
              <div className="text-[10px] uppercase font-semibold text-slate-500 tracking-wider">
                RVFL Drift Error
              </div>
              <div className="text-sm font-mono font-bold text-slate-900 mt-1">
                {evaluatedPrediction?.drift_error == null ? 'Not evaluated' : evaluatedPrediction.drift_error.toFixed(5)}
              </div>
              <div className="text-[10px] text-slate-400 mt-0.5">
                {evaluatedPrediction?.drift_error == null ? 'No current drift measurement' : 'V3 drift measurement'}
              </div>
            </div>

            {/* Predicted Scenario */}
            <div className="bg-slate-50 border border-slate-200 rounded-lg p-3.5">
              <div className="text-[10px] uppercase font-semibold text-slate-500 tracking-wider">
                V3 Scenario
              </div>
              <div className="text-xs font-semibold text-slate-900 mt-1 truncate" title={evaluatedPrediction?.predicted_scenario || undefined}>
                {evaluatedPrediction?.predicted_scenario || 'Not evaluated'}
              </div>
              <div className="text-[10px] text-blue-600 font-mono mt-0.5">
                {evaluatedPrediction?.predicted_scenario && evaluatedPrediction.scenario_probabilities?.[evaluatedPrediction.predicted_scenario] != null
                  ? `${(evaluatedPrediction.scenario_probabilities[evaluatedPrediction.predicted_scenario] * 100).toFixed(1)}% classifier probability`
                  : '—'}
              </div>
            </div>
          </div>

          <section className="rounded-lg border border-indigo-100 bg-indigo-50/40 p-4">
            <div className="mb-3 text-[10px] font-semibold uppercase tracking-wider text-indigo-800">Model V3 · endpoint daily result</div>
            <div className="grid grid-cols-2 gap-3 text-xs md:grid-cols-4">
              <div><div className="text-slate-500">Threat probability</div><div className="mt-1 font-mono font-semibold">{evaluatedPrediction?.threat_probability == null ? 'Not evaluated' : `${(evaluatedPrediction.threat_probability * 100).toFixed(1)}%`}</div></div>
              <div><div className="text-slate-500">V3 fused risk</div><div className="mt-1 font-mono font-semibold">{evaluatedPrediction?.fused_risk == null ? 'Not evaluated' : evaluatedPrediction.fused_risk.toFixed(4)}</div></div>
              <div><div className="text-slate-500">Isolation Forest risk</div><div className="mt-1 font-mono font-semibold">{evaluatedPrediction?.if_risk == null ? 'Not evaluated' : evaluatedPrediction.if_risk.toFixed(4)}</div></div>
              <div><div className="text-slate-500">Temporal forecast</div><div className="mt-1 font-mono font-semibold">{evaluatedPrediction?.forecasted_risk == null ? 'Not evaluated' : evaluatedPrediction.forecasted_risk.toFixed(4)}</div></div>
            </div>
            {prediction && <div className="mt-3 text-[10px] text-slate-500">{evaluatedPrediction ? 'Current result' : 'Historical result'} · Observed-data status: {prediction.selection_status} · {prediction.observation_complete ? 'complete observation' : 'incomplete observation'} · Contract {prediction.feature_contract_version || 'unavailable'}</div>}
          </section>

          {/* Recommended Action Protocol */}
          <div className="bg-slate-50 border border-slate-200 rounded-lg p-4">
            <div className="text-xs font-semibold text-slate-900 mb-1 flex items-center gap-1.5">
              <ShieldAlert className="w-4 h-4 text-blue-600" />
              SOC Action Protocol
            </div>
            <p className="text-xs text-slate-600 leading-relaxed">
              {recommendedAction}
            </p>
          </div>

          <div className="text-[11px] text-slate-500">
            Model state: <span className="font-semibold">{trajectory?.model_state || (agentId ? 'loading' : 'endpoint identity unavailable')}</span>
            {prediction && <> · Day: {prediction.review_date} · {trajectory?.freshness_days === 0 ? 'current completed day' : `${trajectory?.freshness_days} day(s) old`} · {prediction.model_version || 'version unavailable'} · {prediction.source_kind}</>}
            {trajectory && <> · {trajectory.consecutive_complete_days} consecutive complete day(s); forecast {trajectory.forecast_ready ? 'ready' : 'warming up'}, review {trajectory.review_eligible ? 'eligible' : 'not eligible'}</>}
          </div>

          {/* Heuristic Rule Detections */}
          <div>
            <div className="text-xs font-semibold uppercase tracking-wider text-slate-500 mb-3">
              Heuristic Evidence ({detections.length})
            </div>

            {detections.length === 0 ? (
              <div className="flex items-center gap-2 p-4 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-600">
                <CheckCircle className="w-4 h-4 text-emerald-600 shrink-0" />
                <span>No heuristic rule evidence was recorded with this event.</span>
              </div>
            ) : (
              <div className="space-y-2">
                {detections.map((d, idx) => (
                  <div
                    key={idx}
                    className="p-3.5 bg-white border border-slate-200 rounded-lg shadow-2xs flex items-start justify-between gap-3"
                  >
                    <div className="space-y-1">
                      <div className="text-xs font-semibold text-slate-900">{d.scenario}</div>
                      <div className="text-[11px] text-slate-600 leading-normal">
                        {d.reasons && d.reasons.length > 0
                          ? d.reasons.join(', ')
                          : 'Triggered heuristic threshold rules'}
                      </div>
                    </div>
                    <div className="shrink-0 text-right">
                      <Badge level={d.severity} size="sm" />
                      <div className="text-[10px] font-mono text-slate-400 mt-1">
                        Rule score: {d.score || 0}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
          {certScenarios.length > 0 && (
            <section className="rounded-lg border border-slate-200 bg-slate-50 p-4">
              <div className="text-xs font-semibold uppercase tracking-wider text-slate-600 mb-2">Correlated scenario labels</div>
              <div className="space-y-1 text-xs text-slate-700">
                {certScenarios.map((scenario) => (
                  <div key={scenario.id}><strong>{scenario.id}</strong> · {scenario.description}</div>
                ))}
              </div>
              <p className="mt-2 text-[10px] text-slate-500">Scenario labels support the same event; they are not additional weighted detections.</p>
            </section>
          )}
          {tunneling && processEvidence.length === 0 && (
            <p className="text-xs text-amber-800">Matched process details were not stored with this event. Inspect its raw process watcher telemetry before deciding on containment.</p>
          )}
          {processEvidence.length > 0 && (
            <section className="rounded-lg border border-slate-200 bg-white p-4">
              <div className="text-xs font-semibold uppercase tracking-wider text-slate-600 mb-2">Matched process evidence</div>
              <div className="space-y-2">
                {processEvidence.map((process, index) => (
                  <div key={`${process.pid ?? 'unknown'}-${index}`} className="rounded border border-slate-200 p-2 text-xs text-slate-700">
                    <div><strong>{process.name || 'Unknown process'}</strong> · PID {process.pid ?? 'unknown'} · {formatDateTime(process.observed_at)}</div>
                    {process.command_line && <div className="mt-1 break-all font-mono text-[11px]">{process.command_line}</div>}
                    {process.source && <div className="mt-1 text-[10px] text-slate-500">Source: {process.source}</div>}
                  </div>
                ))}
              </div>
            </section>
          )}
        </div>
      )}
    </Drawer>
  );
};
