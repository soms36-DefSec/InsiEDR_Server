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
import { fetchUserPredictions, fetchUserRiskScores, exportAssessmentJSON } from '../../services/api';
import type { UserPrediction, RiskEvent, HeuristicDetection } from '../../types/telemetry';
import { formatScore, getRiskLevel, parseCorrelatedSignals } from '../../utils/formatters';
import { Download, ShieldAlert, CheckCircle } from 'lucide-react';

export interface DrillDownDrawerProps {
  username: string | null;
  hostname?: string | null;
  onClose: () => void;
}

export const DrillDownDrawer: React.FC<DrillDownDrawerProps> = ({
  username,
  hostname,
  onClose,
}) => {
  const [prediction, setPrediction] = useState<UserPrediction | null>(null);
  const [latestEvent, setLatestEvent] = useState<RiskEvent | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!username) {
      setPrediction(null);
      setLatestEvent(null);
      return;
    }

    let active = true;
    setIsLoading(true);
    setError(null);

    Promise.all([
      fetchUserPredictions(username).catch(() => ({ ok: false, username, predictions: null })),
      fetchUserRiskScores(username, 20).catch(() => ({ ok: false, username, risk_scores: [] })),
    ])
      .then(([predRes, scoresRes]) => {
        if (!active) return;
        setPrediction(predRes.predictions || null);
        const rawScores = scoresRes.risk_scores || [];
        // Defensively sort newest first to ensure index 0 is always the latest event
        const sortedScores = [...rawScores].sort(
          (a, b) => new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime()
        );
        setLatestEvent(sortedScores.length > 0 ? sortedScores[0] : null);
      })
      .catch((err) => {
        if (!active) return;
        setError(err.message || 'Failed to load assessment data');
      })
      .finally(() => {
        if (active) setIsLoading(false);
      });

    return () => {
      active = false;
    };
  }, [username]);

  if (!username) return null;

  const currentScore = latestEvent
    ? parseFloat(String(latestEvent.risk_score || 0))
    : prediction?.score || 0;
  const currentLevel = getRiskLevel(currentScore);

  // Extract detections from latest signals
  const detections: HeuristicDetection[] = [];
  if (latestEvent?.correlated_signals_json) {
    const signals = parseCorrelatedSignals(latestEvent.correlated_signals_json);
    if (signals?.heuristics?.detections) {
      detections.push(...signals.heuristics.detections);
    }
    if (signals?.cert_scenarios) {
      signals.cert_scenarios.forEach((cs) => {
        detections.push({
          scenario: cs.id,
          severity: 'HIGH',
          score: 65,
          reasons: [cs.description],
        });
      });
    }
  }

  const handleExportJSON = () => {
    exportAssessmentJSON({
      username,
      hostname,
      timestamp: new Date().toISOString(),
      score: currentScore,
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
          <Badge level={currentLevel} size="md" />
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
      ) : error ? (
        <div className="p-4 bg-rose-50 border border-rose-200 rounded-lg text-rose-700 text-xs">
          {error}
        </div>
      ) : (
        <div className="space-y-6">
          {/* Metrics Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {/* Score */}
            <div className="bg-slate-50 border border-slate-200 rounded-lg p-3.5">
              <div className="text-[10px] uppercase font-semibold text-slate-500 tracking-wider">
                Risk Score
              </div>
              <div className="text-xl font-bold font-mono text-slate-900 mt-1">
                {formatScore(currentScore)}
                <span className="text-xs font-normal text-slate-400 ml-1">/ 100</span>
              </div>
            </div>

            {/* Risk Category */}
            <div className="bg-slate-50 border border-slate-200 rounded-lg p-3.5">
              <div className="text-[10px] uppercase font-semibold text-slate-500 tracking-wider">
                Risk Level
              </div>
              <div className="mt-1.5">
                <Badge level={currentLevel} size="sm" />
              </div>
            </div>

            {/* Behavioral Drift (RVFL) */}
            <div className="bg-slate-50 border border-slate-200 rounded-lg p-3.5">
              <div className="text-[10px] uppercase font-semibold text-slate-500 tracking-wider">
                RVFL Drift Error
              </div>
              <div className="text-sm font-mono font-bold text-slate-900 mt-1">
                {prediction ? prediction.rvfl_error.toFixed(5) : '0.00000'}
              </div>
              <div className="text-[10px] text-slate-400 mt-0.5">
                {prediction?.behavioral_risk || 'LOW'} deviation
              </div>
            </div>

            {/* Predicted Scenario */}
            <div className="bg-slate-50 border border-slate-200 rounded-lg p-3.5">
              <div className="text-[10px] uppercase font-semibold text-slate-500 tracking-wider">
                XGBoost Scenario
              </div>
              <div className="text-xs font-semibold text-slate-900 mt-1 truncate" title={prediction?.predicted_scenario?.scenario}>
                {prediction?.predicted_scenario?.scenario || 'Normal'}
              </div>
              <div className="text-[10px] text-blue-600 font-mono mt-0.5">
                {prediction?.predicted_scenario?.confidence
                  ? `${(prediction.predicted_scenario.confidence * 100).toFixed(1)}% conf`
                  : '—'}
              </div>
            </div>
          </div>

          {/* Recommended Action Protocol */}
          <div className="bg-slate-50 border border-slate-200 rounded-lg p-4">
            <div className="text-xs font-semibold text-slate-900 mb-1 flex items-center gap-1.5">
              <ShieldAlert className="w-4 h-4 text-blue-600" />
              SOC Action Protocol
            </div>
            <p className="text-xs text-slate-600 leading-relaxed">
              {prediction?.recommended_action ||
                (currentScore >= 60
                  ? 'Isolate endpoint and conduct deep packet inspection immediately.'
                  : 'Routine baseline monitoring. No active intervention required.')}
            </p>
          </div>

          {/* Heuristic Rule Detections */}
          <div>
            <div className="text-xs font-semibold uppercase tracking-wider text-slate-500 mb-3">
              Active Heuristic Violations & Correlated Evidence ({detections.length})
            </div>

            {detections.length === 0 ? (
              <div className="flex items-center gap-2 p-4 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-600">
                <CheckCircle className="w-4 h-4 text-emerald-600 shrink-0" />
                <span>No active heuristic violations detected. Endpoint operating normally within baseline.</span>
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
                        Weight: {d.score || 0}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </Drawer>
  );
};
