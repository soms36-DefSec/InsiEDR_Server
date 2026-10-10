/**
 * InsiEDR Forensic Formatting & Normalization Utilities
 * ====================================================
 *
 * Architectural Role:
 *   Centralized parsing, risk threshold classification, threat decay timing,
 *   and temporal formatting routines used across both the core SOC console
 *   and modular developer plugins.
 *
 * Risk Thresholds:
 *   - CRITICAL: >= 85.0
 *   - HIGH:     >= 60.0 and < 85.0
 *   - MEDIUM:   >= 35.0 and < 60.0
 *   - LOW:      < 35.0
 *
 * Threat Decay:
 *   - 30-minute rolling decay window (`THREAT_DECAY_WINDOW_MS`) to reduce analyst
 *     fatigue from transient bursts while preserving audit records.
 */

import type { CorrelatedSignals, RiskEvent, RiskLevel, TelemetryLog } from '../types/telemetry';

export const THREAT_DECAY_WINDOW_MS = 30 * 60 * 1000; // 30-minute rolling threat decay

export function formatScore(score: number | string | null | undefined): string {
  if (score === null || score === undefined || score === '') return '0.0';
  const num = typeof score === 'number' ? score : parseFloat(score);
  if (isNaN(num) || num === 0) return '0.0';
  if (num < 1.0) {
    let s = num.toFixed(6).replace(/0+$/, '');
    if (s.endsWith('.')) s += '0';
    return s;
  }
  if (num < 10.0) {
    let s = num.toFixed(4).replace(/0+$/, '');
    if (s.endsWith('.')) s += '0';
    return s;
  }
  return num.toFixed(2);
}

export function getRiskLevel(score: number | string | null | undefined): RiskLevel {
  const num = typeof score === 'number' ? score : parseFloat(String(score || 0));
  if (num >= 85.0) return 'CRITICAL';
  if (num >= 60.0) return 'HIGH';
  if (num >= 35.0) return 'MEDIUM';
  return 'LOW';
}

export function parseCorrelatedSignals(signals: unknown): CorrelatedSignals | null {
  if (!signals) return null;
  if (typeof signals === 'object') return signals as CorrelatedSignals;
  if (typeof signals === 'string') {
    try {
      return JSON.parse(signals) as CorrelatedSignals;
    } catch {
      return null;
    }
  }
  return null;
}

export function extractEventSummary(event: RiskEvent): string {
  if (!event) return 'Security event';
  const signals = parseCorrelatedSignals(event.correlated_signals_json);
  
  if (signals?.cert_scenarios && signals.cert_scenarios.length > 0) {
    return signals.cert_scenarios.map((s) => s.description || s.id).join(', ');
  }
  if (signals?.heuristics?.detections && signals.heuristics.detections.length > 0) {
    return signals.heuristics.detections[0].scenario;
  }
  if (signals?.predicted_scenario?.scenario && signals.predicted_scenario.scenario !== 'normal') {
    return signals.predicted_scenario.scenario;
  }
  return event.summary || 'Security event logged';
}

export function timeAgo(dateStr: string | null | undefined): string {
  if (!dateStr) return 'N/A';
  const date = new Date(dateStr);
  if (isNaN(date.getTime())) return String(dateStr);
  
  const seconds = Math.floor((Date.now() - date.getTime()) / 1000);
  if (seconds < 5) return 'just now';
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

export function formatDateTime(dateStr: string | null | undefined): string {
  if (!dateStr) return '—';
  const date = new Date(dateStr);
  if (isNaN(date.getTime())) return String(dateStr);
  return date.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

function formatPreviewValue(val: unknown): string {
  if (val === null || val === undefined) return '';
  if (Array.isArray(val)) {
    if (val.length === 0) return '[]';
    const first = val[0];
    if (typeof first === 'object' && first !== null) {
      const names = (val as Array<Record<string, unknown>>)
        .slice(0, 3)
        .map((item) => String(item?.name || item?.process_name || item?.command || item?.path || item?.id || 'item'))
        .filter(Boolean)
        .join(', ');
      return `${val.length} items (${names}${val.length > 3 ? '...' : ''})`;
    }
    return val.slice(0, 3).map(String).join(', ') + (val.length > 3 ? '...' : '');
  }
  if (typeof val === 'object') {
    const subKeys = Object.keys(val as Record<string, unknown>);
    return `{${subKeys.slice(0, 2).join(', ')}${subKeys.length > 2 ? '...' : ''}}`;
  }
  return String(val);
}

/**
 * Extracts a concise human-readable preview of up to 3 telemetry key/value attributes.
 * Safely unwraps nested agent envelope structures without throwing on malformed JSON.
 */
export function extractLogPreview(log: TelemetryLog): string {
  if (!log.payload) return 'Heartbeat telemetry';
  try {
    let p: Record<string, unknown> =
      typeof log.payload === 'string'
        ? JSON.parse(log.payload)
        : (log.payload as Record<string, unknown>);
    if (p && p.payload && p.status && p.collector) {
      p = p.payload as Record<string, unknown>;
    }
    const keys = Object.keys(p);
    if (keys.length === 0) return 'Heartbeat telemetry';
    const preview = keys
      .slice(0, 3)
      .map((k) => `${k}: ${formatPreviewValue(p[k])}`)
      .join(' · ');
    return keys.length > 3 ? `${preview} (+${keys.length - 3} more)` : preview;
  } catch {
    return String(log.payload || 'Telemetry');
  }
}


