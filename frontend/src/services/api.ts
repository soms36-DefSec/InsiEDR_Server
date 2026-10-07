/**
 * InsiEDR REST API Service Gateway
 * =================================
 *
 * Architectural Role:
 *   Acts as the unified HTTP communication layer between the React dashboard
 *   and the backend FastAPI server. Encapsulates all REST endpoint routes,
 *   query serialization, response deserialization, error handling, and file downloads.
 *
 * Primary Responsibilities:
 *   1. REST Queries: Strongly-typed queries for summary, health, threats, logs, and ML predictions.
 *   2. Server-Side Streaming Exports: Triggers chunked, memory-bounded CSV/NDJSON exports via `/api/v1/export/*`.
 *   3. Client-Side Exports: Generates instant browser CSV/JSON downloads for filtered in-memory datasets.
 *
 * Backend URL Compatibility:
 *   - Supports both `/api/*` and `/api/v1/*` FastAPI route aliases.
 *   - Automatically encodes path parameters (e.g. `encodeURIComponent(username)`).
 */

import type {
  DashboardSummary,
  SystemHealth,
  RiskEvent,
  UserPredictionResponse,
  UserRiskScoresResponse,
  TelemetryResponse,
  TelemetryLog,
  EndpointRow,
  TamperAlertsResponse,
} from '../types/telemetry';

/**
 * Generic fetch wrapper that validates HTTP status codes and parses JSON responses.
 *
 * @throws {Error} Detailed error containing status code and status text if the request fails.
 */
export async function fetchApi<T>(url: string, options?: RequestInit): Promise<T> {
  const res = await fetch(url, options);
  if (!res.ok) {
    let errorDetail = res.statusText;
    try {
      const errJson = await res.json();
      if (errJson?.error?.message) {
        errorDetail = errJson.error.message;
      }
    } catch {
      // Non-JSON response body; keep standard statusText
    }
    throw new Error(`API request failed [${res.status}]: ${errorDetail}`);
  }
  return res.json() as Promise<T>;
}

/**
 * Fetches the aggregated fleet overview, risk severity counts, and latest risk events.
 * Maps to `GET /api/dashboard-summary`.
 */
export async function fetchDashboardSummary(signal?: AbortSignal): Promise<DashboardSummary> {
  return fetchApi<DashboardSummary>('/api/dashboard-summary', { signal });
}

/**
 * Checks system component health: database connectivity, ML model pipeline readiness,
 * and background task queue metrics.
 * Maps to `GET /api/health`.
 */
export async function fetchHealth(signal?: AbortSignal): Promise<SystemHealth> {
  return fetchApi<SystemHealth>('/api/health', { signal });
}

/**
 * Retrieves recent agent tamper anomalies (heartbeat gaps, clock tampering, process stops).
 * Maps to `GET /api/v1/agents/tamper-alerts`.
 */
export async function fetchTamperAlerts(limit = 50): Promise<TamperAlertsResponse> {
  return fetchApi<TamperAlertsResponse>(`/api/v1/agents/tamper-alerts?limit=${limit}`);
}

/**
 * Fetches chronological risk events with pagination.
 * Maps to `GET /api/risk-events`.
 */
export async function fetchRiskEvents(limit = 500, offset = 0): Promise<{ ok: boolean; risk_events: RiskEvent[] }> {
  return fetchApi<{ ok: boolean; risk_events: RiskEvent[] }>(`/api/risk-events?limit=${limit}&offset=${offset}`);
}

/**
 * Queries deep behavioral ML predictions (RVFL drift error, XGBoost scenario classification)
 * for a specific user identity.
 * Maps to `GET /api/user-predictions/{username}`.
 */
export async function fetchUserPredictions(username: string): Promise<UserPredictionResponse> {
  return fetchApi<UserPredictionResponse>(`/api/user-predictions/${encodeURIComponent(username)}`);
}

/**
 * Fetches chronological risk events for a specific user identity.
 * Note: The backend returns records ordered with newest first (`ORDER BY created_at DESC`).
 * Maps to `GET /api/user-risk-scores/{username}`.
 */
export async function fetchUserRiskScores(username: string, limit = 20): Promise<UserRiskScoresResponse> {
  return fetchApi<UserRiskScoresResponse>(`/api/user-risk-scores/${encodeURIComponent(username)}?limit=${limit}`);
}

/**
 * Queries raw telemetry logs with multi-parameter filtering (collector domain, username, pagination).
 * Maps to `GET /api/telemetry`.
 */
export async function fetchTelemetry(
  limit = 25,
  offset = 0,
  collector?: string | null,
  username?: string | null,
  filters: { search?: string; status?: string; start_time?: string; end_time?: string; signal?: AbortSignal } = {},
): Promise<TelemetryResponse> {
  const params = new URLSearchParams({
    limit: String(limit),
    offset: String(offset),
    include_enrichment: 'false',
  });
  if (collector) params.set('collector', collector);
  if (username) params.set('username', username);
  for (const key of ['search', 'status', 'start_time', 'end_time'] as const) {
    if (filters[key]) params.set(key, filters[key]);
  }

  return fetchApi<TelemetryResponse>(`/api/telemetry?${params.toString()}`, { signal: filters.signal });
}

/**
 * Triggers a memory-efficient chunked streaming data export directly from the FastAPI server.
 * Opens the download stream in a new browser context.
 *
 * @param type 'logs' for raw telemetry or 'threats' for correlated risk events.
 * @param format 'csv' or 'json' / 'ndjson'.
 * @param filters Optional filtering parameters.
 */
export function triggerServerExport(
  type: 'logs' | 'threats',
  format: 'csv' | 'json' = 'csv',
  filters?: { collector?: string | null; username?: string | null; limit?: number }
): void {
  const params = new URLSearchParams();
  params.set('format', format);
  if (filters?.limit) params.set('limit', String(filters.limit));
  if (filters?.collector && filters.collector !== 'all') params.set('collector', filters.collector);
  if (filters?.username) params.set('username', filters.username);
  const url = `/api/v1/export/${type}?${params.toString()}`;
  window.open(url, '_blank');
}

/**
 * Triggers a download of the ML Model Training Dataset from the FastAPI server.
 * Allows filtering by specific user, rolling N-day window, and output format (Excel .xlsx, CSV, NDJSON).
 */
export function triggerTrainingDatasetExport(options: {
  username?: string | null;
  days?: number;
  format?: 'xlsx' | 'csv' | 'json';
  limit?: number;
}): void {
  const params = new URLSearchParams();
  const format = options.format || 'xlsx';
  params.set('format', format);
  if (options.days && options.days > 0) params.set('days', String(options.days));
  if (options.username && options.username.trim() !== '') {
    params.set('username', options.username.trim());
  }
  if (options.limit && options.limit > 0) params.set('limit', String(options.limit));

  const ext = format === 'xlsx' ? 'xlsx' : (format === 'json' ? 'json' : 'csv');
  const url = `/api/v1/export/training-dataset.${ext}?${params.toString()}`;
  window.open(url, '_blank');
}

/**
 * Securely triggers a client-side file download via a synthetic Blob URL,
 * ensuring proper DOM detachment and memory cleanup.
 */
export function downloadFile(content: string, filename: string, mimeType = 'text/csv;charset=utf-8;'): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/**
 * Generates and downloads a CSV export of active fleet endpoints and their risk postures.
 */
export function exportFleetRiskCSV(endpoints: EndpointRow[]): void {
  let csv = 'Hostname,Username,Risk_Score,Risk_Level,Status,Last_Seen\n';
  endpoints.forEach((ep) => {
    csv += `"${ep.hostname || ''}","${ep.user || ''}",${ep.score.toFixed(2)},"${ep.level}","${
      ep.isOnline ? 'ONLINE' : 'OFFLINE'
    }","${ep.lastSeen || ''}"\n`;
  });
  downloadFile(csv, `insiedr_fleet_risk_${Date.now()}.csv`);
}

/**
 * Generates and downloads a CSV export of visible telemetry logs.
 */
export function exportTelemetryCSV(logs: TelemetryLog[]): void {
  let csv = 'Timestamp,Hostname,Username,Collector,Status\n';
  logs.forEach((log) => {
    csv += `"${log.collected_at || ''}","${log.hostname || ''}","${log.username || ''}","${log.collector || ''}","${
      log.status || ''
    }"\n`;
  });
  downloadFile(csv, `insiedr_telemetry_logs_${Date.now()}.csv`);
}

/**
 * Generates and downloads a JSON export of visible telemetry logs.
 */
export function exportTelemetryJSON(logs: TelemetryLog[]): void {
  downloadFile(JSON.stringify(logs, null, 2), `insiedr_telemetry_logs_${Date.now()}.json`, 'application/json');
}

/**
 * Generates and downloads a JSON export of a user's deep-dive behavioral assessment.
 */
export function exportAssessmentJSON(assessment: Record<string, unknown>): void {
  const user = (assessment.username as string) || 'endpoint';
  downloadFile(JSON.stringify(assessment, null, 2), `insiedr_assessment_${user}_${Date.now()}.json`, 'application/json');
}

export interface CollectorPreviewResponse {
  ok: boolean;
  collector: string;
  total_samples: number;
  columns: string[];
  feature_columns: string[];
  preview_rows: Record<string, unknown>[];
  filename: string;
}

/**
 * Fetches the list of available collectors and fleet usernames for dataset export filtering.
 */
export async function fetchAvailableCollectors(): Promise<{ ok: boolean; collectors: string[]; usernames: string[] }> {
  return fetchApi<{ ok: boolean; collectors: string[]; usernames: string[] }>('/api/v1/export/collectors');
}

/**
 * Fetches a schema preview and sample matching records for a selected collector.
 */
export async function fetchCollectorPreview(options: {
  collector: string;
  startDate?: string | null;
  endDate?: string | null;
  username?: string | null;
  limit?: number;
}): Promise<CollectorPreviewResponse> {
  const params = new URLSearchParams({ collector: options.collector });
  if (options.startDate) params.set('start_date', options.startDate);
  if (options.endDate) params.set('end_date', options.endDate);
  if (options.username && options.username.trim() !== '') {
    params.set('username', options.username.trim());
  }
  if (options.limit) params.set('limit', String(options.limit));

  return fetchApi<CollectorPreviewResponse>(`/api/v1/export/collector-preview?${params.toString()}`);
}

/**
 * Triggers a download of a collector-specific dataset with unrolled feature columns.
 */
export function triggerCollectorDatasetExport(options: {
  collector: string;
  startDate?: string | null;
  endDate?: string | null;
  username?: string | null;
  limit?: number;
}): void {
  const params = new URLSearchParams({ collector: options.collector });
  if (options.startDate) params.set('start_date', options.startDate);
  if (options.endDate) params.set('end_date', options.endDate);
  if (options.username && options.username.trim() !== '') {
    params.set('username', options.username.trim());
  }
  if (options.limit && options.limit > 0) {
    params.set('limit', String(options.limit));
  }

  const url = `/api/v1/export/collector-dataset.csv?${params.toString()}`;
  window.open(url, '_blank');
}
