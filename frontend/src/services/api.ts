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
  TelemetryExplorerResponse,
  TelemetryHistogramResponse,
  TelemetryEventDetailResponse,
  TelemetryLog,
  EndpointRow,
  TamperAlertsResponse,
} from '../types/telemetry';

export const TIMEOUT_CONFIG = {
  DEFAULT_READ_MS: 15000,    // Bound interactive waits; views retain timestamped data
  PREVIEW_MS: 120000,        // 120s for schema and dataset previews
  EXPORT_MS: 180000,         // 180s for dataset downloads and streaming exports
  HEALTH_MS: 15000,          // 15s for liveness and health probes
};

const DEFAULT_TIMEOUT_MS = TIMEOUT_CONFIG.DEFAULT_READ_MS;

const OPERATOR_KEY_STORAGE = 'insiedr.operatorApiKey';

/** Keep the operator credential only for this browser tab's session. */
export function getOperatorApiKey(): string {
  try {
    return window.sessionStorage.getItem(OPERATOR_KEY_STORAGE) || '';
  } catch {
    return '';
  }
}

export function setOperatorApiKey(value: string): void {
  try {
    if (value) window.sessionStorage.setItem(OPERATOR_KEY_STORAGE, value);
    else window.sessionStorage.removeItem(OPERATOR_KEY_STORAGE);
  } catch {
    // The app can still run without session storage when operator auth is disabled.
  }
}

export async function fetchApi<T>(url: string, options?: RequestInit & { timeoutMs?: number }): Promise<T> {
  const timeoutMs = options?.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort(new Error(`API request timed out after ${timeoutMs}ms: ${url}`));
  }, timeoutMs);

  const callerSignal = options?.signal;
  let abortHandler: (() => void) | undefined;
  if (callerSignal) {
    if (callerSignal.aborted) {
      clearTimeout(timer);
      throw callerSignal.reason instanceof Error ? callerSignal.reason : new Error('Request aborted');
    }
    abortHandler = () => controller.abort(callerSignal.reason);
    callerSignal.addEventListener('abort', abortHandler, { once: true });
  }

  try {
    const headers = new Headers(options?.headers);
    const operatorKey = getOperatorApiKey();
    if (operatorKey && !headers.has('X-Operator-Key')) {
      headers.set('X-Operator-Key', operatorKey);
    }
    const res = await fetch(url, {
      ...options,
      headers,
      cache: 'no-store',
      signal: controller.signal,
    });
    if (!res.ok) {
      let errorDetail = res.statusText;
      try {
        const errJson = await res.json();
        if (errJson?.error?.message) {
          errorDetail = errJson.error.message;
        } else if (typeof errJson?.error === 'string') {
          errorDetail = errJson.error;
        }
      } catch {
        // Non-JSON response body; keep standard statusText
      }
      throw new Error(`API request failed [${res.status}]: ${errorDetail}`);
    }
    const data = (await res.json()) as T;
    return data;
  } catch (err: unknown) {
    if (callerSignal?.aborted) {
      throw err;
    }
    if (timedOut) {
      throw new Error(`API request timed out after ${timeoutMs}ms: ${url}`);
    }
    throw err;
  } finally {
    clearTimeout(timer);
    if (callerSignal && abortHandler) {
      callerSignal.removeEventListener('abort', abortHandler);
    }
  }
}

/**
 * Fetches the aggregated fleet overview, risk severity counts, and latest risk events.
 * Maps to `GET /api/dashboard-summary`.
 */
export async function fetchDashboardSummary(signal?: AbortSignal): Promise<DashboardSummary> {
  return fetchApi<DashboardSummary>('/api/dashboard-summary?include_stats=false', {
    signal,
    timeoutMs: TIMEOUT_CONFIG.DEFAULT_READ_MS,
  });
}

/**
 * Checks system component health: database connectivity, ML model pipeline readiness,
 * and background task queue metrics.
 * Maps to `GET /api/health`.
 */
export async function fetchHealth(signal?: AbortSignal): Promise<SystemHealth> {
  return fetchApi<SystemHealth>('/api/health', { signal, timeoutMs: TIMEOUT_CONFIG.HEALTH_MS });
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
  filters: { search?: string; status?: string; start_time?: string; end_time?: string; signal?: AbortSignal;
    cursor?: string; include_total?: boolean; search_scope?: 'metadata' | 'payload' } = {},
): Promise<TelemetryResponse> {
  const params = new URLSearchParams({
    limit: String(limit),
    offset: String(offset),
    include_enrichment: 'false',
  });
  if (collector) params.set('collector', collector);
  if (username) params.set('username', username);
  if (filters.include_total !== undefined) params.set('include_total', String(filters.include_total));
  for (const key of ['search', 'status', 'start_time', 'end_time', 'cursor', 'search_scope'] as const) {
    if (filters[key]) params.set(key, filters[key]);
  }

  return fetchApi<TelemetryResponse>(`/api/telemetry?${params.toString()}`, { signal: filters.signal, timeoutMs: TIMEOUT_CONFIG.DEFAULT_READ_MS });
}

/**
 * Queries lightweight projected telemetry logs via the CQRS Split-View engine.
 * Maps to `GET /api/v1/telemetry/explorer`.
 */
export async function fetchTelemetryExplorer(
  limit = 50,
  cursor?: string | null,
  collector?: string | null,
  username?: string | null,
  filters: {
    search?: string;
    status?: string;
    start_time?: string;
    end_time?: string;
    agent_id?: string;
    include_total?: boolean;
    search_scope?: string;
    offset?: number;
    signal?: AbortSignal;
  } = {},
): Promise<TelemetryExplorerResponse> {
  const params = new URLSearchParams({ limit: String(limit) });
  if (cursor) params.set('cursor', cursor);
  if (collector && collector !== 'all') params.set('collector', collector);
  if (username) params.set('username', username);
  if (filters.search) params.set('search', filters.search);
  if (filters.status && filters.status !== 'all') params.set('status', filters.status);
  if (filters.start_time) params.set('start_time', filters.start_time);
  if (filters.end_time) params.set('end_time', filters.end_time);
  if (filters.agent_id) params.set('agent_id', filters.agent_id);
  if (filters.include_total !== undefined) params.set('include_total', String(filters.include_total));
  if (filters.search_scope) params.set('search_scope', filters.search_scope);
  if (filters.offset !== undefined) params.set('offset', String(filters.offset));

  return fetchApi<TelemetryExplorerResponse>(`/api/v1/telemetry/explorer?${params.toString()}`, {
    signal: filters.signal,
    timeoutMs: TIMEOUT_CONFIG.DEFAULT_READ_MS,
  });
}

/**
 * On-demand deep forensic event payload inspection drawer fetcher.
 * Maps to `GET /api/v1/telemetry/events/{eventId}`.
 */
export async function fetchTelemetryEventDetail(eventId: string | number, signal?: AbortSignal): Promise<TelemetryEventDetailResponse> {
  return fetchApi<TelemetryEventDetailResponse>(`/api/v1/telemetry/events/${encodeURIComponent(String(eventId))}`, { signal });
}

/**
 * Server-side event frequency histogram aggregation query.
 * Maps to `GET /api/v1/telemetry/histogram`.
 */
export async function fetchTelemetryHistogram(
  timeRange = '1h',
  filters: { collector?: string | null; status?: string | null; agent_id?: string | null;
    start_time?: string | null; end_time?: string | null; signal?: AbortSignal } = {},
): Promise<TelemetryHistogramResponse> {
  const params = new URLSearchParams({ time_range: timeRange });
  if (filters.collector && filters.collector !== 'all') params.set('collector', filters.collector);
  if (filters.status && filters.status !== 'all') params.set('status', filters.status);
  if (filters.agent_id) params.set('agent_id', filters.agent_id);
  if (filters.start_time) params.set('start_time', filters.start_time);
  if (filters.end_time) params.set('end_time', filters.end_time);

  return fetchApi<TelemetryHistogramResponse>(`/api/v1/telemetry/histogram?${params.toString()}`, {
    signal: filters.signal,
    timeoutMs: 30000,
  });
}

/**
 * Triggers a memory-efficient chunked streaming data export directly from the FastAPI server.
 * Opens the download stream in a new browser context.
 *
 * @param type 'logs' for raw telemetry or 'threats' for correlated risk events.
 * @param format 'csv' or 'json' / 'ndjson'.
 * @param filters Optional filtering parameters.
 */
export interface ServerExportFilters {
  collector?: string | null;
  username?: string | null;
  status?: string | null;
  search?: string | null;
  start_time?: string | null;
  end_time?: string | null;
  agent_id?: string | null;
  limit?: number;
}

export async function triggerServerExport(
  type: 'logs' | 'threats',
  format: 'csv' | 'json' = 'csv',
  filters?: ServerExportFilters
): Promise<void> {
  const params = new URLSearchParams();
  params.set('format', format);
  if (filters?.limit) params.set('limit', String(filters.limit));
  if (filters?.collector && filters.collector !== 'all') params.set('collector', filters.collector);
  if (filters?.username) params.set('username', filters.username);
  if (filters?.status && filters.status !== 'all') params.set('status', filters.status);
  if (filters?.search) params.set('search', filters.search);
  if (filters?.start_time) params.set('start_time', filters.start_time);
  if (filters?.end_time) params.set('end_time', filters.end_time);
  if (filters?.agent_id) params.set('agent_id', filters.agent_id);

  const url = `/api/v1/export/${type}?${params.toString()}`;
  try {
    const headers = new Headers();
    const operatorKey = getOperatorApiKey();
    if (operatorKey) headers.set('X-Operator-Key', operatorKey);
    const res = await fetch(url, { headers });
    if (!res.ok) {
      let msg = res.statusText;
      try {
        const errJson = await res.json();
        if (errJson?.error?.message || errJson?.error) {
          msg = errJson.error.message || errJson.error;
        }
      } catch {
        // fallback
      }
      throw new Error(`Export failed [${res.status}]: ${msg}`);
    }
    const blob = await res.blob();
    const ext = format === 'json' ? 'jsonl' : 'csv';
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    downloadBlob(blob, `insiedr_${type}_export_${timestamp}.${ext}`);
  } catch (err) {
    console.warn('Authenticated blob export encountered an error, falling back to direct stream:', err);
    window.open(url, '_blank');
  }
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
  downloadBlob(blob, filename);
}

export function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function escapeCsvCell(val: unknown): string {
  if (val === null || val === undefined) return '""';
  const str = String(val);
  return `"${str.replace(/"/g, '""')}"`;
}

/**
 * Generates and downloads a CSV export of active fleet endpoints and their risk postures.
 */
export function exportFleetRiskCSV(endpoints: EndpointRow[]): void {
  let csv = 'Hostname,Username,Risk_Score,Risk_Level,Status,Last_Seen\n';
  endpoints.forEach((ep) => {
    csv += `${escapeCsvCell(ep.hostname)},${escapeCsvCell(ep.user)},${ep.score.toFixed(2)},${escapeCsvCell(ep.level)},${
      escapeCsvCell(ep.isOnline ? 'ONLINE' : 'OFFLINE')
    },${escapeCsvCell(ep.lastSeen || '')}\n`;
  });
  downloadFile(csv, `insiedr_fleet_risk_${Date.now()}.csv`);
}

/**
 * Generates and downloads an RFC-4180 compliant CSV export of visible telemetry logs with complete forensic fields.
 */
export function exportTelemetryCSV(logs: TelemetryLog[]): void {
  let csv = 'Event_ID,Timestamp,Agent_ID,Hostname,Username,Collector,Status,Summary_Preview\n';
  logs.forEach((log) => {
    const eid = log.event_id || log.id || '';
    const ts = log.timestamp || log.collected_at || '';
    const aid = log.agent_id || '';
    const host = log.hostname || '';
    const user = log.username || '';
    const col = log.collector_name || log.collector || '';
    const stat = log.status || '';
    const summary = log.summary_preview || '';
    csv += `${escapeCsvCell(eid)},${escapeCsvCell(ts)},${escapeCsvCell(aid)},${escapeCsvCell(host)},${escapeCsvCell(user)},${escapeCsvCell(col)},${escapeCsvCell(stat)},${escapeCsvCell(summary)}\n`;
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
export async function fetchAvailableCollectors(signal?: AbortSignal): Promise<{ ok: boolean; collectors: string[]; usernames: string[] }> {
  return fetchApi<{ ok: boolean; collectors: string[]; usernames: string[] }>('/api/v1/export/collectors', { signal, timeoutMs: TIMEOUT_CONFIG.PREVIEW_MS });
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
  signal?: AbortSignal;
}): Promise<CollectorPreviewResponse> {
  const params = new URLSearchParams({ collector: options.collector });
  if (options.startDate) params.set('start_date', options.startDate);
  if (options.endDate) params.set('end_date', options.endDate);
  if (options.username && options.username.trim() !== '') {
    params.set('username', options.username.trim());
  }
  if (options.limit) params.set('limit', String(options.limit));

  return fetchApi<CollectorPreviewResponse>(`/api/v1/export/collector-preview?${params.toString()}`, { signal: options.signal, timeoutMs: TIMEOUT_CONFIG.PREVIEW_MS });
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
