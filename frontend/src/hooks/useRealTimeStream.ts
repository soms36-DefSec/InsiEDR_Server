import { useState, useEffect, useCallback, useRef } from 'react';
import type { DashboardSummary, SystemHealth, RiskEvent, TelemetryLog } from '../types/telemetry';
import { fetchDashboardSummary, fetchHealth, fetchTelemetry } from '../services/api';
import { notifyTelemetry } from '../services/telemetryStream';

// One multiplexed SSE connection; views subscribe without re-rendering the shell
// for every telemetry event. REST is the authoritative recovery path.
export function useRealTimeStream() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [logs, setLogs] = useState<TelemetryLog[]>([]);
  const [liveThreats, setLiveThreats] = useState<RiskEvent[]>([]);
  const [connectionMode, setConnectionMode] = useState<'sse' | 'polling' | 'disconnected'>('polling');
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const inFlight = useRef<Promise<void> | null>(null);
  const controller = useRef<AbortController | null>(null);

  const refreshAll = useCallback((): Promise<void> => {
    if (inFlight.current) return inFlight.current;
    const abort = new AbortController();
    controller.current = abort;
    const run = async () => {
      try {
        const [nextSummary, nextHealth] = await Promise.all([
          fetchDashboardSummary(abort.signal),
          fetchHealth(abort.signal).catch(() => ({ status: 'unknown' })),
        ]);
        if (abort.signal.aborted) return;
        setSummary(nextSummary);
        setHealth(nextHealth);
        setLastUpdated(new Date());
        setError(null);
      } catch (err) {
        if (!abort.signal.aborted) setError(err instanceof Error ? err.message : 'Telemetry sync failed');
      } finally {
        if (!abort.signal.aborted) setIsLoading(false);
      }
    };
    const promise = run().finally(() => {
      if (inFlight.current === promise) inFlight.current = null;
    });
    inFlight.current = promise;
    return promise;
  }, []);

  const refreshLogs = useCallback(async (collector?: string | null, username?: string | null) => {
    const response = await fetchTelemetry(50, 0, collector, username);
    if (response.ok) setLogs(response.logs);
  }, []);

  useEffect(() => {
    void refreshAll();
    return () => { controller.current?.abort(); inFlight.current = null; };
  }, [refreshAll]);

  useEffect(() => {
    if (!autoRefresh) return;
    let source: EventSource | undefined;
    let summaryTimer: number | undefined;
    let alertTimer: number | undefined;
    let pendingAlerts: RiskEvent[] = [];
    const scheduleSummary = () => {
      if (summaryTimer !== undefined) return;
      summaryTimer = window.setTimeout(() => {
        summaryTimer = undefined;
        void refreshAll();
      }, 500);
    };
    try {
      source = new EventSource('/api/v1/stream/dashboard');
      source.onopen = () => {
        setConnectionMode('sse');
        scheduleSummary();
        notifyTelemetry(); // Reconnect also recovers events missed while offline.
      };
      source.onerror = () => setConnectionMode('polling');
      source.addEventListener('telemetry_changed', notifyTelemetry);
      source.addEventListener('agent_status', scheduleSummary);
      source.addEventListener('resync', () => { notifyTelemetry(); scheduleSummary(); });
      source.addEventListener('threat_alert', (event) => {
        try {
          const payload = JSON.parse((event as MessageEvent).data);
          pendingAlerts.unshift({ ...payload, created_at: payload.created_at || new Date().toISOString() });
          pendingAlerts = pendingAlerts.slice(0, 50);
          if (alertTimer === undefined) alertTimer = window.setTimeout(() => {
            const batch = pendingAlerts;
            pendingAlerts = [];
            alertTimer = undefined;
            setLiveThreats((previous) => [...batch, ...previous].slice(0, 50));
          }, 50);
          scheduleSummary();
        } catch { /* A malformed event must not stop reconnect/recovery. */ }
      });
    } catch {
      setConnectionMode('polling');
    }
    return () => {
      source?.close();
      window.clearTimeout(summaryTimer);
      window.clearTimeout(alertTimer);
    };
  }, [autoRefresh, refreshAll]);

  useEffect(() => {
    if (!autoRefresh) return;
    const timer = window.setInterval(() => { void refreshAll(); }, connectionMode === 'sse' ? 30000 : 3000);
    return () => window.clearInterval(timer);
  }, [autoRefresh, connectionMode, refreshAll]);

  return {
    summary, health, logs, liveThreats, lastUpdated, isLoading, error, autoRefresh,
    isConnected: autoRefresh && connectionMode === 'sse',
    connectionMode: autoRefresh ? connectionMode : 'disconnected' as const,
    toggleAutoRefresh: useCallback(() => setAutoRefresh((previous) => !previous), []),
    refreshAll, refreshLogs,
  };
}
