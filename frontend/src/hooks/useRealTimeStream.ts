import { useState, useEffect, useCallback, useRef } from 'react';
import type { DashboardSummary, SystemHealth, RiskEvent, TelemetryLog } from '../types/telemetry';
import { fetchApi, fetchDashboardSummary, fetchHealth, fetchTelemetry } from '../services/api';
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
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const inFlight = useRef<Promise<void> | null>(null);
  const controller = useRef<AbortController | null>(null);
  const requestSeq = useRef(0);
  const latestAppliedSeq = useRef(0);

  const refreshAll = useCallback((): Promise<void> => {
    if (inFlight.current) return inFlight.current;
    const abort = new AbortController();
    controller.current = abort;
    const seq = ++requestSeq.current;
    const run = async () => {
      try {
        await Promise.allSettled([
          fetchDashboardSummary(abort.signal).then(value => {
            if (abort.signal.aborted || seq < latestAppliedSeq.current) return;
            latestAppliedSeq.current = seq;
            setSummary(previous => ({ ...value, stats: previous?.stats ?? value.stats }));
            setLastUpdated(value.freshness?.generated_at ? new Date(value.freshness.generated_at) : new Date());
            setError(value.freshness?.stale ? 'Showing the last successful fleet snapshot; refreshing.' : null);
            setIsLoading(false);
          }).catch((reason: unknown) => {
            if (!abort.signal.aborted) {
              console.warn('Fleet refresh deferred', reason);
              setError(reason instanceof Error ? reason.message : 'Fleet refresh failed');
              setIsLoading(false);
            }
          }),
          fetchHealth(abort.signal).then(value => {
            if (!abort.signal.aborted) setHealth(value);
          }).catch(() => {}),
        ]);
      } catch (err) {
        if (!abort.signal.aborted && seq >= latestAppliedSeq.current) console.warn('Telemetry sync deferred', err);
      } finally {
        if (!abort.signal.aborted && seq >= latestAppliedSeq.current) setIsLoading(false);
      }
    };
    const promise = run().finally(() => {
      if (inFlight.current === promise) inFlight.current = null;
    });
    inFlight.current = promise;
    return promise;
  }, []);

  // Large historical aggregates refresh independently of the fleet cards.
  useEffect(() => {
    const abort = new AbortController();
    let running = false;
    const refreshStats = async () => {
      if (running || document.visibilityState !== 'visible') return;
      running = true;
      try {
        const stats = await fetchApi<NonNullable<DashboardSummary['stats']>>('/api/stats', { signal: abort.signal });
        if (!abort.signal.aborted && stats.ok !== false) setSummary(previous => previous ? { ...previous, stats } : previous);
      } catch (reason) { if (!abort.signal.aborted) console.warn('Statistics refresh deferred', reason); }
      finally { running = false; }
    };
    void refreshStats();
    const timer = autoRefresh ? window.setInterval(() => { void refreshStats(); }, 30000) : undefined;
    return () => { abort.abort(); window.clearInterval(timer); };
  }, [autoRefresh]);

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
      source.addEventListener('telemetry_changed', () => { notifyTelemetry(); });
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
    // Poll at a bounded rate in both modes; SSE is a notification, not freshness.
    const timer = window.setInterval(() => { void refreshAll(); }, 15000);
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
