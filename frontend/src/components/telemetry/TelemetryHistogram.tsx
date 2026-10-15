import React, { useState, useEffect, useMemo, useId } from 'react';
import { BarChart3, Activity, Zap, Clock } from 'lucide-react';
import type { TelemetryHistogramBucket } from '../../types/telemetry';
import { fetchTelemetryHistogram } from '../../services/api';

export interface TelemetryHistogramProps {
  timeRange: string;
  autoRefresh?: boolean;
  refreshVersion?: number;
  activeCollector?: string;
  statusFilter?: string;
  agentId?: string;
  onSelectBucket?: (timestamp: string) => void;
}

const formatAxisLabel = (isoStr: string, range: string, _intervalStr: string): string => {
  try {
    const d = new Date(isoStr);
    if (isNaN(d.getTime())) return isoStr;
    if (range === '15m' || range === '1h') {
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    }
    if (range === '24h') {
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }
    return `${d.getMonth() + 1}/${d.getDate()} ${d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;
  } catch {
    return isoStr;
  }
};

const formatTooltipTime = (isoStr: string, _range: string, intervalStr: string): string => {
  try {
    const d = new Date(isoStr);
    if (isNaN(d.getTime())) return isoStr;
    return `${d.toLocaleDateString()} ${d.toLocaleTimeString()} (${intervalStr} bucket)`;
  } catch {
    return isoStr;
  }
};

export const TelemetryHistogram: React.FC<TelemetryHistogramProps> = ({
  timeRange,
  autoRefresh = true,
  refreshVersion,
  activeCollector,
  statusFilter,
  agentId,
  onSelectBucket,
}) => {
  const [buckets, setBuckets] = useState<TelemetryHistogramBucket[]>([]);
  const [totalEvents, setTotalEvents] = useState<number | null>(null);
  const [interval, setInterval] = useState<string>('1m');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [hoveredBucket, setHoveredBucket] = useState<{
    bucket: TelemetryHistogramBucket;
    x: number;
    y: number;
  } | null>(null);

  const gradId = useId();
  const [notice, setNotice] = useState<string | null>(null);
  const [generatedAt, setGeneratedAt] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    let timer: number | undefined;
    const abort = new AbortController();
    setBuckets([]);
    setTotalEvents(null);
    setGeneratedAt(null);
    setNotice(null);
    const refresh = async () => {
      if (!active) return;
      if (document.visibilityState !== 'visible') {
        if (autoRefresh) timer = window.setTimeout(refresh, 15000);
        return;
      }
      setIsLoading(true);
      let nextDelay = 30000;
      try {
        const res = await fetchTelemetryHistogram(timeRange, {
          collector: activeCollector, status: statusFilter, agent_id: agentId, signal: abort.signal,
        });
        if (!active) return;
        if (!res?.ok) throw new Error('Histogram unavailable');
        setBuckets(Array.isArray(res.histogram) ? res.histogram : []);
        setTotalEvents(res.total_events ?? 0);
        setInterval(res.interval || '1m');
        setGeneratedAt(res.freshness?.generated_at ?? new Date().toISOString());
        setNotice(res.freshness?.stale ? 'Showing the last successful chart; refreshing.' : null);
        if (res.freshness?.stale) nextDelay = 15000;
      } catch {
        if (active) setNotice('Chart refresh delayed. Retrying automatically.');
        nextDelay = 15000;
      } finally {
        if (active) {
          setIsLoading(false);
          if (autoRefresh) timer = window.setTimeout(refresh, nextDelay);
        }
      }
    };
    void refresh();
    return () => { active = false; abort.abort(); window.clearTimeout(timer); };
  }, [timeRange, activeCollector, statusFilter, agentId, refreshVersion, autoRefresh]);

  const maxCount = useMemo(() => {
    if (!buckets.length) return 1;
    return Math.max(...buckets.map((b) => b.count), 1);
  }, [buckets]);

  const chartHeight = 64; // px
  const chartWidth = 800; // viewBox units

  const displayBuckets = buckets;

  return (
    <div className="bg-white border border-slate-200 rounded-lg p-4 shadow-[0_1px_3px_rgba(0,0,0,0.06)] relative select-none">
      {/* Header Stat Row */}
      <div className="flex items-center justify-between pb-3 border-b border-slate-100 flex-wrap gap-2 text-xs">
        <div className="flex items-center gap-2">
          <div className="w-6 h-6 rounded-md bg-blue-50 border border-blue-200/60 flex items-center justify-center text-blue-600">
            <BarChart3 className="w-3.5 h-3.5" />
          </div>
          <div>
            <span className="font-semibold text-slate-900 tracking-tight">Event Ingestion Histogram</span>
            <span className="text-slate-400 font-normal ml-2">ClickHouse Columnar Server Aggregation</span>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 bg-slate-50 border border-slate-200/80 px-2 py-0.5 rounded text-[11px] text-slate-600">
            <Activity className="w-3 h-3 text-blue-500" />
            <span className="text-slate-500">Volume{timeRange === 'all' ? ' (30d window)' : ''}:</span>
            <span className="font-mono font-semibold text-slate-900">{totalEvents === null ? '—' : totalEvents.toLocaleString()}</span>
            <span className="text-slate-400">events</span>
          </div>

          <div className="flex items-center gap-1.5 bg-slate-50 border border-slate-200/80 px-2 py-0.5 rounded text-[11px] text-slate-600">
            <Zap className="w-3 h-3 text-amber-500" />
            <span className="text-slate-500">Peak:</span>
            <span className="font-mono font-semibold text-slate-900">{(buckets.length ? maxCount : 0).toLocaleString()}</span>
            <span className="text-slate-400">/bucket</span>
          </div>

          <div className="flex items-center gap-1 bg-slate-50 border border-slate-200/80 px-2 py-0.5 rounded text-[11px] text-slate-500">
            <Clock className="w-3 h-3 text-slate-400" />
            <span>Bucket:</span>
            <span className="font-mono font-semibold text-slate-800">{interval || '1m'}</span>
          </div>
        </div>
      </div>

      <div role="status" className="pt-2 text-xs text-slate-500">
        {notice || (totalEvents === 0 ? 'No events in this window.' : totalEvents === null ? 'Loading chart…' : '')}
        {generatedAt && <span className="ml-2">Data as of {new Date(generatedAt).toLocaleTimeString()}</span>}
      </div>
      {/* SVG Bar Chart Area */}
      <div className="pt-3 relative">
        {isLoading && (
          <div className="absolute inset-0 bg-white/60 backdrop-blur-[1px] flex items-center justify-center z-10 text-xs text-slate-400">
            <span className="w-3.5 h-3.5 border-2 border-slate-300 border-t-blue-600 rounded-full animate-spin mr-2" />
            Calculating frequency bins...
          </div>
        )}

        <div className="w-full h-16 relative">
          <svg
            viewBox={`0 0 ${chartWidth} ${chartHeight}`}
            preserveAspectRatio="none"
            className="w-full h-full overflow-visible"
          >
            <defs>
              <linearGradient id={`${gradId}-grad`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#3b82f6" stopOpacity="0.9" />
                <stop offset="100%" stopColor="#60a5fa" stopOpacity="0.4" />
              </linearGradient>
              <linearGradient id={`${gradId}-hover`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#1d4ed8" stopOpacity="1" />
                <stop offset="100%" stopColor="#2563eb" stopOpacity="0.8" />
              </linearGradient>
            </defs>

            {/* Horizontal guideline */}
            <line
              x1="0"
              y1={chartHeight - 1}
              x2={chartWidth}
              y2={chartHeight - 1}
              stroke="#e2e8f0"
              strokeWidth="1"
            />

            {/* Bars */}
            {displayBuckets.map((bucket, index) => {
              const numBuckets = displayBuckets.length;
              const barSpacing = chartWidth / numBuckets;
              const barWidth = Math.max(2, barSpacing * 0.75);
              const x = index * barSpacing + (barSpacing - barWidth) / 2;
              const ratio = maxCount > 0 ? bucket.count / maxCount : 0;
              const barH = Math.max(bucket.count > 0 ? 4 : 1, ratio * (chartHeight - 4));
              const y = chartHeight - barH;
              const isHovered = hoveredBucket?.bucket.timestamp === bucket.timestamp;

              return (
                <rect
                  key={bucket.timestamp || index}
                  x={x}
                  y={y}
                  width={barWidth}
                  height={barH}
                  rx="1.5"
                  className="transition-all duration-150 cursor-pointer"
                  fill={isHovered ? `url(#${gradId}-hover)` : `url(#${gradId}-grad)`}
                  opacity={bucket.count === 0 ? 0.35 : 1}
                  onMouseEnter={(e) => {
                    const rect = e.currentTarget.getBoundingClientRect();
                    setHoveredBucket({
                      bucket,
                      x: rect.left + rect.width / 2,
                      y: rect.top,
                    });
                  }}
                  onMouseLeave={() => setHoveredBucket(null)}
                  onClick={() => onSelectBucket?.(bucket.timestamp)}
                />
              );
            })}
          </svg>
        </div>

        {/* Time axis endpoints */}
        <div className="flex justify-between items-center text-[10px] text-slate-400 font-mono mt-1 pt-0.5 select-none">
          <span>{displayBuckets[0]?.timestamp ? formatAxisLabel(displayBuckets[0].timestamp, timeRange, interval) : 'Start'}</span>
          <span className="text-slate-400 text-[10px]">Rolling Window ({timeRange === 'all' ? '90D RETENTION' : timeRange.toUpperCase()})</span>
          <span>{displayBuckets.at(-1)?.timestamp ? formatAxisLabel(displayBuckets.at(-1)!.timestamp, timeRange, interval) : 'Now'}</span>
        </div>
      </div>

      {/* Floating Hover Tooltip */}
      {hoveredBucket && (
        <div
          role="tooltip"
          className="fixed z-50 pointer-events-none transform -translate-x-1/2 -translate-y-full mb-2 bg-slate-900 text-white text-[11px] px-2.5 py-1.5 rounded shadow-lg border border-slate-700 font-mono"
          style={{ left: hoveredBucket.x, top: hoveredBucket.y - 6 }}
        >
          <div className="font-semibold text-blue-300">
            {hoveredBucket.bucket.count.toLocaleString()} events
          </div>
          <div className="text-slate-400 text-[10px]">
            {formatTooltipTime(hoveredBucket.bucket.timestamp, timeRange, interval)}
          </div>
        </div>
      )}
    </div>
  );
};
