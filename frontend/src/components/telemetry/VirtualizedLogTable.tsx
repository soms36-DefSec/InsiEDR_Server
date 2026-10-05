/**
 * InsiEDR Virtualized Telemetry Table
 * ====================================
 *
 * Architectural Role:
 *   Ultra-high-performance log viewport designed for massive forensic streams.
 *   Uses DOM windowing to render only visible rows plus a small overscan buffer,
 *   maintaining a fixed DOM size (<10MB) and silky 60 FPS scrolling even with
 *   100,000+ raw telemetry events.
 *
 * Virtualization Mathematics:
 *   - `totalHeight`: `logs.length * ROW_HEIGHT`
 *   - `startIndex`: `Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN)`
 *   - `endIndex`: `Math.min(logs.length, Math.ceil((scrollTop + height) / ROW_HEIGHT) + OVERSCAN)`
 *   - `offsetY`: `startIndex * ROW_HEIGHT` translated via GPU `transform`
 */

import React, { useRef, useState, useEffect } from 'react';
import type { TelemetryLog } from '../../types/telemetry';
import { Badge } from '../ui/Badge';
import { formatDateTime, extractLogPreview } from '../../utils/formatters';

export interface VirtualizedLogTableProps {
  logs: TelemetryLog[];
  onSelectLog: (log: TelemetryLog) => void;
  isLoading?: boolean;
}

const ROW_HEIGHT = 44;
const OVERSCAN = 6;

export const VirtualizedLogTable: React.FC<VirtualizedLogTableProps> = ({
  logs,
  onSelectLog,
  isLoading = false,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [containerHeight, setContainerHeight] = useState(520);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;

    const handleScroll = () => {
      setScrollTop(el.scrollTop);
    };

    const handleResize = () => {
      setContainerHeight(el.clientHeight);
    };

    el.addEventListener('scroll', handleScroll, { passive: true });
    window.addEventListener('resize', handleResize);
    handleResize();

    return () => {
      el.removeEventListener('scroll', handleScroll);
      window.removeEventListener('resize', handleResize);
    };
  }, []);

  const totalHeight = logs.length * ROW_HEIGHT;
  const startIndex = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN);
  const endIndex = Math.min(
    logs.length,
    Math.ceil((scrollTop + containerHeight) / ROW_HEIGHT) + OVERSCAN
  );

  const visibleLogs = logs.slice(startIndex, endIndex);
  const offsetY = startIndex * ROW_HEIGHT;

  if (isLoading && logs.length === 0) {
    return (
      <div className="h-96 flex flex-col items-center justify-center text-slate-400 text-xs">
        <span className="w-5 h-5 border-2 border-slate-300 border-t-blue-600 rounded-full animate-spin mb-2" />
        Streaming telemetry logs from backend storage...
      </div>
    );
  }

  if (logs.length === 0) {
    return (
      <div className="h-64 flex flex-col items-center justify-center text-slate-400 text-xs bg-slate-50/50 rounded-lg border border-dashed border-slate-200">
        No telemetry records found matching filter criteria.
      </div>
    );
  }

  return (
    <div className="border border-slate-200 rounded-lg overflow-hidden bg-white shadow-[0_1px_3px_rgba(0,0,0,0.06)]">
      {/* Fixed Header */}
      <div className="bg-slate-50/80 border-b border-slate-200 grid grid-cols-12 px-6 py-3 text-xs font-medium text-slate-500 select-none">
        <div className="col-span-2">Timestamp</div>
        <div className="col-span-2">Hostname</div>
        <div className="col-span-1">User</div>
        <div className="col-span-2">Collector</div>
        <div className="col-span-4">Payload Summary</div>
        <div className="col-span-1 text-right">Status</div>
      </div>

      {/* Virtualized Scroll Viewport */}
      <div
        ref={containerRef}
        className="overflow-y-auto relative min-h-[320px] max-h-[580px]"
        style={{ willChange: 'transform' }}
      >
        <div style={{ height: `${totalHeight}px`, position: 'relative' }}>
          <div
            style={{
              position: 'absolute',
              top: 0,
              left: 0,
              right: 0,
              transform: `translateY(${offsetY}px)`,
            }}
          >
            {visibleLogs.map((log, index) => {
              const actualIndex = startIndex + index;

              const details = extractLogPreview(log);

              return (
                <div
                  key={log.id || actualIndex}
                  onClick={() => onSelectLog(log)}
                  className="grid grid-cols-12 px-6 items-center text-xs border-b border-slate-100 hover:bg-slate-50 transition-colors cursor-pointer group"
                  style={{ height: `${ROW_HEIGHT}px` }}
                >
                  {/* Timestamp */}
                  <div className="col-span-2 text-slate-500 font-mono text-[11px] truncate">
                    {formatDateTime(log.collected_at)}
                  </div>

                  {/* Hostname */}
                  <div className="col-span-2 font-mono text-slate-600 truncate">
                    {log.hostname}
                  </div>

                  {/* Username */}
                  <div className="col-span-1 font-medium text-slate-900 truncate">
                    {log.username}
                  </div>

                  {/* Collector */}
                  <div className="col-span-2 pr-2 flex items-center overflow-hidden">
                    <Badge level={log.collector} variant="collector" size="sm" />
                  </div>

                  {/* Payload Details */}
                  <div
                    className="col-span-4 text-slate-600 truncate pr-2 font-mono text-[11px]"
                    title={details}
                  >
                    {details}
                  </div>

                  {/* Status */}
                  <div className="col-span-1 flex justify-end">
                    <span
                      className={`inline-block w-2 h-2 rounded-full ${
                        log.status === 'success' ? 'bg-emerald-500' : 'bg-slate-400'
                      }`}
                      title={log.status}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};
