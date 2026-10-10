/**
 * InsiEDR Forensic Log Inspector Drawer
 * =====================================
 *
 * Architectural Role:
 *   Slide-over forensic examination drawer providing deep payload inspection
 *   for SOC tier-2 analysts. Renders both normalized structured key/value
 *   attributes and formatted raw JSON payloads.
 *
 * Resiliency:
 *   - Auto-unwraps nested collector envelope structures (`{ collector, status, payload }`).
 *   - Safely parses stringified JSON without throwing on malformed log streams.
 *   - Defensive clipboard fallback for restricted browser security contexts (HTTP/iframes).
 */

import React, { useState, useEffect } from 'react';
import { Drawer } from '../ui/Drawer';
import { Button } from '../ui/Button';
import { Badge } from '../ui/Badge';
import type { TelemetryLog } from '../../types/telemetry';
import { formatDateTime } from '../../utils/formatters';
import { fetchTelemetryEventDetail } from '../../services/api';
import { Copy, Check, Terminal, FileCode, ShieldAlert, Cpu } from 'lucide-react';

export interface LogInspectorDrawerProps {
  log: TelemetryLog | null;
  onClose: () => void;
}

export const LogInspectorDrawer: React.FC<LogInspectorDrawerProps> = ({ log, onClose }) => {
  const [activeTab, setActiveTab] = useState<'structured' | 'raw'>('structured');
  const [copied, setCopied] = useState(false);
  const [detailEvent, setDetailEvent] = useState<TelemetryLog | null>(null);
  const [isLoadingDetail, setIsLoadingDetail] = useState(false);

  useEffect(() => {
    if (!log) {
      setDetailEvent(null);
      return;
    }
    setDetailEvent(log);

    // If full payload is not yet loaded, query on-demand detail from ClickHouse / backend
    const hasPayload = log.payload && typeof log.payload === 'object' && Object.keys(log.payload).length > 0;
    const eventId = log.event_id || log.id;

    if (!hasPayload && eventId) {
      setIsLoadingDetail(true);
      fetchTelemetryEventDetail(eventId)
        .then((res) => {
          if (res && res.ok && res.event) {
            setDetailEvent((prev) => ({
              ...(prev || log),
              ...res.event,
            }));
          }
        })
        .catch(() => {
          // Graceful fallback to initial log projection
        })
        .finally(() => {
          setIsLoadingDetail(false);
        });
    }
  }, [log]);

  if (!log) return null;
  const currentEvent = detailEvent || log;

  let parsedPayload: Record<string, unknown> = {};
  try {
    if (typeof currentEvent.payload === 'string') {
      parsedPayload = JSON.parse(currentEvent.payload);
    } else if (currentEvent.payload && typeof currentEvent.payload === 'object') {
      parsedPayload = currentEvent.payload as Record<string, unknown>;
    }
    // Unwrap nested envelope payload if present
    if (parsedPayload.payload && parsedPayload.collector && parsedPayload.status) {
      parsedPayload = parsedPayload.payload as Record<string, unknown>;
    }
  } catch {
    parsedPayload = { raw: String(currentEvent.payload || currentEvent.summary_preview || '') };
  }

  const rawJsonString = JSON.stringify(
    Object.keys(parsedPayload).length > 0 ? parsedPayload : currentEvent,
    null,
    2
  );

  const handleCopy = async () => {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(rawJsonString);
      } else {
        // Fallback for non-HTTPS or legacy contexts
        const textarea = document.createElement('textarea');
        textarea.value = rawJsonString;
        textarea.style.position = 'fixed';
        textarea.style.left = '-999999px';
        document.body.appendChild(textarea);
        textarea.focus();
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
      }
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch (err) {
      console.warn('[LogInspectorDrawer] Copy to clipboard failed:', err);
    }
  };

  return (
    <Drawer
      isOpen={Boolean(log)}
      onClose={onClose}
      title={
        <div className="flex items-center gap-2">
          <span>Telemetry Payload Inspector</span>
          <Badge level={log.collector} variant="collector" size="sm" />
        </div>
      }
      subtitle={`Collected at: ${formatDateTime(log.collected_at)}`}
      width="xl"
      footer={
        <>
          <Button
            variant="secondary"
            size="sm"
            onClick={handleCopy}
            icon={copied ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
          >
            {copied ? 'Copied to Clipboard' : 'Copy JSON'}
          </Button>
          <Button variant="primary" size="sm" onClick={onClose}>
            Close Inspector
          </Button>
        </>
      }
    >
      {/* Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-200 pb-2">
        <button
          onClick={() => setActiveTab('structured')}
          className={`px-3 py-1.5 rounded-md text-xs transition-colors cursor-pointer flex items-center gap-1.5 ${
            activeTab === 'structured'
              ? 'bg-blue-50 text-blue-700 font-medium border border-blue-200'
              : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900 border border-transparent font-normal'
          }`}
        >
          <Terminal className="w-3.5 h-3.5" />
          Structured View
        </button>
        <button
          onClick={() => setActiveTab('raw')}
          className={`px-3 py-1.5 rounded-md text-xs transition-colors cursor-pointer flex items-center gap-1.5 ${
            activeTab === 'raw'
              ? 'bg-blue-50 text-blue-700 font-medium border border-blue-200'
              : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900 border border-transparent font-normal'
          }`}
        >
          <FileCode className="w-3.5 h-3.5" />
          Raw JSON Payload
        </button>
      </div>

      {isLoadingDetail && (
        <div className="mb-4 bg-blue-50 border border-blue-200 rounded-lg p-3 text-xs text-blue-700 flex items-center gap-2">
          <span className="w-3.5 h-3.5 border-2 border-blue-400 border-t-blue-700 rounded-full animate-spin shrink-0" />
          <span>Fetching full raw payload & normalized features on-demand from ClickHouse...</span>
        </div>
      )}

      {activeTab === 'structured' ? (
        <div className="space-y-4">
          {/* Envelope Summary */}
          <div className="bg-slate-50 border border-slate-200 rounded-lg p-4">
            <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-2.5">
              Telemetry Envelope
            </div>
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div>
                <span className="text-slate-500">Hostname:</span>{' '}
                <span className="font-semibold text-slate-900 font-mono">{currentEvent.hostname}</span>
              </div>
              <div>
                <span className="text-slate-500">Username:</span>{' '}
                <span className="font-semibold text-slate-900">{currentEvent.username}</span>
              </div>
              <div>
                <span className="text-slate-500">Collector:</span>{' '}
                <span className="font-semibold text-slate-900 font-mono">{currentEvent.collector || currentEvent.collector_name}</span>
              </div>
              <div>
                <span className="text-slate-500">Status:</span>{' '}
                <Badge level={currentEvent.status} variant="status" size="sm" />
              </div>
            </div>
          </div>

          {/* Key-Value Properties */}
          <div>
            <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-2">
              Extracted Payload Attributes
            </div>
            {Object.keys(parsedPayload).length === 0 ? (
              <div className="text-xs text-slate-400 p-4 bg-slate-50 rounded-lg border border-slate-200">
                {isLoadingDetail ? 'Loading payload details...' : 'Empty payload attributes recorded.'}
              </div>
            ) : (
              <div className="border border-slate-200 rounded-lg overflow-hidden divide-y divide-slate-100 text-xs">
                {Object.entries(parsedPayload).map(([key, val]) => (
                  <div key={key} className="px-4 py-2.5 flex items-center justify-between hover:bg-slate-50">
                    <span className="font-mono font-medium text-slate-600">{key}</span>
                    <span className="font-mono text-slate-900 font-semibold max-w-[280px] truncate" title={String(val)}>
                      {typeof val === 'object' ? JSON.stringify(val) : String(val)}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Normalized Features (ClickHouse OLAP) */}
          {currentEvent.features && Object.keys(currentEvent.features).length > 0 && (
            <div>
              <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <Cpu className="w-3.5 h-3.5 text-indigo-500" />
                <span>Normalized ML Feature Vectors</span>
              </div>
              <div className="border border-indigo-100 bg-indigo-50/30 rounded-lg overflow-hidden divide-y divide-indigo-100/60 text-xs">
                {Object.entries(currentEvent.features).map(([fName, fVal]) => (
                  <div key={fName} className="px-4 py-2 flex items-center justify-between">
                    <span className="font-mono text-indigo-900 font-medium">{fName}</span>
                    <span className="font-mono text-indigo-700 font-bold">{String(fVal)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Risk Events & Detection */}
          {currentEvent.risk && Object.keys(currentEvent.risk).length > 0 && (
            <div>
              <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <ShieldAlert className="w-3.5 h-3.5 text-rose-500" />
                <span>Correlated Risk Context</span>
              </div>
              <div className="border border-rose-100 bg-rose-50/40 rounded-lg p-3 text-xs space-y-1.5">
                <div className="flex justify-between">
                  <span className="text-slate-500">Risk Score:</span>
                  <span className="font-mono font-bold text-rose-700">{String(currentEvent.risk.risk_score || '0')}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Risk Level:</span>
                  <span className="font-semibold text-rose-800 uppercase">{String(currentEvent.risk.risk_level || 'LOW')}</span>
                </div>
                {Boolean(currentEvent.risk.summary) && (
                  <div className="pt-1 text-slate-700">
                    {String(currentEvent.risk.summary)}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      ) : (
        <pre className="p-4 bg-slate-900 text-blue-300 font-mono text-xs rounded-lg overflow-x-auto leading-relaxed border border-slate-800 shadow-inner">
          {rawJsonString}
        </pre>
      )}
    </Drawer>
  );
};
