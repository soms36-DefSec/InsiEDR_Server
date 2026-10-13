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

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { Drawer } from '../ui/Drawer';
import { Button } from '../ui/Button';
import { Badge } from '../ui/Badge';
import type { TelemetryLog } from '../../types/telemetry';
import { formatDateTime } from '../../utils/formatters';
import { fetchTelemetryEventDetail } from '../../services/api';
import { Copy, Check, Terminal, FileCode, ShieldAlert, AlertCircle } from 'lucide-react';

export interface LogInspectorDrawerProps {
  log: TelemetryLog | null;
  onClose: () => void;
}

export const LogInspectorDrawer: React.FC<LogInspectorDrawerProps> = ({ log, onClose }) => {
  const [activeTab, setActiveTab] = useState<'structured' | 'raw'>('structured');
  const [copied, setCopied] = useState(false);
  const [detailEvent, setDetailEvent] = useState<TelemetryLog | null>(null);
  const [isLoadingDetail, setIsLoadingDetail] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);

  const eventId = log ? String(log.event_id || log.id || '') : '';
  const abortControllerRef = useRef<AbortController | null>(null);
  const lastLoadedIdRef = useRef<string>('');

  const loadDetail = useCallback(async (targetId: string, baseLog: TelemetryLog) => {
    if (!targetId) return;

    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    const controller = new AbortController();
    abortControllerRef.current = controller;

    setIsLoadingDetail(true);
    setDetailError(null);

    try {
      const res = await fetchTelemetryEventDetail(targetId, controller.signal);
      if (controller.signal.aborted) return;

      if (res && res.ok && res.event) {
        setDetailEvent((prev) => {
          const currentId = prev ? String(prev.event_id || prev.id || '') : '';
          if (currentId && currentId !== targetId) return prev;
          return {
            ...(prev || baseLog),
            ...res.event,
          };
        });
      } else {
        setDetailError('Failed to fetch event detail from telemetry engine.');
      }
    } catch (err: unknown) {
      if (controller.signal.aborted) return;
      const msg = err instanceof Error ? err.message : String(err);
      setDetailError(`Failed to fetch event detail: ${msg}`);
    } finally {
      if (!controller.signal.aborted) {
        setIsLoadingDetail(false);
      }
    }
  }, []);

  useEffect(() => {
    if (!log || !eventId) {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
        abortControllerRef.current = null;
      }
      lastLoadedIdRef.current = '';
      setDetailEvent(null);
      setDetailError(null);
      setIsLoadingDetail(false);
      return;
    }

    if (lastLoadedIdRef.current !== eventId) {
      lastLoadedIdRef.current = eventId;
      setDetailEvent(log);
      setDetailError(null);

      const hasPayload = log.payload && typeof log.payload === 'object' && Object.keys(log.payload).length > 0;
      if (!hasPayload) {
        loadDetail(eventId, log);
      } else {
        setIsLoadingDetail(false);
      }
    }

    return () => {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
        abortControllerRef.current = null;
      }
    };
  }, [eventId, log, loadDetail]);

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
          <span>Fetching full payload details on-demand...</span>
        </div>
      )}

      {detailError && (
        <div className="mb-4 bg-rose-50 border border-rose-200 rounded-lg p-3 text-xs text-rose-700 flex items-center justify-between gap-2">
          <div className="flex items-center gap-2 min-w-0">
            <AlertCircle className="w-4 h-4 text-rose-500 shrink-0" />
            <span className="truncate">{detailError}</span>
          </div>
          <button
            type="button"
            onClick={() => log && loadDetail(eventId, log)}
            className="px-2.5 py-1 bg-white border border-rose-300 rounded text-rose-800 font-medium hover:bg-rose-100 transition-colors shrink-0 cursor-pointer text-xs"
          >
            Retry
          </button>
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
