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

import React, { useState } from 'react';
import { Drawer } from '../ui/Drawer';
import { Button } from '../ui/Button';
import { Badge } from '../ui/Badge';
import type { TelemetryLog } from '../../types/telemetry';
import { formatDateTime } from '../../utils/formatters';
import { Copy, Check, Terminal, FileCode } from 'lucide-react';

export interface LogInspectorDrawerProps {
  log: TelemetryLog | null;
  onClose: () => void;
}

export const LogInspectorDrawer: React.FC<LogInspectorDrawerProps> = ({ log, onClose }) => {
  const [activeTab, setActiveTab] = useState<'structured' | 'raw'>('structured');
  const [copied, setCopied] = useState(false);

  if (!log) return null;

  let parsedPayload: Record<string, unknown> = {};
  try {
    if (typeof log.payload === 'string') {
      parsedPayload = JSON.parse(log.payload);
    } else if (log.payload && typeof log.payload === 'object') {
      parsedPayload = log.payload as Record<string, unknown>;
    }
    // Unwrap nested envelope payload if present
    if (parsedPayload.payload && parsedPayload.collector && parsedPayload.status) {
      parsedPayload = parsedPayload.payload as Record<string, unknown>;
    }
  } catch {
    parsedPayload = { raw: String(log.payload || '') };
  }

  const rawJsonString = JSON.stringify(parsedPayload || log, null, 2);

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
                <span className="font-semibold text-slate-900 font-mono">{log.hostname}</span>
              </div>
              <div>
                <span className="text-slate-500">Username:</span>{' '}
                <span className="font-semibold text-slate-900">{log.username}</span>
              </div>
              <div>
                <span className="text-slate-500">Collector:</span>{' '}
                <span className="font-semibold text-slate-900 font-mono">{log.collector}</span>
              </div>
              <div>
                <span className="text-slate-500">Status:</span>{' '}
                <Badge level={log.status} variant="status" size="sm" />
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
                Empty payload attributes recorded.
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
        </div>
      ) : (
        <pre className="p-4 bg-slate-900 text-blue-300 font-mono text-xs rounded-lg overflow-x-auto leading-relaxed border border-slate-800 shadow-inner">
          {rawJsonString}
        </pre>
      )}
    </Drawer>
  );
};
