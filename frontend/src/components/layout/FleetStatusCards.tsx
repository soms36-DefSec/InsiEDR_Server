import { useEffect, useId, useRef, useState } from 'react';
import { ChevronDown, Monitor, Search, X } from 'lucide-react';
import type { DashboardSummary, FleetEndpoint } from '../../types/telemetry';
import { timeAgo } from '../../utils/formatters';

type FleetFilter = 'total' | 'online' | 'offline';

const metrics: { key: FleetFilter; label: string }[] = [
  { key: 'total', label: 'Total PCs' },
  { key: 'online', label: 'Online' },
  { key: 'offline', label: 'Offline' },
];

function fleetEndpoints(summary: DashboardSummary | null): FleetEndpoint[] {
  if (summary?.pc_status?.endpoints) return summary.pc_status.endpoints;

  // Compatibility with older summaries: collapse agent IDs to unique hosts,
  // keeping the newest observation. The UI discloses any incomplete list.
  const hosts = new Map<string, FleetEndpoint>();
  for (const agent of summary?.agents ?? []) {
    const hostname = agent.hostname?.trim();
    if (!hostname) continue;
    const previous = hosts.get(hostname);
    const seen = Date.parse(agent.last_seen_at) || 0;
    if (!previous || seen > (Date.parse(previous.last_seen_at ?? '') || 0)) {
      hosts.set(hostname, {
        hostname,
        last_seen_at: agent.last_seen_at || null,
        status: ['active', 'online'].includes(agent.status) ? 'online' : 'offline',
      });
    }
  }
  return [...hosts.values()].sort((a, b) => a.hostname.localeCompare(b.hostname));
}

export function FleetStatusCards({ summary, compact = false }: {
  summary: DashboardSummary | null;
  compact?: boolean;
}) {
  const [open, setOpen] = useState<FleetFilter | null>(null);
  const [query, setQuery] = useState('');
  const root = useRef<HTMLDivElement>(null);
  const buttons = useRef<Partial<Record<FleetFilter, HTMLButtonElement | null>>>({});
  const id = useId();
  const status = summary?.pc_status;
  const counts = {
    total: status?.total_pcs ?? status?.total_count,
    online: status?.online_pcs ?? status?.online_count,
    offline: status?.offline_pcs ?? status?.offline_count,
  };
  const endpoints = fleetEndpoints(summary);
  const selected = endpoints.filter((endpoint) => open === 'total' || endpoint.status === open);
  const visible = selected.filter((endpoint) => endpoint.hostname.toLowerCase().includes(query.trim().toLowerCase()));
  const selectedLabel = metrics.find((metric) => metric.key === open)?.label;

  useEffect(() => {
    if (!open) return;
    const dismiss = (event: PointerEvent) => {
      if (!root.current?.contains(event.target as Node)) setOpen(null);
    };
    document.addEventListener('pointerdown', dismiss);
    return () => document.removeEventListener('pointerdown', dismiss);
  }, [open]);

  const close = () => {
    if (open) buttons.current[open]?.focus();
    setOpen(null);
  };

  return (
    <div
      ref={root}
      className="relative shrink-0 max-w-full"
      onKeyDown={(event) => {
        if (event.key === 'Escape' && open) {
          event.preventDefault();
          event.stopPropagation();
          close();
        }
      }}
      onBlur={(event) => {
        if (!event.currentTarget.contains(event.relatedTarget)) setOpen(null);
      }}
    >
      <div className={`grid grid-cols-3 ${compact ? 'gap-2' : 'gap-2 sm:gap-3'}`}>
        {metrics.map(({ key, label }) => {
          const online = key === 'online';
          return (
            <button
              key={key}
              ref={(node) => { buttons.current[key] = node; }}
              id={`${id}-${key}`}
              type="button"
              aria-expanded={open === key}
              aria-controls={open === key ? `${id}-endpoints` : undefined}
              aria-label={`${label}: ${counts[key] ?? 'unavailable'}. Show endpoints`}
              onClick={() => {
                setOpen(open === key ? null : key);
                setQuery('');
              }}
              className={`flex items-center justify-between text-left rounded-lg border transition-colors cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2 ${
                compact ? 'h-8 gap-1.5 px-2.5' : 'h-16 gap-2 px-3 sm:gap-3 sm:px-3.5'
              } ${online
                ? 'bg-emerald-50/50 border-emerald-200 hover:border-emerald-400'
                : 'bg-white border-slate-200 hover:border-slate-400'
              }`}
            >
              {!compact && (
                <span className={`hidden sm:flex w-8 h-8 items-center justify-center rounded-md shrink-0 ${online ? 'bg-emerald-100/60 text-emerald-600' : 'bg-slate-100 text-slate-500'}`}>
                  <Monitor className="w-4 h-4" aria-hidden="true" />
                </span>
              )}
              <span className={compact ? 'flex items-center gap-1.5' : 'flex flex-col gap-1'}>
                <span className={`flex items-center gap-1.5 whitespace-nowrap font-semibold ${compact ? 'text-[11px]' : 'text-[10px] uppercase tracking-wider'} ${online ? 'text-emerald-700' : 'text-slate-500'}`}>
                  {key !== 'total' && (
                    <span aria-hidden="true" className={`w-1.5 h-1.5 rounded-full shrink-0 ${online ? 'bg-emerald-500 motion-safe:animate-pulse' : 'bg-slate-400'}`} />
                  )}
                  {label}
                </span>
                <span className={`font-semibold tabular-nums leading-none ${compact ? 'text-xs' : 'text-xl'} ${online ? 'text-emerald-700' : 'text-slate-900'}`}>
                  {counts[key] ?? '—'}
                </span>
              </span>
              <ChevronDown aria-hidden="true" className={`w-3 h-3 text-slate-400 shrink-0 transition-transform ${open === key ? 'rotate-180' : ''}`} />
            </button>
          );
        })}
      </div>

      {open && (
        <section
          id={`${id}-endpoints`}
          aria-labelledby={`${id}-${open}`}
          className="absolute right-0 top-full mt-2 z-50 w-96 max-w-[calc(100vw-3rem)] rounded-xl border border-slate-200 bg-white shadow-xl text-slate-800 select-text"
        >
          <div className="flex items-start justify-between gap-3 px-4 pt-4 pb-3">
            <div>
              <h2 className="text-sm font-semibold">{selectedLabel} · {counts[open] ?? '—'}</h2>
              <p className="mt-1 text-xs text-slate-500">Online = seen within the last 5 minutes.</p>
            </div>
            <button type="button" onClick={close} aria-label="Close endpoint list" className="p-1 rounded hover:bg-slate-100 focus-visible:outline-blue-500 cursor-pointer">
              <X className="w-4 h-4" aria-hidden="true" />
            </button>
          </div>
          <label className="mx-4 mb-3 flex items-center gap-2 rounded-md border border-slate-200 px-2.5 py-2 focus-within:ring-2 focus-within:ring-blue-500">
            <Search className="w-3.5 h-3.5 text-slate-400" aria-hidden="true" />
            <input
              type="search"
              aria-label="Filter hostnames"
              placeholder="Filter hostnames…"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              className="min-w-0 w-full text-xs outline-none bg-transparent"
            />
          </label>
          <ul className="max-h-64 overflow-y-auto overscroll-contain px-4 divide-y divide-slate-100">
            {visible.map((endpoint) => (
              <li key={endpoint.hostname} className="flex items-start justify-between gap-3 py-3 text-xs">
                <div className="min-w-0">
                  <div className="font-medium text-slate-900 break-words [overflow-wrap:anywhere]">{endpoint.hostname}</div>
                  <div className="mt-1 text-slate-500">
                    {endpoint.last_seen_at && !Number.isNaN(Date.parse(endpoint.last_seen_at))
                      ? `Seen ${timeAgo(endpoint.last_seen_at)}`
                      : 'Last seen unknown'}
                  </div>
                </div>
                <span className={`flex items-center gap-1.5 shrink-0 ${endpoint.status === 'online' ? 'text-emerald-700' : 'text-slate-500'}`}>
                  <span aria-hidden="true" className={`w-1.5 h-1.5 rounded-full ${endpoint.status === 'online' ? 'bg-emerald-500' : 'bg-slate-400'}`} />
                  {endpoint.status === 'online' ? 'Online' : 'Offline'}
                </span>
              </li>
            ))}
            {visible.length === 0 && (
              <li className="py-5 text-center text-xs text-slate-500">
                {query ? 'No matching hostnames.' : counts[open] === 0 ? 'No endpoints in this group.' : 'Endpoint details unavailable. Refresh to try again.'}
              </li>
            )}
          </ul>
          <p className="px-4 py-3 border-t border-slate-100 text-[11px] text-slate-500">
            {counts[open] !== undefined && selected.length < counts[open]!
              ? `Details available for ${selected.length} of ${counts[open]} PCs. Refresh for the latest fleet snapshot.`
              : 'One entry per hostname · blank names excluded'}
          </p>
        </section>
      )}
    </div>
  );
}
