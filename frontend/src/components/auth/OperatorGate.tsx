import { useCallback, useEffect, useState, type FormEvent, type ReactNode } from 'react';
import { OperatorSignOutContext } from './operatorAuthContext';

type SessionState = 'checking' | 'signed-out' | 'signed-in' | 'unavailable';

export function OperatorGate({ children }: { children: ReactNode }) {
  const [state, setState] = useState<SessionState>('checking');
  const [operatorKey, setOperatorKey] = useState('');
  const [authRequired, setAuthRequired] = useState(true);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const checkSession = useCallback(async () => {
    try {
      const response = await fetch('/api/auth/session', { cache: 'no-store', credentials: 'same-origin' });
      if (!response.ok) throw new Error(`Session check failed (${response.status})`);
      const result = await response.json() as { authenticated: boolean; auth_required?: boolean };
      setState(result.authenticated ? 'signed-in' : 'signed-out');
      setAuthRequired(result.auth_required !== false);
      setError('');
    } catch (reason) {
      setState('unavailable');
      setError(reason instanceof Error ? reason.message : 'Could not reach the server');
    }
  }, []);

  useEffect(() => { void checkSession(); }, [checkSession]);
  useEffect(() => {
    const expired = () => { setState('signed-out'); setError('Your operator session expired. Sign in again.'); };
    window.addEventListener('insiedr:auth-expired', expired);
    return () => window.removeEventListener('insiedr:auth-expired', expired);
  }, []);

  const signIn = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      const response = await fetch('/api/auth/session', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ operator_key: operatorKey }),
      });
      if (!response.ok) {
        const body = await response.json().catch(() => null) as { error?: { message?: string }; detail?: string } | null;
        throw new Error(body?.error?.message || body?.detail || `Sign in failed (${response.status})`);
      }
      setOperatorKey('');
      const result = await response.json() as { auth_required?: boolean };
      setAuthRequired(result.auth_required !== false);
      setState('signed-in');
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Sign in failed');
    } finally { setBusy(false); }
  };

  const signOut = async () => {
    await fetch('/api/auth/session', { method: 'DELETE', credentials: 'same-origin' }).catch(() => undefined);
    setState('signed-out');
  };

  if (state === 'signed-in') return <OperatorSignOutContext.Provider value={authRequired ? () => { void signOut(); } : null}>{children}</OperatorSignOutContext.Provider>;
  if (state === 'checking') return <div className="min-h-screen grid place-items-center text-sm text-slate-600">Checking operator session…</div>;
  if (state === 'unavailable') return <div className="min-h-screen grid place-items-center bg-slate-50 p-4">
    <div className="w-full max-w-md rounded-xl border bg-white p-6 shadow-sm">
      <h1 className="text-lg font-semibold">Dashboard unavailable</h1>
      <p role="alert" className="mt-2 text-sm text-rose-700">{error}</p>
      <button className="mt-4 rounded bg-slate-900 px-4 py-2 text-sm text-white" onClick={() => { setState('checking'); void checkSession(); }}>Retry</button>
    </div>
  </div>;

  return <div className="min-h-screen grid place-items-center bg-slate-50 p-4">
    <form onSubmit={signIn} className="w-full max-w-md rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
      <div className="text-xs font-semibold uppercase tracking-wider text-slate-500">InsiEDR Security Operations</div>
      <h1 className="mt-2 text-xl font-semibold text-slate-900">Operator sign in</h1>
      <p className="mt-1 text-sm text-slate-600">Enter your operator key to open the dashboard.</p>
      <label className="mt-5 block text-sm font-medium text-slate-700" htmlFor="operator-key">Operator key</label>
      <input id="operator-key" type="password" autoComplete="current-password" required value={operatorKey}
        onChange={(event) => setOperatorKey(event.target.value)}
        className="mt-1 w-full rounded-md border border-slate-300 px-3 py-2 text-sm focus:border-slate-500 focus:outline-none focus:ring-2 focus:ring-slate-200" />
      {error && <p role="alert" className="mt-3 text-sm text-rose-700">{error}</p>}
      <button disabled={busy} className="mt-5 w-full rounded-md bg-slate-900 px-4 py-2.5 text-sm font-semibold text-white disabled:opacity-50">
        {busy ? 'Signing in…' : 'Sign in'}
      </button>
    </form>
  </div>;
}

