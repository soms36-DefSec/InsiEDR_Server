import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { createServer } from 'vite';
import { chromium } from 'playwright';

const root = fileURLToPath(new URL('../', import.meta.url));
const reports = fileURLToPath(new URL('../../reports/dashboard-audit/', import.meta.url));
let server, browser, base;
before(async () => {
  await mkdir(reports, { recursive: true });
  server = await createServer({ root, server: { host: '127.0.0.1', port: 0 }, logLevel: 'error' });
  await server.listen();
  base = server.resolvedUrls.local[0];
  browser = await chromium.launch({ headless: true,
    ...(process.env.PLAYWRIGHT_CHANNEL ? { channel: process.env.PLAYWRIGHT_CHANNEL } : {}) });
});
after(async () => { await browser?.close(); await server?.close(); });

test('50,000 rows: empty-to-loaded scroll, bounded DOM, shrink, keyboard and error boundary', async () => {
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  try {
    await page.goto(`${base}tests/viewport.html`);
    await page.getByText('No telemetry records found', { exact: false }).waitFor();
    const cdp = await page.context().newCDPSession(page);
    await cdp.send('HeapProfiler.collectGarbage');
    const beforeHeap = (await cdp.send('Runtime.getHeapUsage')).usedSize;
    await page.evaluate(() => window.loadRows(50000));
    const viewport = page.getByTestId('telemetry-viewport');
    await viewport.waitFor();
    assert.ok(await page.getByRole('row').count() < 40);
    const frames = await viewport.evaluate(async (element) => {
      const deltas = [];
      let previous = performance.now();
      for (let i = 0; i < 120; i++) {
        await new Promise(requestAnimationFrame);
        const now = performance.now();
        deltas.push(now - previous); previous = now;
        element.scrollTop = i * 13000;
      }
      element.scrollTop = element.scrollHeight;
      return deltas.slice(5);
    });
    await page.getByText('HOST-49999', { exact: true }).waitFor();
    assert.ok(await page.getByRole('row').count() < 40);
    await cdp.send('HeapProfiler.collectGarbage');
    const overhead = (await cdp.send('Runtime.getHeapUsage')).usedSize - beforeHeap;
    frames.sort((a, b) => a - b);
    const metrics = { rows: 50000, domRows: await page.getByRole('row').count(),
      frameP50Ms: frames[Math.floor(frames.length * .5)], frameP95Ms: frames[Math.floor(frames.length * .95)],
      viewportHeapDeltaBytes: overhead, browser: browser.version(),
      environment: `Headless ${process.env.PLAYWRIGHT_CHANNEL || 'Chromium'}; Vite development build; synthetic fixed-size payloads` };
    console.log(JSON.stringify(metrics));
    await writeFile(`${reports}/viewport-metrics.json`, JSON.stringify(metrics, null, 2));
    await page.screenshot({ path: `${reports}/viewport-50000.png` });
    await page.evaluate(() => window.loadRows(10));
    await page.getByText('HOST-9', { exact: true }).waitFor();
    await page.getByRole('row').filter({ hasText: 'HOST-9' }).press('Enter');
    assert.equal(await page.evaluate(() => window.selectedRow), 9);
    await page.evaluate(() => window.breakView());
    await page.getByRole('alert').waitFor();
    // Timing and heap are recorded, not hardware-dependent CI promises.
  } finally { await page.close(); }
});

test('dashboard: one SSE stream, coalesced updates, filters, stale responses, pause and fleet details', async () => {
  const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
  const requests = [];
  let version = 0, fail = false;
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(() => {
    window.streams = [];
    window.EventSource = class extends EventTarget {
      constructor(url) {
        super(); this.url = url; this.closed = false; window.streams.push(this);
        setTimeout(() => { if (!this.closed) this.onopen?.(); }, 0);
      }
      close() { this.closed = true; }
    };
    window.emitTelemetry = () => window.streams.filter(s => !s.closed)
      .forEach(s => s.dispatchEvent(new MessageEvent('telemetry_changed', { data: '{}' })));
  });
  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url());
    let body;
    if (url.pathname.endsWith('/telemetry')) {
      requests.push(url.searchParams);
      if (url.searchParams.get('search') === 'OLD') await new Promise(resolve => setTimeout(resolve, 650));
      if (fail) { await route.fulfill({ status: 503, json: { error: { message: 'Database busy' } } }); return; }
      body = { ok: true, total: 50, logs: [{ id: version,
        hostname: url.searchParams.get('search') || `LIVE-${version}`, username: 'alice',
        collector: 'file-collector', collected_at: new Date().toISOString(), status: 'success', payload: { count: version } }] };
    } else if (url.pathname.endsWith('/dashboard-summary')) {
      body = { ok: true, pc_status: { total_pcs: 3, online_pcs: 1, offline_pcs: 2, endpoints: [
        { hostname: 'DESKTOP-SOMS', status: 'online', last_seen_at: new Date().toISOString() },
        { hostname: 'TEST-VM', status: 'offline', last_seen_at: '2026-10-01T00:00:00Z' },
        { hostname: 'UNSEEN', status: 'offline', last_seen_at: null },
      ] }, agents: [], risk_counts: {}, risk_events: [], stats: {} };
    } else body = { ok: true, status: 'ok', database: 'ok' };
    await route.fulfill({ json: body });
  });
  try {
    await page.goto(base);
    await page.getByText('LIVE-0', { exact: true }).waitFor();
    assert.equal(await page.evaluate(() => window.streams.filter(s => !s.closed).length), 1);
    assert.equal(await page.evaluate(() => window.streams.find(s => !s.closed).url), '/api/v1/stream/dashboard');
    const before = requests.length;
    version = 1;
    await page.evaluate(() => { for (let i = 0; i < 1000; i++) window.emitTelemetry(); });
    await page.getByText('LIVE-1', { exact: true }).waitFor();
    assert.ok(requests.length - before <= 2, 'bursts should not issue one REST query per event');
    const search = page.getByRole('textbox', { name: 'Search telemetry' });
    await search.fill('OLD');
    await page.waitForRequest(req => new URL(req.url()).searchParams.get('search') === 'OLD');
    await search.fill('NEW');
    await page.getByText('NEW', { exact: true }).waitFor();
    await page.waitForTimeout(700);
    assert.equal(await page.getByText('OLD', { exact: true }).count(), 0);
    await page.getByLabel('Collector', { exact: true }).selectOption('device');
    await page.getByLabel('Status', { exact: true }).selectOption('error');
    await page.getByLabel('Time range', { exact: true }).selectOption('1h');
    await page.waitForResponse(resp => {
      const p = new URL(resp.url()).searchParams;
      return p.get('search') === 'NEW' && p.get('collector') === 'device' && p.get('status') === 'error' && p.has('start_time');
    });
    assert.equal(requests.at(-1).has('username'), false);
    fail = true;
    await page.evaluate(() => window.emitTelemetry());
    await page.getByRole('alert').filter({ hasText: 'Database busy' }).waitFor();
    await page.getByText('NEW', { exact: true }).waitFor();
    fail = false;
    await page.getByRole('button', { name: 'Retry', exact: true }).click();
    await page.getByRole('alert').waitFor({ state: 'hidden' });
    await page.getByRole('button', { name: 'Pause', exact: true }).click();
    assert.equal(await page.evaluate(() => window.streams.filter(s => !s.closed).length), 0);
    const paused = requests.length;
    await page.waitForTimeout(3200);
    assert.equal(requests.length, paused);
    await page.getByRole('button', { name: /^Total PCs/ }).last().click();
    await page.getByText('DESKTOP-SOMS', { exact: true }).waitFor();
    await page.getByText('TEST-VM', { exact: true }).waitFor();
    await page.screenshot({ path: `${reports}/dashboard-fleet.png`, fullPage: true });
    await page.keyboard.press('Escape');
    await page.getByRole('button', { name: /^Online/ }).last().click();
    await page.getByText('DESKTOP-SOMS', { exact: true }).waitFor();
    assert.equal(await page.getByText('TEST-VM', { exact: true }).count(), 0);
    assert.deepEqual(errors, []);
  } finally { await page.close(); }
});
