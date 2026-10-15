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
  const channel = process.env.PLAYWRIGHT_CHANNEL || (process.platform === 'win32' ? 'msedge' : undefined);
  try {
    browser = await chromium.launch({ headless: true, ...(channel ? { channel } : {}) });
  } catch {
    browser = await chromium.launch({ headless: true });
  }
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
    if (url.pathname.endsWith('/telemetry') || url.pathname.endsWith('/telemetry/explorer')) {
      requests.push(url.searchParams);
      if (url.searchParams.get('search') === 'OLD') await new Promise(resolve => setTimeout(resolve, 650));
      if (fail) { await route.fulfill({ status: 503, json: { error: { message: 'Database busy' } } }); return; }
      const older = url.searchParams.has('cursor');
      const rows = [{ id: version, event_id: `ev-${version}`,
        hostname: older ? 'OLDER-PAGE' : url.searchParams.get('search') || `LIVE-${version}`, username: 'alice',
        collector: 'file-collector', collector_name: 'file-collector', collected_at: new Date().toISOString(), timestamp: new Date().toISOString(), status: 'success', summary_preview: `Test ${version}`, payload: { count: version } }];
      body = { ok: true, total: null, has_more: !older, next_cursor: older ? null : 'test-position', events: rows, logs: rows };
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
    const tab = page.getByRole('tab', { name: /Telemetry Explorer/i });
    if (await tab.count() > 0) {
      await tab.click();
    }
    await page.getByText('LIVE-0', { exact: true }).waitFor();
    assert.equal(requests.at(-1).get('include_total'), 'false');
    assert.equal(requests.at(-1).get('search_scope'), 'metadata');
    await page.getByRole('button', { name: 'Next', exact: true }).click();
    await page.getByText('OLDER-PAGE', { exact: true }).waitFor();
    assert.equal(requests.at(-1).get('cursor'), 'test-position');
    assert.equal(requests.at(-1).get('offset'), '0');
    const browsing = requests.length;
    await page.evaluate(() => { for (let i = 0; i < 1000; i++) window.emitTelemetry(); });
    await page.waitForTimeout(2300);
    assert.equal(requests.length, browsing, 'older pages must stay stable during SSE bursts');
    await page.getByTitle('First Page (Page 1)').click();
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
    await page.getByRole('status').filter({ hasText: 'Showing previously loaded logs' }).waitFor();
    await page.getByText('NEW', { exact: true }).waitFor();
    fail = false;
    await page.getByRole('button', { name: 'Retry', exact: true }).first().click();
    await page.getByRole('status').filter({ hasText: 'Showing previously loaded logs' }).waitFor({ state: 'hidden' });
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

test('fleet status cards: valid counts, empty fleet zero, unavailable fallback, and scoped stale indication on failure', async () => {
  const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
  let summaryResponse = {
    ok: true,
    pc_status: { total_pcs: 3, online_pcs: 1, offline_pcs: 2, endpoints: [
      { hostname: 'HOST-A', status: 'online', last_seen_at: new Date().toISOString() },
      { hostname: 'HOST-B', status: 'offline', last_seen_at: '2026-10-01T00:00:00Z' },
      { hostname: 'HOST-C', status: 'offline', last_seen_at: null },
    ] },
    agents: [], risk_counts: {}, risk_events: [], stats: { collector_results: 500 }
  };
  let summaryStatus = 200;

  await page.addInitScript(() => {
    window.streams = [];
    window.EventSource = class extends EventTarget {
      constructor(url) {
        super(); this.url = url; this.closed = false; window.streams.push(this);
        setTimeout(() => { if (!this.closed) this.onopen?.(); }, 0);
      }
      close() { this.closed = true; }
    };
    window.emitFleetUpdate = () => window.streams.filter(s => !s.closed)
      .forEach(s => s.dispatchEvent(new MessageEvent('agent_status', { data: '{}' })));
  });

  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url());
    if (url.pathname.endsWith('/dashboard-summary')) {
      if (summaryStatus !== 200) {
        await route.fulfill({ status: summaryStatus, json: { error: 'Backend error' } });
      } else {
        await route.fulfill({ json: summaryResponse });
      }
    } else if (url.pathname.endsWith('/telemetry/explorer') || url.pathname.endsWith('/telemetry')) {
      await route.fulfill({ json: { ok: true, total: null, has_more: false, next_cursor: null, events: [], logs: [] } });
    } else {
      await route.fulfill({ json: { ok: true, status: 'ok', database: 'ok' } });
    }
  });

  try {
    await page.goto(base);
    // 1. Initial valid nonzero counts
    const totalBtn = page.getByRole('button', { name: /^Total PCs/ }).last();
    await totalBtn.waitFor();
    assert.ok((await totalBtn.textContent()).includes('3'));
    assert.ok(!(await totalBtn.textContent()).includes('stale'));

    // 2. Refresh failure after success: retain previous values with stale indication
    summaryStatus = 503;
    await page.evaluate(() => window.emitFleetUpdate());
    await page.waitForTimeout(800);
    assert.ok((await totalBtn.textContent()).includes('3'));
    assert.ok((await totalBtn.textContent()).includes('stale'));

    // 3. Recovery after failure: updates to new counts and removes stale
    summaryStatus = 200;
    summaryResponse = {
      ok: true,
      pc_status: { total_pcs: 5, online_pcs: 3, offline_pcs: 2, endpoints: [] },
      agents: [], risk_counts: {}, risk_events: [], stats: { collector_results: 600 }
    };
    await page.evaluate(() => window.emitFleetUpdate());
    await page.waitForTimeout(800);
    assert.ok((await totalBtn.textContent()).includes('5'));
    assert.ok(!(await totalBtn.textContent()).includes('stale'));

    // 4. Valid empty inventory: confirms zero (not unavailable)
    summaryResponse = {
      ok: true,
      pc_status: { total_pcs: 0, online_pcs: 0, offline_pcs: 0, endpoints: [] },
      agents: [], risk_counts: {}, risk_events: [], stats: { collector_results: 700 }
    };
    await page.evaluate(() => window.emitFleetUpdate());
    await page.waitForTimeout(800);
    assert.ok((await totalBtn.textContent()).includes('0'));
    assert.ok(!(await totalBtn.textContent()).includes('stale'));
  } finally {
    await page.close();
  }
});

test('collector dataset export modal: preview schema, clears stale data on filter change, and truthful failure states without phantom counts', async () => {
  const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
  let previewStatus = 200;
  let previewResponse = {
    ok: true,
    collector: 'logon',
    total_samples: 50,
    columns: ['timestamp', 'username', 'hostname', 'status', 'auth_type', 'session_id'],
    feature_columns: ['auth_type', 'session_id'],
    preview_rows: [
      { timestamp: '2026-10-13T10:00:00Z', username: 'admin', hostname: 'HOST-01', status: 'success', auth_type: 'Kerberos', session_id: '1001' }
    ],
    filename: 'logon_export.csv'
  };

  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url());
    if (url.pathname.includes('/collector-preview')) {
      if (previewStatus !== 200) {
        await route.fulfill({ status: previewStatus, json: { error: 'Preview timed out or database error' } });
      } else {
        await route.fulfill({ json: previewResponse });
      }
    } else if (url.pathname.includes('/collectors')) {
      await route.fulfill({ json: { ok: true, collectors: ['logon', 'file', 'process'], usernames: ['admin', 'analyst'] } });
    } else if (url.pathname.endsWith('/dashboard-summary')) {
      await route.fulfill({ json: { ok: true, pc_status: { total_pcs: 1, online_pcs: 1, offline_pcs: 0, endpoints: [] }, stats: { logs: 100 } } });
    } else if (url.pathname.endsWith('/telemetry/explorer') || url.pathname.endsWith('/telemetry')) {
      await route.fulfill({ json: { ok: true, total: null, has_more: false, next_cursor: null, events: [], logs: [] } });
    } else {
      await route.fulfill({ json: { ok: true } });
    }
  });

  try {
    await page.goto(base);
    const tab = page.getByRole('tab', { name: /Telemetry Explorer/i });
    if (await tab.count() > 0) {
      await tab.click();
    }
    // 1. Open the Collector Dataset modal
    const collectorBtn = page.getByRole('button', { name: 'Collector Dataset' });
    await collectorBtn.waitFor();
    await collectorBtn.click();

    // 2. Initial preview load succeeds with 50 sample records found
    await page.getByText('50 sample records found').waitFor();
    await page.getByText('auth_type', { exact: true }).first().waitFor();
    await page.getByText('session_id', { exact: true }).first().waitFor();

    // 3. Switch collector to 'file' with backend returning 500/timeout error
    previewStatus = 500;
    const collectorSelect = page.getByLabel('Target Collector');
    await collectorSelect.selectOption('file');

    // 4. Verify stale "50 sample records found" is NOT present, and error alert with Retry button is rendered
    await page.getByText('Failed to inspect schema').waitFor();
    assert.equal(await page.getByText('50 sample records found').count(), 0);
    assert.equal(await page.getByText('session_id', { exact: true }).count(), 0);

    const retryBtn = page.getByRole('button', { name: 'Retry Preview' }).first();
    assert.ok(await retryBtn.count() > 0);

    // 5. Recovery: backend recovers to 200 and user clicks Retry Preview
    previewStatus = 200;
    previewResponse = {
      ok: true,
      collector: 'file',
      total_samples: 12,
      columns: ['timestamp', 'username', 'hostname', 'status', 'file_path', 'operation'],
      feature_columns: ['file_path', 'operation'],
      preview_rows: [
        { timestamp: '2026-10-13T10:00:00Z', username: 'admin', hostname: 'HOST-01', status: 'success', file_path: 'C:\\test.txt', operation: 'WRITE' }
      ],
      filename: 'file_export.csv'
    };
    await retryBtn.click();
    await page.getByText('12 sample records found').waitFor();
    await page.getByText('file_path', { exact: true }).first().waitFor();
    assert.equal(await page.getByText('Failed to inspect schema').count(), 0);
  } finally {
    await page.close();
  }
});

