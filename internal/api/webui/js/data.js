// Server data access and the few stateful operations the panel performs.
// Every screen reads the same store; no screen keeps a second copy.

import { api } from './api.js';
import { store, toast, toastError } from './store.js';

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export async function refreshStatus() {
  try {
    const status = await api.get('/status');
    store.set({ status, statusAt: new Date().toISOString(), statusError: '' });
    return status;
  } catch (err) {
    store.set({ statusError: err.message });
    throw err;
  }
}

export async function loadConnections() {
  try {
    const data = await api.get('/connections?include_hidden=1');
    store.set({ connections: (data && data.connections) || [], connectionsLoaded: true });
    return store.get().connections;
  } catch (err) {
    store.set({ connectionsLoaded: true });
    throw err;
  }
}

export async function loadGroups() {
  try {
    const data = await api.get('/layer/groups');
    store.set({ groups: (data && data.groups) || [], groupsLoaded: true });
    return store.get().groups;
  } catch (err) {
    store.set({ groups: [], groupsLoaded: true });
    throw err;
  }
}

export async function loadLayer() {
  let layer = null;
  try {
    layer = await api.get('/layer/status');
  } catch {
    layer = null;
  }
  let plan = null;
  if (layer && !layer.migrated) {
    try { plan = await api.get('/layer/plan'); } catch { plan = null; }
  }
  store.set({ layer, layerPlan: plan });
  return layer;
}

export async function migrateLayer(dryRun) {
  const plan = await api.post('/layer/migrate', { dry_run: !!dryRun });
  if (!dryRun) {
    await Promise.all([loadLayer(), loadGroups(), loadConnections(), refreshStatus()]);
    toast('Organisation layer created. Your import lists are unchanged.', 'success', 7000);
  }
  return plan;
}

export async function loadResults() {
  try {
    if (!store.get().connectionsLoaded) await loadConnections().catch(() => {});
    const connections = store.get().connections || [];
    const ids = connections.map((connection) => connection.stable_id || connection.id).filter(Boolean);
    const pages = await Promise.allSettled(ids.map((id) =>
      api.get(`/tests/results?connection=${encodeURIComponent(id)}`)));
    const results = [];
    for (const page of pages) {
      if (page.status === 'fulfilled' && Array.isArray(page.value)) results.push(...page.value);
    }
    store.set({ results, resultsLoaded: true });
  } catch {
    store.set({ resultsLoaded: true });
  }
  return store.get().results;
}

export async function loadSources() {
  try {
    const data = await api.get('/subscriptions');
    store.set({ subscriptions: (data && data.subscriptions) || [], subscriptionsLoaded: true });
  } catch (err) {
    store.set({ subscriptionsLoaded: true });
    throw err;
  }
}

export async function loadSettings() {
  const settings = await api.get('/settings');
  store.set({ settings, settingsLoaded: true });
  return settings;
}

export async function loadEngines() {
  try {
    const data = await api.get('/engines');
    store.set({ engines: Array.isArray(data) ? data : (data && data.engines) || [] });
  } catch {
    store.set({ engines: [] });
  }
}

export async function loadLogs(limit = 300) {
  const data = await api.get(`/logs?limit=${encodeURIComponent(limit)}`);
  store.set({ logs: (data && data.logs) || [], logsAt: new Date().toISOString() });
  return store.get().logs;
}

export async function loadTargets() {
  const targets = await api.get('/tests/targets');
  store.set({ targets: targets || [], targetsLoaded: true });
  return store.get().targets;
}

export async function loadUsage() {
  const usage = await api.get('/tests/usage');
  store.set({ usage });
  return usage;
}

export async function probeExit(quiet = false) {
  store.set({ exitBusy: true });
  try {
    const info = await api.post('/exit-ip');
    const exit = {
      ip: info.ip,
      country: info.country,
      city: info.city,
      at: new Date().toISOString(),
    };
    store.set({ exit, exitBusy: false });
    if (!quiet) toast(`Exit ${info.ip}${info.country ? ` · ${info.country}` : ''}`, 'success');
    return exit;
  } catch (err) {
    const exit = { error: err.message, at: new Date().toISOString() };
    store.set({ exit, exitBusy: false });
    if (!quiet) toastError(err);
    return exit;
  }
}

// --- switching the tunnel --------------------------------------------------

function patchSheet(patch) {
  store.set((s) => (s.switchSheet ? { switchSheet: { ...s.switchSheet, ...patch } } : {}));
}

export function dismissSwitchSheet() {
  store.set({ switchSheet: null });
}

async function waitForState(wanted, timeoutMs = 45000) {
  const deadline = Date.now() + timeoutMs;
  let status = null;
  while (Date.now() < deadline) {
    await sleep(1200);
    try { status = await refreshStatus(); } catch { continue; }
    const state = String((status && status.state) || '').toUpperCase();
    if (wanted.includes(state)) return status;
  }
  return status;
}

async function runSwitch(label, action, verify) {
  const startedAt = Date.now();
  store.set({ switchSheet: { label, phase: 'stopping', startedAt, message: '', exit: null } });
  let result;
  try {
    patchSheet({ phase: 'starting' });
    result = await action();
  } catch (err) {
    patchSheet({ phase: 'failed', message: err.message, finishedAt: Date.now() });
    throw err;
  }
  if (result && result.applied === false) {
    patchSheet({
      phase: 'failed',
      message: result.message || 'The gateway did not apply the change and kept its previous state.',
      finishedAt: Date.now(),
    });
    return result;
  }
  if (verify) {
    patchSheet({ phase: 'verifying', message: 'Waiting for the tunnel to report it is serving.' });
    const status = await waitForState(['CONNECTED', 'FAILED', 'DISCONNECTED']);
    const state = String((status && status.state) || '').toUpperCase();
    if (state !== 'CONNECTED') {
      patchSheet({
        phase: 'failed',
        message: status && status.last_error
          ? status.last_error
          : 'The tunnel did not reach the serving state in time.',
        finishedAt: Date.now(),
      });
      await Promise.all([loadConnections().catch(() => {}), refreshStatus().catch(() => {})]);
      return result;
    }
    const exit = await probeExit(true);
    patchSheet({ phase: 'done', exit, finishedAt: Date.now() });
  } else {
    patchSheet({ phase: 'done', finishedAt: Date.now() });
  }
  await Promise.all([loadConnections().catch(() => {}), refreshStatus().catch(() => {})]);
  return result;
}

export async function connectTo(id) {
  const connection = store.get().connections.find((c) => c.id === id);
  const name = connection ? (connection.display_name || connection.remark) : id;
  return runSwitch(`Connecting to ${name}…`, () => api.post('/connect', { id }), true);
}

export async function restorePrevious() {
  return runSwitch('Restoring the previous connection…', () => api.post('/connections/restore'), true);
}

export async function restartTunnel() {
  return runSwitch('Reconnecting the tunnel…', () => api.post('/restart'), true);
}

export async function disconnectTunnel() {
  return runSwitch('Disconnecting the tunnel…', () => api.post('/disconnect'), false);
}

export async function setSelection(id) {
  const result = await api.post('/connections/active', { id });
  await Promise.all([loadConnections().catch(() => {}), refreshStatus().catch(() => {})]);
  return result;
}

// --- tests -----------------------------------------------------------------

let jobStream = null;
let jobTimer = null;
let jobTerminal = false;

function terminalJob(state) {
  return ['done', 'failed', 'cancelled'].includes(state);
}

function applyJob(job) {
  if (!job) return;
  store.set({ job });
  if (terminalJob(job.state) && !jobTerminal) {
    jobTerminal = true;
    stopJobWatch();
    loadResults().catch(() => {});
    toast(
      job.state === 'done' ? 'Test finished.' : job.state === 'cancelled' ? 'Test cancelled.' : `Test failed${job.error ? `: ${job.error}` : '.'}`,
      job.state === 'done' ? 'success' : job.state === 'cancelled' ? 'info' : 'error',
      7000,
    );
  }
}

function stopJobWatch() {
  if (jobStream) {
    try { jobStream.close(); } catch { /* already closed */ }
    jobStream = null;
  }
  if (jobTimer) {
    clearInterval(jobTimer);
    jobTimer = null;
  }
  store.set({ jobPolling: false });
}

async function pollJob(id) {
  try {
    const job = await api.get(`/tests/jobs/${encodeURIComponent(id)}`);
    applyJob(job);
  } catch {
    // The SSE stream and the next poll both retry; a transient read failure
    // must not cancel the job or clear the table.
  }
}

function watchJob(id, after = 0) {
  stopJobWatch();
  jobTerminal = false;
  store.set({ jobPolling: true });
  try {
    const stream = new EventSource(`/api/v1/app/tests/jobs/${encodeURIComponent(id)}/events?after=${after}`);
    jobStream = stream;
    let lastSeq = after;
    stream.addEventListener('test', (event) => {
      try {
        const ev = JSON.parse(event.data);
        lastSeq = ev.seq || lastSeq;
        const current = store.get().job;
        if (!current || current.id !== id) return;
        const results = ev.result
          ? [...(current.results || []), ev.result]
          : current.results || [];
        applyJob({
          ...current,
          state: ev.state || current.state,
          stage: ev.stage || current.stage,
          completed: ev.completed ?? current.completed,
          total: ev.total ?? current.total,
          results,
          error: ev.error || current.error,
        });
      } catch {
        // Ignore a malformed event; the poll below is authoritative.
      }
    });
    stream.onerror = () => {
      // The polling fallback keeps running, so a dropped stream loses nothing.
      try { stream.close(); } catch { /* noop */ }
      if (jobStream === stream) jobStream = null;
    };
  } catch {
    // EventSource is absent or blocked; the poll below still drives the job.
  }
  jobTimer = setInterval(() => {
    if (jobTerminal) { stopJobWatch(); return; }
    pollJob(id);
  }, 1200);
  pollJob(id);
}

export async function startTestJob(req) {
  const job = await api.post('/tests/jobs', req);
  applyJob(job);
  watchJob(job.id);
  return job;
}

export async function cancelTestJob() {
  const job = store.get().job;
  if (!job) return;
  await api.post(`/tests/jobs/${encodeURIComponent(job.id)}/cancel`);
  await pollJob(job.id);
}

export async function testBudget(req) {
  return api.post('/tests/budget', req);
}

export async function addSpeedTarget(url) {
  const target = await api.post('/tests/targets', { url });
  await loadTargets();
  return target;
}

export async function deleteSpeedTarget(id) {
  await api.del(`/tests/targets/${encodeURIComponent(id)}`);
  await loadTargets();
}

export async function validateSpeedTarget(id) {
  const target = await api.post(`/tests/targets/${encodeURIComponent(id)}/validate`);
  await loadTargets();
  return target;
}

// --- sources ---------------------------------------------------------------

export async function addSubscription(url, group) {
  const added = await api.post('/subscriptions/add', { url, group: group || '' });
  await loadSources();
  try {
    await api.post('/subscriptions/refresh', { group: added.group, url: added.url });
  } catch (err) {
    toast(`Source stored, but the first refresh failed: ${err.message}`, 'warn', 9000);
  }
  await Promise.all([loadSources(), loadConnections().catch(() => {})]);
  return added;
}

export async function refreshSubscription(subscription) {
  const result = await api.post('/subscriptions/refresh', { group: subscription.group, url: subscription.url });
  await Promise.all([loadSources(), loadConnections().catch(() => {}), loadResults().catch(() => {})]);
  return result;
}

export async function refreshAllSubscriptions() {
  const list = store.get().subscriptions;
  let ok = 0;
  let failed = 0;
  for (const subscription of list) {
    try {
      await api.post('/subscriptions/refresh', { group: subscription.group, url: subscription.url });
      ok += 1;
    } catch {
      failed += 1;
    }
  }
  await Promise.all([loadSources(), loadConnections().catch(() => {})]);
  return { ok, failed };
}

export async function importSubscriptionText(group, text) {
  const result = await api.post('/subscriptions/import', { group, text });
  await Promise.all([loadSources(), loadConnections().catch(() => {})]);
  return result;
}

export { sleep, toast, toastError };
