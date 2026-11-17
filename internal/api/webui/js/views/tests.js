// Tests: operational benchmarks (real HTTPS latency and bounded speed) are
// separated from independent path verification. Every result shows which layer
// it came from; nothing is ranked as a proven path without L1+L2.

import { html, Chip, Banner, Empty, Skeleton, Tabs, Progress, KV, Footnote, ByteNote, ResultChip, RelTime } from '../ui.js';
import { useState, useEffect } from '../../vendor/hooks.module.js';
import { store, toast, toastError } from '../store.js';
import { navigate } from '../nav.js';
import {
  loadResults, loadTargets, loadUsage, startTestJob, cancelTestJob,
  validateSpeedTarget, deleteSpeedTarget,
} from '../data.js';
import {
  connectionName, evidenceOf, connectivityOf, verdictOf, reasonText, pathKind, fmtLatency, fmtMB, timeAgo,
  verifiedResult, invalidateSupersededResults, throughputText, downloadedText, mbPerSec, delayMS,
} from '../format.js';
import { BudgetDialog, TargetAddDialog, TargetDeleteDialog } from '../dialogs.js';

const TABS = [
  { id: 'run', label: 'Run' },
  { id: 'results', label: 'Results' },
  { id: 'compare', label: 'Compare' },
  { id: 'targets', label: 'Targets' },
];

export default function TestsView({ state }) {
  const tab = TABS.some((item) => item.id === state.tab) ? state.tab : 'run';
  const job = state.job;
  const running = !!(job && ['queued', 'running'].includes(job.state));
  return html`<div class="view-head">
    <div>
      <h1>Tests</h1>
      <div class="sub">A test measures what a connection actually carries. An operational result answers real HTTPS traffic through the selected engine; a verified result additionally proves the isolated path and the independent exit, and only that layer is ranked as a proven path.</div>
    </div>
    <div class="view-actions">
      ${running ? html`<button class="btn danger" type="button" onClick=${() => cancelTestJob().catch(toastError)}>Cancel job</button>` : null}
    </div>
  </div>
  <${Tabs} tabs=${TABS} active=${tab} onChange=${(id) => navigate('tests', id)} />
  ${tab === 'run' ? html`<${RunPanel} state=${state} />` : null}
  ${tab === 'results' ? html`<${ResultsPanel} state=${state} />` : null}
  ${tab === 'compare' ? html`<${ComparePanel} state=${state} />` : null}
  ${tab === 'targets' ? html`<${TargetsPanel} state=${state} />` : null}`;
}

function scopeOptions(state) {
  const connections = (state.connections || []).filter((connection) => !connection.hidden);
  const groups = [];
  const seen = new Set();
  for (const connection of connections) {
    const name = connection.layer_group || connection.group;
    if (name && !seen.has(name)) {
      seen.add(name);
      groups.push(name);
    }
  }
  return { connections, groups };
}

function RunPanel({ state }) {
  const { connections, groups } = scopeOptions(state);
  const [kind, setKind] = useState('latency');
  const [scopeKind, setScopeKind] = useState('all');
  const [group, setGroup] = useState('');
  const [connection, setConnection] = useState('');
  const [includeHidden, setIncludeHidden] = useState(false);
  const job = state.job;
  const running = !!(job && ['queued', 'running'].includes(job.state));
  const results = (job && job.results) || [];
  const skippedByBudget = results.filter((result) => result.status === 'skipped' && result.reason === 'BUDGET_REACHED').length;

  useEffect(() => {
    if (scopeKind === 'group' && !group && groups.length) setGroup(groups[0]);
    if (scopeKind === 'link' && !connection && connections.length) setConnection(connections[0].id);
  }, [scopeKind, groups.length, connections.length]);

  const request = () => {
    const scope = scopeKind === 'all'
      ? { kind: 'all' }
      : scopeKind === 'group'
        ? { kind: 'group', group }
        : { kind: 'link', connection_id: connection };
    return { kind, scope, include_hidden: includeHidden };
  };

  const run = async () => {
    try {
      await startTestJob(request());
      toast(kind === 'speed' ? 'Speed test started.' : 'Relay test started.', 'success');
    } catch (err) {
      toastError(err);
    }
  };

  const openBudget = () => {
    store.set({ dialog: html`<${BudgetDialog} request=${request()} onClose=${() => store.set({ dialog: null })}
      onStart=${() => startTestJob(request())} />` });
  };

  const disabled = running || (scopeKind === 'group' && !group) || (scopeKind === 'link' && !connection);

  return html`<div class="panel">
    <h2>New measurement</h2>
    <div class="grid2">
      <label>What to measure
        <select value=${kind} onChange=${(e) => setKind(e.target.value)}>
          <option value="latency">Relay and latency</option>
          <option value="speed">Download speed (bounded)</option>
        </select>
      </label>
      <label>Scope
        <select value=${scopeKind} onChange=${(e) => setScopeKind(e.target.value)}>
          <option value="all">All connections</option>
          <option value="group">One group</option>
          <option value="link">One connection</option>
        </select>
      </label>
      ${scopeKind === 'group' ? html`<label>Group
        <select value=${group} onChange=${(e) => setGroup(e.target.value)}>
          ${groups.map((name) => html`<option key=${name} value=${name}>${name}</option>`)}
        </select>
      </label>` : null}
      ${scopeKind === 'link' ? html`<label>Connection
        <select value=${connection} onChange=${(e) => setConnection(e.target.value)}>
          ${connections.map((item) => html`<option key=${item.id} value=${item.id}>${connectionName(item)}</option>`)}
        </select>
      </label>` : null}
      <label class="check"><input type="checkbox" checked=${includeHidden} onChange=${(e) => setIncludeHidden(e.target.checked)} /> Include hidden connections</label>
    </div>
    <div class="actions">
      <button class="btn primary" type="button" disabled=${disabled} onClick=${kind === 'speed' ? openBudget : run}>
        ${running ? 'A job is running' : kind === 'speed' ? 'Review budget and start' : 'Start relay test'}
      </button>
      ${running ? html`<button class="btn ghost" type="button" onClick=${() => cancelTestJob().catch(toastError)}>Cancel</button>` : null}
      <button class="btn ghost" type="button" onClick=${() => loadResults().catch(toastError)}>Reload results</button>
    </div>
    <p class="muted small">${kind === 'speed'
      ? 'Speed runs are serial, one connection at a time, and are capped per connection and per batch. A connection needs a recent HTTPS measurement, not a proven exit. Upload testing is not available in this release.'
      : 'Relay tests start an isolated test tunnel per connection, answer a real HTTPS probe through it and compare the observed exit with the uplink and the serving tunnel. A result without L1+L2 is reported as a measured operational result, never as a proven path.'}</p>

    ${job ? html`<div class="stack" style="margin-top:12px">
      <div class="row">
        <strong class="grow">${job.kind === 'speed' ? 'Speed job' : 'Relay job'} <span class="muted small mono">${job.id}</span></strong>
        <${Chip} state=${job.state === 'done' ? 'healthy' : job.state === 'failed' ? 'failed' : job.state === 'cancelled' ? 'cancelled' : 'testing'}
          label=${job.state === 'done' ? 'Done' : job.state === 'running' ? 'Running' : job.state} />
      </div>
      <${Progress} completed=${job.completed || 0} total=${job.total || 0} state=${job.state} />
      <div class="muted small">${job.stage ? `${job.stage} · ` : ''}${job.completed || 0} of ${job.total || 0}${job.error ? ` · ${job.error}` : ''}</div>
      ${job.kind === 'speed' && job.planned_links ? html`<div class="muted small">
        Plan: ${job.planned_links} of ${job.total || 0} connections measured, at most ${fmtMB(job.planned_bytes || 0)} this batch${job.budget_skipped ? ` · ${job.budget_skipped} would be skipped by budget` : ''}. The batch stops on the bytes it actually spent.
      </div>` : null}
      ${skippedByBudget ? html`<div class="muted small">${skippedByBudget} connection${skippedByBudget === 1 ? ' was' : 's were'} not measured because the batch traffic budget was spent. They are not failures.</div>` : null}
      ${results.length ? html`<div class="table-wrap"><table class="data">
        <thead><tr><th>Connection</th><th>Result</th><th>Evidence</th><th>Path</th></tr></thead>
        <tbody>${results.map((result) => html`<tr key=${`${result.connection_id}:${result.kind}:${result.tested_at}`}>
          <td>${result.remark || result.connection_id}</td>
          <td><${ResultChip} result=${result} /></td>
          <td class="small muted">${evidenceOf(result)}</td>
          <td class="small muted">${pathKind(result) || '—'}</td>
        </tr>`)}</tbody>
      </table></div>` : html`<p class="empty">Results appear as each connection finishes.</p>`}
    </div>` : null}
  </div>

  <div class="panel">
    <h2>What makes a result trustworthy</h2>
    <ul class="bullets muted">
      <li><strong>Operational measurement</strong>: a real HTTPS probe answers through the tested connection, and latency or downloaded bytes are recorded only from that answer. An open listener or a bare TCP handshake never counts.</li>
      <li><strong>L1 construction audit</strong>: the test engine configuration is checked before it starts; a shared or non-isolated configuration is refused.</li>
      <li><strong>L2 independent exit identity</strong>: two echo services must agree on the public address, and it must differ from the uplink and from the serving tunnel.</li>
      <li><strong>Route decisions</strong>: the target must be routed through the test tunnel; a DIRECT target invalidates the measurement.</li>
      <li><strong>Stability</strong>: the policy revision and the exit must not change during the measurement.</li>
      <li><strong>Negative control</strong>: the serving tunnel re-checks that DIRECT traffic is not silently absorbed by the tunnel.</li>
    </ul>
    <p class="footnote">A measured result is usable evidence that traffic flowed, even when the exit is shared or could not be identified. Only a verified result is ranked as a proven path. EXIT_EQUALS_UPLINK stays a refusal: that traffic went DIRECT, so nothing was measured.</p>
  </div>`;
}

function failureRank(result) {
  switch (result.status) {
    case 'failed': return 0;
    case 'unavailable': return 1;
    case 'inconclusive': return 2;
    default: return 3;
  }
}

function sortResults(list, mode) {
  const ms = (result) => delayMS(result);
  const recent = (a, b) => String(b.tested_at || '').localeCompare(String(a.tested_at || ''));
  // A superseded or stale row is history, not a current ranking candidate. A
  // failed row may still carry a fast delay, but it has no completed sample, so
  // it sorts after rows that do.
  const current = (result) => (result.superseded || result.stale ? 1 : 0);
  const complete = (result) => (result.status === 'ok' || result.status === 'measured' ? 0 : 1);
  const rows = list.slice();
  if (mode === 'latency') {
    return rows.sort((a, b) => complete(a) - complete(b) || current(a) - current(b)
      || (ms(a) || Number.POSITIVE_INFINITY) - (ms(b) || Number.POSITIVE_INFINITY) || recent(a, b));
  }
  if (mode === 'speed') {
    return rows.sort((a, b) => current(a) - current(b) || (b.mbps || -1) - (a.mbps || -1) || recent(a, b));
  }
  if (mode === 'failures') {
    return rows.sort((a, b) => failureRank(a) - failureRank(b) || recent(a, b));
  }
  return rows.sort(recent);
}

function ResultsPanel({ state }) {
  const [connectionFilter, setConnectionFilter] = useState('');
  const [kindFilter, setKindFilter] = useState('');
  const [sortBy, setSortBy] = useState('recent');
  const [expanded, setExpanded] = useState('');
  const filtered = invalidateSupersededResults(state.results).filter((result) => {
    if (connectionFilter && result.connection_id !== connectionFilter) return false;
    if (kindFilter && result.kind !== kindFilter) return false;
    return true;
  });
  const results = sortResults(filtered, sortBy);
  const connectionIds = Array.from(new Set((state.results || []).map((result) => result.connection_id)));

  return html`<div class="panel">
    <div class="toolbar">
      <select aria-label="Filter by connection" value=${connectionFilter} onChange=${(e) => setConnectionFilter(e.target.value)}>
        <option value="">All connections</option>
        ${connectionIds.map((id) => {
          const result = (state.results || []).find((item) => item.connection_id === id);
          return html`<option key=${id} value=${id}>${result ? result.remark || id : id}</option>`;
        })}
      </select>
      <select aria-label="Filter by kind" value=${kindFilter} onChange=${(e) => setKindFilter(e.target.value)}>
        <option value="">All tests</option>
        <option value="latency">Relay and latency</option>
        <option value="speed">Download speed</option>
      </select>
      <select aria-label="Sort results" value=${sortBy} onChange=${(e) => setSortBy(e.target.value)}>
        <option value="recent">Last tested</option>
        <option value="latency">Lowest latency</option>
        <option value="speed">Fastest download</option>
        <option value="failures">Failures first</option>
      </select>
      <button class="btn ghost small" type="button" onClick=${() => loadResults().catch(toastError)}>Refresh</button>
      <span class="muted small">${results.length} result${results.length === 1 ? '' : 's'} · kept per connection with a cap</span>
    </div>
    ${!state.resultsLoaded ? html`<${Skeleton} rows=${4} />` : null}
    ${state.resultsLoaded && results.length === 0 ? html`<${Empty} icon="◎" title="No results match"
      text=${kindFilter === 'speed'
        ? 'No speed result matches this filter. A speed run needs a registered target and a recent HTTPS measurement for the connection; the exit does not have to be proven.'
        : 'Run a relay test first. Results are stored on the gateway, so they survive a panel reload.'}
      action=${html`<button class="btn primary small" type="button" onClick=${() => navigate('tests', 'run')}>Run a test</button>`} />` : null}
    ${results.length ? html`<div class="clist">
      ${results.map((result) => {
        const key = `${result.connection_id}:${result.kind}:${result.tested_at}`;
        const open = expanded === key;
        return html`<div class="stack" key=${key} style="gap:6px">
          <div class="crow" role="button" tabindex="0" onClick=${() => setExpanded(open ? '' : key)}
              onKeyDown=${(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setExpanded(open ? '' : key); } }}>
            <div class="avatar">${result.kind === 'speed' ? 'SPD' : 'RT'}<span class="p">${result.protocol || ''}</span></div>
            <div class="c-main">
              <div class="c-name">${result.remark || result.connection_id}</div>
              <div class="c-sub">${evidenceOf(result) || '—'}${['ok', 'measured'].includes(result.status) ? '' : ` · ${timeAgo(result.tested_at)}`}</div>
            </div>
            <div class="c-end"><${ResultChip} result=${result} evidence=${false} /></div>
          </div>
          ${open ? html`<div class="evidence-box">
            <div class="row"><strong class="grow">${result.kind === 'speed' ? 'Download speed' : 'Relay and latency'}</strong>
              <${ResultChip} result=${result} /></div>
            ${result.status !== 'ok' ? html`<div>${result.detail || reasonText(result.reason) || 'No usable evidence.'}</div>` : null}
            <${KV} rows=${[
              ['Connection id', result.connection_id],
              ['Connectivity', connectivityOf(result).text],
              ['Evidence', result.status === 'ok' && verifiedResult(result) ? 'verified path (L1+L2)' : result.status === 'measured' ? 'operational measurement · exit ownership unproven' : 'no verified proof'],
              ['Path', pathKind(result) || 'no proof recorded'],
              ['Fast delay', delayMS(result) ? `${delayMS(result)} ms` : '—'],
              result.kind === 'speed' ? ['Throughput', throughputText(result) || '—'] : ['HTTPS median / p90', `${fmtLatency(result.p50_ms || result.latency_ms)} / ${fmtLatency(result.p90_ms)}`],
              result.kind === 'speed' ? ['Sample', downloadedText(result) || '—'] : null,
              result.kind === 'speed' ? ['Target', result.target || '—'] : null,
              result.kind === 'speed' ? ['Counted bytes', result.bytes ? `${result.bytes} B` : '—'] : null,
              ['Exit before', result.path && result.path.exit_ip_before],
              ['Exit after', result.path && result.path.exit_ip_after],
              ['Uplink address', result.path && result.path.uplink_ip],
              ['Serving exit', result.path && result.path.serving_exit_ip],
              ['Policy revision', result.path && result.path.policy_revision],
              ['Negative control', result.path && result.path.negative_control],
              ['Note', result.path && result.path.note],
            ]} />
            ${result.path && (result.path.echoes || []).length ? html`<div class="small muted">
              Echoes: ${result.path.echoes.map((echo) => `${echo.service} → ${echo.ip}`).join(' · ')}
            </div>` : null}
          </div>` : null}
        </div>`;
      })}
    </div>` : null}
    <p class="footnote">A result older than 24 hours is shown as stale. Stale results still inform history but are not used for ranking by default.</p>
  </div>`;
}

function ComparePanel({ state }) {
  const [kind, setKind] = useState('latency');
  const results = invalidateSupersededResults(state.results);
  const latest = new Map();
  for (const result of results) {
    if (result.kind !== kind) continue;
    const current = latest.get(result.connection_id);
    if (!current || Date.parse(result.tested_at) >= Date.parse(current.tested_at)) latest.set(result.connection_id, result);
  }
  const all = Array.from(latest.values());
  const byValue = (a, b) => kind === 'speed'
    ? (b.mbps || -1) - (a.mbps || -1)
    : ((delayMS(a) || Number.POSITIVE_INFINITY) - (delayMS(b) || Number.POSITIVE_INFINITY));
  const proven = all.filter(verifiedResult).sort(byValue);
  const operational = all
    .filter((result) => !verifiedResult(result) && result.status === 'measured' && !result.superseded && !result.stale)
    .sort(byValue);
  const rest = all.filter((result) => !proven.includes(result) && !operational.includes(result));

  const rankRows = (list, badge) => html`<div class="rank">
    ${list.map((result, index) => html`<div class=${`rk ${index === 0 ? 'best' : ''}`} key=${result.connection_id}>
      <div class="pos">${index + 1}</div>
      <div class="grow">
        <div class="rk-name">${result.remark || result.connection_id}${index === 0 ? html`<span class=${`badge ${badge.cls}`}>${badge.label}</span>` : null}</div>
        <div class="rk-facts">${result.protocol ? result.protocol.toUpperCase() : ''}${result.engine ? ` · ${result.engine}` : ''} · ${pathKind(result) || 'no proof recorded'} · ${connectivityOf(result).text} · ${timeAgo(result.tested_at)}</div>
      </div>
      <div class="rk-nums">
        ${kind === 'speed'
          ? html`<div><div class="v">${result.mbps ? result.mbps.toFixed(1) : '—'}</div><div class="k">Mbps</div></div>
              <div><div class="v">${mbPerSec(result) ? mbPerSec(result).toFixed(2) : '—'}</div><div class="k">MB/s</div></div>`
          : html`<div><div class="v">${fmtLatency(delayMS(result))}</div><div class="k">delay</div></div>
              <div><div class="v">${fmtLatency(result.p90_ms)}</div><div class="k">https p90</div></div>`}
        <div><div class="v"><${ResultChip} result=${result} /></div><div class="k">evidence</div></div>
      </div>
    </div>`)}
  </div>`;

  return html`<div class="panel">
    <div class="toolbar">
      <select aria-label="Compare by" value=${kind} onChange=${(e) => setKind(e.target.value)}>
        <option value="latency">Relay latency</option>
        <option value="speed">Download speed</option>
      </select>
      <span class="muted small">${proven.length} verified · ${operational.length} measured (exit unproven) · ${rest.length} not ranked</span>
    </div>
    ${all.length === 0 ? html`<${Empty} icon="◎" title="Nothing to compare yet"
      text=${kind === 'speed' ? 'A speed run needs a recent HTTPS measurement and a registered target; the exit does not have to be proven.' : 'Run a relay test across the connections you care about.'}
      action=${html`<button class="btn primary small" type="button" onClick=${() => navigate('tests', 'run')}>Run a test</button>`} />` : null}
    ${proven.length ? html`<div class="stack" style="gap:8px">
      <h3>Verified · ranked as a proven path</h3>
      ${rankRows(proven, { label: 'fastest proven', cls: 'ok' })}
    </div>` : null}
    ${operational.length ? html`<div class="stack" style="margin-top:12px; gap:8px">
      <h3>Measured · operational (exit unproven)</h3>
      <p class="muted small">These numbers came from real HTTPS traffic through the tested connection. They are usable for choosing a connection, but the exit ownership was not independently proven.</p>
      ${rankRows(operational, { label: 'fastest measured', cls: 'info' })}
    </div>` : null}
    ${rest.length ? html`<div class="stack" style="margin-top:12px">
      <h3>Not ranked</h3>
      <p class="muted small">These results are shown for honesty, not for selection. An inconclusive result does not mean the connection is bad; it means no real HTTPS measurement was recorded through it.</p>
      <div class="clist">
        ${rest.map((result) => html`<div class="crow" key=${result.connection_id}>
          <div class="avatar">${result.kind === 'speed' ? 'SPD' : 'RT'}</div>
          <div class="c-main">
            <div class="c-name">${result.remark || result.connection_id}</div>
            <div class="c-sub">${evidenceOf(result) || reasonText(result.reason)}</div>
          </div>
          <div class="c-end"><${ResultChip} result=${result} /></div>
        </div>`)}
      </div>
    </div>` : null}
    ${kind === 'speed' ? html`<div style="margin-top:12px"><${ByteNote} /></div>` : null}
  </div>`;
}

function TargetsPanel({ state }) {
  const targets = state.targets || [];
  const usage = state.usage;
  useEffect(() => {
    loadUsage().catch(() => {});
    loadTargets().catch(() => {});
  }, []);
  const [busy, setBusy] = useState('');
  const validate = async (target) => {
    setBusy(target.id);
    try {
      const checked = await validateSpeedTarget(target.id);
      if (checked && checked.last_status) toast(`${checked.host} was not accepted: ${checked.last_status}`, 'warn', 9000);
      else toast(`Target ${target.host} checked${checked && checked.last_route ? ` · ${checked.last_route}` : ''}.`, 'success');
    } catch (err) {
      toastError(err);
    } finally {
      setBusy('');
    }
  };
  const usedMB = usage ? Math.round((usage.bytes || 0) / (1024 * 1024)) : 0;
  return html`<div class="view-head">
    <div>
      <h2>Download targets</h2>
      <div class="sub">Speed tests download from the first registered target. Only public https addresses on port 443 are accepted; redirects and private addresses are refused at run time.</div>
    </div>
    <div class="view-actions">
      <button class="btn primary" type="button" onClick=${() => store.set({ dialog: html`<${TargetAddDialog}
        onClose=${() => { store.set({ dialog: null }); loadTargets().catch(() => {}); }} />` })}>Add target</button>
      <button class="btn ghost" type="button" onClick=${() => store.set({ dialog: html`<${BudgetDialog}
        request=${{ kind: 'speed', scope: { kind: 'all' } }} onClose=${() => store.set({ dialog: null })}
        onStart=${() => startTestJob({ kind: 'speed', scope: { kind: 'all' } })} />` })}>Check speed budget</button>
    </div>
  </div>
  <div class="panel table-wrap">
    <table class="data">
      <thead><tr><th>Target</th><th>Path</th><th>Checked</th><th>Route</th><th>Range</th><th>Actions</th></tr></thead>
      <tbody>
        ${targets.map((target) => html`<tr key=${target.id}>
          <td><strong>${target.host}</strong>${target.built_in ? html` <span class="badge">built-in</span>` : null}
            <div class="small muted mono">${target.url}</div></td>
          <td class="small mono">${target.path || '—'}</td>
          <td class="small"><${RelTime} iso=${target.last_checked_at || target.validated_at} /></td>
          <td>${target.last_route
            ? html`<span class=${`route-outcome ${target.last_route.toLowerCase() === 'direct' ? 'direct' : 'proxy'}`}>${target.last_route}</span>`
            : target.last_status
              ? html`<span class="notice bad small" title=${target.last_status}>rejected</span>`
              : html`<span class="muted small">not checked</span>`}</td>
          <td class="small">${target.supports_range ? 'range' : 'whole file'}</td>
          <td><div class="actions nowrap">
            <button class="btn ghost small" type="button" disabled=${busy === target.id} onClick=${() => validate(target)}>${busy === target.id ? 'Checking…' : 'Check'}</button>
            ${target.built_in ? null : html`<button class="btn danger small" type="button" onClick=${() => store.set({ dialog: html`<${TargetDeleteDialog}
              target=${target} onClose=${() => { store.set({ dialog: null }); loadTargets().catch(() => {}); }} />` })}>Delete</button>`}
          </div></td>
        </tr>`)}
      </tbody>
    </table>
    ${targets.length === 0 ? html`<${Empty} icon="⇣" title="No targets registered"
      text="A speed test needs one public https target. Add a host you control or trust; the DNS answer is checked before every run."
      action=${html`<button class="btn primary small" type="button" onClick=${() => store.set({ dialog: html`<${TargetAddDialog}
        onClose=${() => { store.set({ dialog: null }); loadTargets().catch(() => {}); }} />` })}>Add target</button>`} />` : null}
  </div>
  <div class="panel">
    <h2>Counted traffic</h2>
    <div class="grid3">
      <div><div class="cap">This month</div><div class="value mono">${fmtMB(usage ? usage.bytes : 0)}</div></div>
      <div><div class="cap">Monthly cap</div><div class="value mono">${usage && usage.monthly_cap_mb ? `${usage.monthly_cap_mb} MB` : 'not set'}</div></div>
      <div><div class="cap">Used</div><div class="value mono">${usage && usage.monthly_cap_mb ? `${usedMB} MB` : '—'}</div></div>
    </div>
    <p class="muted">${usage && usage.label ? usage.label : 'Payload bytes Bypath counted while downloading. This is not the provider\'s billing figure.'}</p>
    <${ByteNote} />
  </div>`;
}
