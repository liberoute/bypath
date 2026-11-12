// Tests: relay and latency first, download speed only on proven connections.
// Every result shown here carries the proof that produced it; nothing is
// ranked without L1+L2.

import { html, Chip, Banner, Empty, Skeleton, Tabs, Progress, KV, Footnote, ByteNote, ResultChip, RelTime } from '../ui.js';
import { useState, useEffect } from '../../vendor/hooks.module.js';
import { store, toast, toastError } from '../store.js';
import { navigate } from '../nav.js';
import {
  loadResults, loadTargets, loadUsage, startTestJob, cancelTestJob,
  validateSpeedTarget, deleteSpeedTarget,
} from '../data.js';
import {
  connectionName, evidenceOf, verdictOf, reasonText, pathKind, fmtLatency, fmtMB, timeAgo,
  verifiedResult, invalidateSupersededResults,
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
      <div class="sub">A test proves what a connection does. Relay and latency results carry the path evidence; a speed result is only produced for a connection that already has one.</div>
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
      ? 'Speed runs are serial, one connection at a time, and are capped per connection and per batch. Upload testing is not available in this release.'
      : 'Relay tests start an isolated test tunnel per connection and compare the observed exit with the uplink and the serving tunnel. A result without L1+L2 is reported as inconclusive, never as healthy.'}</p>

    ${job ? html`<div class="stack" style="margin-top:12px">
      <div class="row">
        <strong class="grow">${job.kind === 'speed' ? 'Speed job' : 'Relay job'} <span class="muted small mono">${job.id}</span></strong>
        <${Chip} state=${job.state === 'done' ? 'healthy' : job.state === 'failed' ? 'failed' : job.state === 'cancelled' ? 'cancelled' : 'testing'}
          label=${job.state === 'done' ? 'Done' : job.state === 'running' ? 'Running' : job.state} />
      </div>
      <${Progress} completed=${job.completed || 0} total=${job.total || 0} state=${job.state} />
      <div class="muted small">${job.stage ? `${job.stage} · ` : ''}${job.completed || 0} of ${job.total || 0}${job.error ? ` · ${job.error}` : ''}</div>
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
      <li><strong>L1 construction audit</strong>: the test engine configuration is checked before it starts; a shared or non-isolated configuration is refused.</li>
      <li><strong>L2 independent exit identity</strong>: two echo services must agree on the public address, and it must differ from the uplink and from the serving tunnel.</li>
      <li><strong>Route decisions</strong>: the target must be routed through the test tunnel; a DIRECT target invalidates the measurement.</li>
      <li><strong>Stability</strong>: the policy revision and the exit must not change during the measurement.</li>
      <li><strong>Negative control</strong>: the serving tunnel re-checks that DIRECT traffic is not silently absorbed by the tunnel.</li>
    </ul>
    <p class="footnote">An inconclusive result names the reason. It is never presented as a failure of the link, and it is never ranked.</p>
  </div>`;
}

function ResultsPanel({ state }) {
  const [connectionFilter, setConnectionFilter] = useState('');
  const [kindFilter, setKindFilter] = useState('');
  const [expanded, setExpanded] = useState('');
  const results = invalidateSupersededResults(state.results).filter((result) => {
    if (connectionFilter && result.connection_id !== connectionFilter) return false;
    if (kindFilter && result.kind !== kindFilter) return false;
    return true;
  }).slice().sort((a, b) => String(b.tested_at || '').localeCompare(String(a.tested_at || '')));
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
      <button class="btn ghost small" type="button" onClick=${() => loadResults().catch(toastError)}>Refresh</button>
      <span class="muted small">${results.length} result${results.length === 1 ? '' : 's'} · kept per connection with a cap</span>
    </div>
    ${!state.resultsLoaded ? html`<${Skeleton} rows=${4} />` : null}
    ${state.resultsLoaded && results.length === 0 ? html`<${Empty} icon="◎" title="No results match"
      text=${kindFilter === 'speed'
        ? 'No speed result matches this filter. Speed runs are bounded and only produce a result on a connection that already has a proven path.'
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
              <div class="c-sub">${evidenceOf(result) || '—'}${result.status === 'ok' ? '' : ` · ${timeAgo(result.tested_at)}`}</div>
            </div>
            <div class="c-end"><${ResultChip} result=${result} /></div>
          </div>
          ${open ? html`<div class="evidence-box">
            <div class="row"><strong class="grow">${result.kind === 'speed' ? 'Download speed' : 'Relay and latency'}</strong>
              <${ResultChip} result=${result} /></div>
            ${result.status !== 'ok' ? html`<div>${result.detail || reasonText(result.reason) || 'No usable evidence.'}</div>` : null}
            <${KV} rows=${[
              ['Connection id', result.connection_id],
              ['Path', pathKind(result) || 'no proof recorded'],
              result.kind === 'speed' ? ['Throughput', result.mbps ? `${result.mbps.toFixed(1)} Mbps` : '—'] : ['Median / p90', `${fmtLatency(result.p50_ms || result.latency_ms)} / ${fmtLatency(result.p90_ms)}`],
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
  const proven = all.filter(verifiedResult)
    .sort((a, b) => kind === 'speed'
      ? (b.mbps || 0) - (a.mbps || 0)
      : (a.p50_ms || a.latency_ms || Infinity) - (b.p50_ms || b.latency_ms || Infinity));
  const rest = all.filter((result) => !proven.includes(result));

  return html`<div class="panel">
    <div class="toolbar">
      <select aria-label="Compare by" value=${kind} onChange=${(e) => setKind(e.target.value)}>
        <option value="latency">Relay latency</option>
        <option value="speed">Download speed</option>
      </select>
      <span class="muted small">${proven.length} proven result${proven.length === 1 ? '' : 's'} ranked · ${rest.length} not ranked</span>
    </div>
    ${all.length === 0 ? html`<${Empty} icon="◎" title="Nothing to compare yet"
      text=${kind === 'speed' ? 'A speed result requires a proven relay result for the same connection.' : 'Run a relay test across the connections you care about.'}
      action=${html`<button class="btn primary small" type="button" onClick=${() => navigate('tests', 'run')}>Run a test</button>`} />` : null}
    ${proven.length ? html`<div class="rank">
      ${proven.map((result, index) => html`<div class=${`rk ${index === 0 ? 'best' : ''}`} key=${result.connection_id}>
        <div class="pos">${index + 1}</div>
        <div class="grow">
          <div class="rk-name">${result.remark || result.connection_id}${index === 0 ? html`<span class="badge ok">fastest proven</span>` : null}</div>
          <div class="rk-facts">${result.protocol ? result.protocol.toUpperCase() : ''}${result.engine ? ` · ${result.engine}` : ''} · ${pathKind(result)} · ${timeAgo(result.tested_at)}</div>
        </div>
        <div class="rk-nums">
          ${kind === 'speed'
            ? html`<div><div class="v">${result.mbps ? result.mbps.toFixed(1) : '—'}</div><div class="k">Mbps</div></div>`
            : html`<div><div class="v">${fmtLatency(result.p50_ms || result.latency_ms)}</div><div class="k">p50</div></div>
                <div><div class="v">${fmtLatency(result.p90_ms)}</div><div class="k">p90</div></div>`}
          <div><div class="v"><${ResultChip} result=${result} /></div><div class="k">evidence</div></div>
        </div>
      </div>`)}
    </div>` : null}
    ${rest.length ? html`<div class="stack" style="margin-top:12px">
      <h3>Not ranked</h3>
      <p class="muted small">These results are shown for honesty, not for selection. An inconclusive result does not mean the connection is bad; it means its path was not proven.</p>
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
