// Routing: what happens to traffic and why. The explanation comes from the same
// ordered plan the tunnel runs; editing is draft → preview → apply, never a
// single unverified write.

import { html, Banner, Empty, Skeleton, KV, Footnote } from '../ui.js';
import { useState, useEffect } from '../../vendor/hooks.module.js';
import { api } from '../api.js';
import { toast, toastError, store } from '../store.js';
import { refreshStatus, loadConnections } from '../data.js';
import { fmtLatency } from '../format.js';
import { ConfirmDialog } from '../dialogs.js';

const EMPTY_EDIT = { force: [], direct: [] };

const OUTBOUNDS = [
  { value: 'proxy', label: 'Through the tunnel' },
  { value: 'direct', label: 'Direct' },
  { value: 'block', label: 'Block' },
];

function cloneEdit(edit) {
  return {
    force: ((edit && edit.force) || []).map((rule) => ({ match: rule.match, outbound: rule.outbound || 'proxy' })),
    direct: ((edit && edit.direct) || []).map((rule) => ({ match: rule.match, outbound: rule.outbound || 'direct' })),
  };
}

function editKey(edit) {
  return JSON.stringify({ force: edit.force, direct: edit.direct });
}

export default function RoutingView({ state }) {
  const [overview, setOverview] = useState(null);
  const [error, setError] = useState('');
  const [filter, setFilter] = useState('');
  const [draft, setDraft] = useState(cloneEdit(EMPTY_EDIT));
  const [preview, setPreview] = useState(null);
  const [previewKey, setPreviewKey] = useState('');
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState('');

  const load = async () => {
    try {
      const value = await api.get('/routing');
      setOverview(value);
      setDraft(cloneEdit(value.edit));
      setPreview(null);
      setError('');
    } catch (err) {
      setError(err.message);
    }
  };

  useEffect(() => { load(); }, []);

  const canEdit = !!(overview && overview.can_edit);
  const dirty = !overview || editKey(draft) !== editKey(cloneEdit(overview.edit));
  const previewMatches = preview && previewKey === editKey(draft);

  const addRule = (list) => {
    setDraft((current) => ({
      ...current,
      [list]: [...current[list], { match: '', outbound: list === 'force' ? 'proxy' : 'direct' }],
    }));
    setPreview(null);
  };
  const updateRule = (list, index, patch) => {
    setDraft((current) => ({
      ...current,
      [list]: current[list].map((rule, i) => (i === index ? { ...rule, ...patch } : rule)),
    }));
    setPreview(null);
  };
  const removeRule = (list, index) => {
    setDraft((current) => ({ ...current, [list]: current[list].filter((rule, i) => i !== index) }));
    setPreview(null);
  };

  const runPreview = async () => {
    setBusy('preview');
    try {
      const clean = {
        force: draft.force.filter((rule) => rule.match.trim()),
        direct: draft.direct.filter((rule) => rule.match.trim()),
      };
      const value = await api.post('/routing/preview', { edit: clean });
      setPreview(value);
      setPreviewKey(editKey(clean));
      toast('Preview composed. Nothing has been applied.', 'info');
    } catch (err) {
      toastError(err);
    } finally {
      setBusy('');
    }
  };

  const apply = async () => {
    if (!preview || !previewMatches) {
      toast('Preview the current draft before applying it.', 'warn');
      return;
    }
    setBusy('apply');
    try {
      const change = await api.post('/routing/apply', {
        edit: preview.edit,
        revision: preview.revision,
        note: note.trim(),
        confirmed: true,
      });
      toast(change.message || 'Routing policy applied.', change.restart_required ? 'warn' : 'success', 9000);
      setNote('');
      await Promise.allSettled([load(), refreshStatus(), loadConnections()]);
    } catch (err) {
      toastError(err);
    } finally {
      setBusy('');
    }
  };

  const useProfile = (profile) => {
    if (!profile.edit) return;
    setDraft(cloneEdit(profile.edit));
    setPreview(null);
    toast(`Draft loaded from “${profile.name}”. Review and preview it before applying.`, 'info', 7000);
  };

  const applyRestore = async (snapshot) => {
    setBusy(snapshot.id);
    try {
      const change = await api.post('/routing/rollback', { snapshot: snapshot.id, confirmed: true });
      toast(change.message || 'Policy restored.', change.restart_required ? 'warn' : 'success', 9000);
      await Promise.allSettled([load(), refreshStatus()]);
    } catch (err) {
      toastError(err);
    } finally {
      setBusy('');
    }
  };

  const restore = (snapshot) => {
    store.set({ dialog: html`<${ConfirmDialog} title="Restore routing policy"
      text=${`Restore the policy saved at ${snapshot.created}? The current policy is saved as a new rollback point before it is replaced, so this stays reversible.`}
      confirmLabel="Restore policy"
      onClose=${() => store.set({ dialog: null })}
      onConfirm=${() => { store.set({ dialog: null }); applyRestore(snapshot); }} />` });
  };

  if (error) {
    return html`<div class="view-head"><div><h1>Routing</h1></div></div>
      <${Banner} kind="bad" title="Routing could not be read" text=${error}
        actions=${html`<button class="btn ghost small" type="button" onClick=${load}>Retry</button>`} />`;
  }
  if (!overview) {
    return html`<div class="view-head"><div><h1>Routing</h1></div></div><${Skeleton} rows=${5} />`;
  }

  const filteredRules = (overview.rules || []).filter((rule) => {
    if (!filter) return true;
    return [rule.effect, rule.match, rule.source, rule.note, rule.scope]
      .filter(Boolean).join(' ').toLowerCase().includes(filter.toLowerCase());
  });

  return html`<div class="view-head">
    <div>
      <h1>Routing</h1>
      <div class="sub">What happens to traffic from devices on this network, and why. The answers below are evaluated by the same ordered rules the tunnel runs.</div>
    </div>
    <div class="view-actions">
      <button class="btn ghost small" type="button" onClick=${load}>Refresh</button>
    </div>
  </div>

  <div class="cards">
    <div class="tile"><div class="label">Mode</div><div class="value">${overview.mode === 'rules' ? 'Rules' : 'Legacy whitelist'}</div><div class="sub">${overview.engine || 'engine unknown'}</div></div>
    <div class="tile"><div class="label">Default</div><div class="value">${String(overview.default_outbound || '—').toUpperCase()}</div><div class="sub">everything not matched above</div></div>
    <div class="tile"><div class="label">DNS</div><div class="value">${overview.dns_mode || '—'}</div><div class="sub">${overview.gateway_connected ? 'gateway connected' : 'gateway not connected'}</div></div>
    <div class="tile"><div class="label">Revision</div><div class="value mono small">${overview.revision || '—'}</div><div class="sub">${(overview.rules || []).length} effective rules</div></div>
  </div>

  ${(overview.warnings || []).length ? html`<${Banner} kind="warn" title="Attention">
    <ul class="bullets">${overview.warnings.map((warning) => html`<li key=${warning}>${warning}</li>`)}</ul>
  <//>` : null}

  <div class="panel">
    <h2>Where does a site go?</h2>
    <p class="muted">Type a domain or an IP address. The answer comes from the same rules the tunnel runs, not from a copy.</p>
    <${ExplainTool} status=${state.status} />
  </div>

  <div class="panel">
    <h2>Public addresses</h2>
    <p class="muted">The tunnel exit is the address websites see for devices on this network. The second row is this gateway process.</p>
    <${EgressTool} />
  </div>

  <div class="panel">
    <h2>Effective rules</h2>
    <p class="muted">Checked from top to bottom. For a named site the domain rules are checked first; IP rules are checked after the name is resolved.</p>
    <div class="toolbar">
      <input type="search" placeholder="Filter by rule, source or effect" aria-label="Filter effective rules"
        value=${filter} onInput=${(e) => setFilter(e.target.value)} />
    </div>
    ${filteredRules.length === 0
      ? html`<p class="empty">No rule matches this filter.</p>`
      : html`<div class="table-wrap"><table class="data">
          <thead><tr><th class="num">#</th><th>Effect</th><th>What it matches</th><th>Source</th><th>Note</th></tr></thead>
          <tbody>${filteredRules.map((rule) => html`<tr key=${rule.position}>
            <td class="num">${rule.position}</td>
            <td><span class=${`route-outcome ${rule.effect === 'direct' ? 'direct' : rule.effect === 'block' || rule.effect === 'deny' ? 'block' : 'proxy'}`}>${String(rule.effect || '').toUpperCase()}</span></td>
            <td>${rule.match}${rule.skipped ? html` <span class="badge warn">skipped</span>` : null}</td>
            <td class="small muted">${rule.source || rule.scope || '—'}</td>
            <td class="small muted">${rule.note || '—'}</td>
          </tr>`)}</tbody>
        </table></div>`}
    <p class="footnote">The order is fixed: built-in safety rules, local DNS, legacy directives, then your exceptions, then the default. Editing an exception never changes the rule order or the default outbound.</p>
  </div>

  <div class="panel">
    <h2>Exceptions <span class="hint">draft · preview · apply</span></h2>
    <p class="muted">Send a specific site or address range through the tunnel, direct, or block it. Nothing changes until you preview and apply.</p>
    ${!canEdit ? html`<p class="notice">${overview.can_edit_reason || 'This policy cannot be edited from the panel right now.'}</p>` : null}
    <div class="grid2">
      ${RuleGroup({ title: 'Always through the tunnel', hint: 'wins over geo directives and the default', list: 'force', rules: draft.force, outboundDefault: 'proxy', canEdit, updateRule, removeRule })}
      ${RuleGroup({ title: 'Always direct', hint: 'wins over the default, not over built-in safety rules', list: 'direct', rules: draft.direct, outboundDefault: 'direct', canEdit, updateRule, removeRule })}
    </div>
    ${canEdit ? html`<div class="actions">
      <button class="btn ghost small" type="button" onClick=${() => addRule('force')}>Add tunnel rule</button>
      <button class="btn ghost small" type="button" onClick=${() => addRule('direct')}>Add direct rule</button>
      <button class="btn primary" type="button" disabled=${busy === 'preview'} onClick=${runPreview}>${busy === 'preview' ? 'Previewing…' : 'Preview change'}</button>
      <button class="btn primary" type="button" disabled=${!previewMatches || busy === 'apply'} onClick=${apply}>${busy === 'apply' ? 'Applying…' : 'Apply preview'}</button>
      <button class="btn ghost" type="button" disabled=${!dirty} onClick=${() => { setDraft(cloneEdit(overview.edit)); setPreview(null); }}>Reset draft</button>
      ${dirty ? html`<span class="badge warn">unsaved draft</span>` : null}
    </div>` : null}
    ${preview ? html`<div class="evidence-box" style="margin-top:12px">
      <div class="row"><strong class="grow">Preview · revision ${preview.revision}</strong>
        <span class="badge accent">${preview.default_outbound ? preview.default_outbound.toUpperCase() : ''} default</span></div>
      ${(preview.summary || []).length ? html`<ul class="bullets">${preview.summary.map((line) => html`<li key=${line}>${line}</li>`)}</ul>` : html`<p class="muted small">No change summary was produced.</p>`}
      ${(preview.warnings || []).length ? html`<ul class="bullets">${preview.warnings.map((line) => html`<li key=${line} class="small">${line}</li>`)}</ul>` : null}
      <label>Note for the rollback point
        <input type="text" value=${note} onInput=${(e) => setNote(e.target.value)} placeholder="Why are you changing this?" maxlength="200" />
      </label>
      <p class="small muted">${previewMatches ? 'This preview matches the current draft and can be applied.' : 'The draft changed after this preview. Preview again before applying.'}</p>
    </div>` : null}
  </div>

  <div class="panel">
    <h2>Compatibility profiles</h2>
    <p class="muted">Optional named behaviours. A profile only edits the exception list above; the rule order and default outbound always stay in place.</p>
    ${(overview.profiles || []).length === 0 ? html`<p class="empty">No profiles are available on this gateway.</p>` : html`<div class="grid2">
      ${overview.profiles.map((profile) => html`<div class="profile-card" key=${profile.id}>
        <h3>${profile.name}
          <span class=${`badge ${profile.status === 'active' ? 'ok' : profile.status === 'review' ? 'inc' : ''}`}>${profile.status}</span>
          ${profile.verified ? html`<span class="evidence">${profile.verified}</span>` : null}</h3>
        <div class="small muted">${profile.description}</div>
        ${(profile.warnings || []).length ? html`<ul class="bullets small">${profile.warnings.map((warning) => html`<li key=${warning}>${warning}</li>`)}</ul>` : null}
        <div class="actions">
          <button class="btn ghost small" type="button" disabled=${!canEdit || !profile.edit} onClick=${() => useProfile(profile)}>Load into draft</button>
        </div>
      </div>`)}
    </div>`}
  </div>

  <div class="panel">
    <h2>Rollback points</h2>
    <p class="muted">Every apply saves the previous policy first. Restoring one is itself reversible.</p>
    ${(overview.snapshots || []).length === 0 ? html`<p class="empty">No rollback points yet.</p>` : (overview.snapshots || []).map((snapshot) => html`
      <div class="snapshot-row" key=${snapshot.id}>
        <div class="grow">
          <div><strong>${snapshot.note || 'Routing change'}</strong></div>
          <div class="when">${snapshot.created} · ${snapshot.rules} rules</div>
        </div>
        <button class="btn ghost small" type="button" disabled=${!canEdit || busy === snapshot.id} onClick=${() => restore(snapshot)}>${busy === snapshot.id ? 'Restoring…' : 'Restore'}</button>
      </div>`)}
  </div>

  <div class="panel">
    <h2>Advanced details</h2>
    <p class="muted">Read-only information for troubleshooting. These values come from the running configuration.</p>
    <${KV} rows=${[
      ['Policy mode', overview.mode],
      ['Engine', overview.engine || '—'],
      ['Default outbound', overview.default_outbound],
      ['DNS mode', overview.dns_mode],
      ['GeoIP database', (overview.assets || {}).geoip_present ? overview.assets.geoip_path : 'not installed'],
      ['GeoSite database', (overview.assets || {}).geosite_present ? overview.assets.geosite_path : 'not installed'],
      ['Gateway connected', overview.gateway_connected ? 'yes' : 'no'],
      ['Editable', overview.can_edit ? 'yes' : overview.can_edit_reason || 'no'],
      ['Legacy whitelist', (overview.legacy || {}).present ? (overview.legacy.ignored ? 'present, ignored' : 'present, in use') : 'not present'],
      ['Local DNS groups', String((overview.local_dns || []).length)],
    ]} />
    ${(overview.local_dns || []).length ? html`<${KV} rows=${overview.local_dns.map((entry) => [entry.server, (entry.domains || []).join(', ')])} />` : null}
  </div>`;
}

function RuleGroup({ title, hint, list, rules, outboundDefault, canEdit, updateRule, removeRule }) {
  return html`<div class="rule-group">
    <strong>${title}</strong>
    <div class="small muted">${hint}</div>
    <div class="rule-rows">
      ${rules.length === 0 ? html`<div class="rule-empty">No exceptions in this list.</div>` : rules.map((rule, index) => html`
        <div class="rule-row" key=${`${list}:${index}`}>
          <input type="text" value=${rule.match} placeholder="domain:example.com"
            disabled=${!canEdit} onInput=${(e) => updateRule(list, index, { match: e.target.value })} class="grow" />
          <select value=${rule.outbound} disabled=${!canEdit} onChange=${(e) => updateRule(list, index, { outbound: e.target.value })}>
            ${OUTBOUNDS.map((option) => html`<option key=${option.value} value=${option.value}>${option.label}</option>`)}
          </select>
          <button class="btn ghost small" type="button" disabled=${!canEdit} aria-label="Remove rule"
            onClick=${() => removeRule(list, index)}>Remove</button>
        </div>`)}
    </div>
    <div class="small muted">Rules need an explicit type: <code>domain:example.com</code>, <code>domain_suffix:example.com</code> or <code>ip_cidr:203.0.113.0/24</code>. Default for a new rule: ${outboundDefault === 'proxy' ? 'through the tunnel' : 'direct'}.</div>
  </div>`;
}

function ExplainTool({ status }) {
  const [target, setTarget] = useState('');
  const [port, setPort] = useState('443');
  const [explanation, setExplanation] = useState(null);
  const [test, setTest] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState('');

  const explain = async () => {
    if (!target.trim()) { toast('Enter a domain or an IP address.', 'warn'); return; }
    setBusy('explain');
    setError('');
    setTest(null);
    try {
      setExplanation(await api.get(`/routing/explain?target=${encodeURIComponent(target.trim())}`));
    } catch (err) {
      setError(err.message);
      setExplanation(null);
    } finally {
      setBusy('');
    }
  };

  const runTest = async () => {
    if (!target.trim()) { toast('Enter a domain or an IP address.', 'warn'); return; }
    setBusy('test');
    setError('');
    try {
      setTest(await api.post('/routing/test', { target: target.trim(), port: Number(port) || 443 }));
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy('');
    }
  };

  const outcome = explanation && explanation.outcome;
  const outcomeClass = outcome === 'DIRECT' ? 'direct' : outcome === 'BLOCK' ? 'block' : 'proxy';
  const verdictKind = test && ['reachable', 'tcp_connected'].includes(test.verdict) ? 'ok'
    : test && test.verdict === 'blocked_by_rule' ? 'warn' : 'bad';

  return html`<div class="stack">
    <div class="toolbar">
      <input type="search" placeholder="example.com or 203.0.113.10" aria-label="Domain or IP address to explain"
        value=${target} onInput=${(e) => setTarget(e.target.value)} style="flex:1 1 260px" />
      <input type="number" min="1" max="65535" value=${port} aria-label="Port"
        onInput=${(e) => setPort(e.target.value)} style="width:90px" />
      <button class="btn primary" type="button" disabled=${busy === 'explain'} onClick=${explain}>${busy === 'explain' ? 'Explaining…' : 'Explain'}</button>
      <button class="btn ghost" type="button" disabled=${busy === 'test' || !status || !status.running} onClick=${runTest}>${busy === 'test' ? 'Testing…' : 'Test connection'}</button>
    </div>
    ${status && !status.running ? html`<p class="muted small">The gateway is not running; testing a connection is unavailable. Explanation still works.</p>` : null}
    ${error ? html`<p class="notice bad">${error}</p>` : null}
    ${explanation ? html`<div class="evidence-box">
      <div class="row">
        <span class=${`route-outcome ${outcomeClass}`}>${outcome || 'UNKNOWN'}</span>
        <strong class="grow">${explanation.target}</strong>
        ${explanation.certain ? html`<span class="badge ok">certain</span>` : html`<span class="badge warn">depends on the resolved address</span>`}
      </div>
      <div>${explanation.summary}</div>
      ${explanation.decided_by ? html`<div class="small muted">Decided by rule ${explanation.decided_by.position}: ${explanation.decided_by.match} → ${explanation.decided_by.effect}</div>` : null}
      ${(explanation.addresses || []).length ? html`<div class="small muted mono">Resolved: ${explanation.addresses.join(', ')}</div>` : null}
      <div class="small muted">DNS: ${explanation.dns} · default ${explanation.default_outbound}</div>
      ${(explanation.warnings || []).length ? html`<ul class="bullets small">${explanation.warnings.map((warning) => html`<li key=${warning}>${warning}</li>`)}</ul>` : null}
      ${(explanation.steps || []).length ? html`<ol class="route-steps">
        ${explanation.steps.map((step, index) => html`<li key=${`${index}:${step.label}`}>
          <span class="pos">${step.position || ''}</span>
          <span>${step.label} ${step.routed || ''}<span class="detail">${step.verdict}${step.detail ? ` · ${step.detail}` : ''}</span></span>
        </li>`)}
      </ol>` : null}
    </div>` : null}
    ${test ? html`<div class="evidence-box">
      <div class="row"><strong class="grow">Connection test · port ${test.port}</strong>
        <span class=${`route-verdict ${verdictKind}`}>${test.verdict}</span></div>
      <div>${test.verdict_text}</div>
      <div class="small muted">${test.latency_ms ? `${fmtLatency(test.latency_ms)} · ` : ''}${test.http_status ? `HTTP ${test.http_status}` : 'no HTTP status'} · tested just now</div>
      ${test.detail ? html`<div class="small muted">${test.detail}</div>` : null}
    </div>` : null}
  </div>`;
}

function EgressTool() {
  const [check, setCheck] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const run = async () => {
    setBusy(true);
    setError('');
    try {
      setCheck(await api.post('/routing/egress'));
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };
  return html`<div class="stack">
    <div class="actions">
      <button class="btn ghost" type="button" disabled=${busy} onClick=${run}>${busy ? 'Checking…' : 'Check addresses'}</button>
    </div>
    ${error ? html`<p class="notice bad">${error}</p>` : null}
    ${check ? html`<${KV} rows=${[
      ['Tunnel exit', check.tunnel_exit || check.tunnel_error || 'unavailable'],
      ['Gateway public address', check.direct_ip || check.direct_error || 'unavailable'],
      ['Same address', check.same ? 'yes — traffic may be leaving directly' : 'no'],
      ['Country', check.country],
      ['Colo', check.colo],
      ['Note', check.note],
    ]} />` : null}
  </div>`;
}
