// Settings: the gateway's non-secret configuration, backup/restore, the admin
// password, diagnostics and a truthful account of what the next start does.

import { html, Banner, KV, Skeleton } from '../ui.js';
import { useState, useEffect } from '../../vendor/hooks.module.js';
import { request, web } from '../api.js';
import { store, toast, toastError } from '../store.js';
import {
  loadSettings, loadEngines, loadLogs, refreshStatus, loadConnections,
  restartTunnel,
} from '../data.js';
import { signOut, navigate } from '../nav.js';
import { ConfirmDialog, StopDaemonDialog } from '../dialogs.js';
import { fmtDate, fmtStateLabel } from '../format.js';
import { operationKey, pollOperation, proxyEndpoint, validateProxy, terminalOperation } from '../operations.js';

const closeDialog = () => store.set({ dialog: null });
const openDialog = (node) => store.set({ dialog: node });

export default function SettingsView({ state }) {
  const [form, setForm] = useState(null);
  const [original, setOriginal] = useState(null);
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [restoreFile, setRestoreFile] = useState(null);
  const [logs, setLogs] = useState(state.logs || []);
  const [logFilter, setLogFilter] = useState('');
  const [logLevel, setLogLevel] = useState('all');
  const [logsAt, setLogsAt] = useState('');
  const [proxy, setProxy] = useState(null);
  const [operation, setOperation] = useState(null);
  const [operationID, setOperationID] = useState(() => sessionStorage.getItem(operationKey) || '');

  useEffect(() => {
    if (state.settings && !proxy) setProxy({ socks_port: state.settings.socks_port, socks_listen: state.settings.socks_listen || '127.0.0.1' });
  }, [state.settings]);

  useEffect(() => {
    if (!operationID) return;
    let cancelled = false;
    pollOperation(
      () => request('GET', `/api/v1/app/service/operation?id=${encodeURIComponent(operationID)}`, { timeoutMs: 8000 }),
      (next) => { if (!cancelled) setOperation(next); },
      { cancelled: () => cancelled },
    ).then(async (result) => {
      if (cancelled || !result) return;
      if (terminalOperation(result.state)) {
        setBusy('');
        await loadSettings();
        const actual = store.get().settings;
        if (actual && !cancelled) setProxy({ socks_port: actual.socks_port, socks_listen: actual.socks_listen });
        await refreshStatus();
      }
    }).catch((err) => { if (!cancelled) { setBusy(''); setMessage(err.message); } });
    return () => { cancelled = true; };
  }, [operationID]);

  useEffect(() => {
    let live = true;
    Promise.allSettled([loadSettings(), loadEngines(), loadConnections()]).then(() => {
      if (!live) return;
      const settings = store.get().settings;
      if (settings) {
        setForm(toForm(settings));
        setOriginal(toForm(settings));
      }
    });
    return () => { live = false; };
  }, []);

  useEffect(() => {
    if (state.settings && !form) {
      setForm(toForm(state.settings));
      setOriginal(toForm(state.settings));
    }
  }, [state.settings]);

  const settings = state.settings || state.status || {};
  const status = state.status || {};
  const controlsBusy = busy === 'service'
    || (state.switchSheet && !['done', 'failed'].includes(state.switchSheet.phase))
    || (operationID && (!operation || !terminalOperation(operation.state)));

  const set = (key, value) => setForm((current) => ({ ...(current || {}), [key]: value }));

  const save = async () => {
    if (!form || !original) return;
    const patch = diffForm(original, form);
    if (!Object.keys(patch).length) {
      setMessage('No changes to save.');
      return;
    }
    setBusy('save');
    setMessage('');
    try {
      const change = await request('PATCH', '/api/v1/app/settings', { json: patch });
      setForm(toForm(change.settings));
      setOriginal(toForm(change.settings));
      setMessage(change.restart_required
        ? 'Saved. The change takes effect after the tunnel reconnects.'
        : 'Saved. No reconnect was required.');
      toast('Settings saved.', 'success');
      await Promise.allSettled([refreshStatus(), loadConnections()]);
    } catch (err) {
      toastError(err);
      setMessage(err.message);
    } finally {
      setBusy('');
    }
  };

  const supervised = async (path, payload) => {
    setBusy('service');
    setMessage('Submitting one supervised operation. Do not repeat it if the panel temporarily disappears.');
    try {
      const next = await request('POST', path, { json: payload });
      sessionStorage.setItem(operationKey, next.id);
      setOperation(next);
      setOperationID(next.id);
    } catch (err) {
      setBusy('');
      toastError(err);
      setMessage(err.code === 'network'
        ? 'The response was lost; the operation may have been accepted. Check gateway status before submitting another operation.'
        : err.message);
    }
  };

  const confirmServiceRestart = () => openDialog(html`<${ConfirmDialog}
    title="Restart Bypath Gateway service"
    text="This restarts Bypath, not the host. Connected clients will pause and this panel may become unavailable. A separate systemd supervisor verifies recovery and restores the previous configuration on failure. You will need to sign in again."
    confirmLabel="Restart Gateway service"
    onClose=${closeDialog}
    onConfirm=${() => { closeDialog(); supervised('/api/v1/app/service/restart', { confirm: true }); }} />`);

  const confirmProxy = () => {
    if (!proxy) return;
    const error = validateProxy(proxy.socks_port, proxy.socks_listen, settings);
    if (error) { setMessage(error); return; }
    const broad = proxy.socks_listen === '0.0.0.0';
    const lan = proxy.socks_listen !== '127.0.0.1';
    const oldEndpoint = proxyEndpoint(settings.socks_listen, settings.socks_port);
    const nextEndpoint = proxyEndpoint(proxy.socks_listen, proxy.socks_port);
    openDialog(html`<${ConfirmDialog} title="Apply proxy listener and restart Gateway"
      text=${`${oldEndpoint} → ${nextEndpoint}. Traffic pauses during a supervised service restart. ${lan ? `Only sources in the trusted allow-list (${settings.trusted_lan_cidr}) may reach the proxy; the owned firewall drops every other source and interface. ` : ''}${broad ? '0.0.0.0 alone does NOT restrict access to the LAN. This explicitly confirms a broad bind protected by the allow-list. ' : ''}Startup or tunneled HTTPS verification failure restores the previous listener. Web HTTPS and the internal API do not move. Sign in again after restart.`}
      confirmLabel=${broad ? 'Confirm all IPv4 interfaces and apply' : 'Apply and restart Gateway'}
      onClose=${closeDialog}
      onConfirm=${() => { closeDialog(); supervised('/api/v1/app/proxy/apply', { ...proxy, confirm_lan: lan, confirm_all: broad }); }} />`);
  };

  const downloadBackup = async () => {
    setBusy('backup');
    try {
      const backup = await request('GET', '/api/v1/app/backup');
      const blob = new Blob([JSON.stringify(backup, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
      anchor.href = url;
      anchor.download = `bypath-backup-${stamp}.json`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      setTimeout(() => URL.revokeObjectURL(url), 2000);
      toast(`Backup downloaded. ${(backup.excluded || []).length} secret categories excluded.`, 'success', 7000);
    } catch (err) {
      toastError(err);
    } finally {
      setBusy('');
    }
  };

  const chooseRestore = async (event) => {
    const file = event.target.files[0];
    if (!file) { setRestoreFile(null); return; }
    if (file.size > 1024 * 1024) {
      toast('That backup is larger than 1 MiB.', 'warn');
      event.target.value = '';
      return;
    }
    setRestoreFile({ name: file.name, text: await file.text() });
  };

  const applyRestore = async () => {
    setBusy('restore');
    try {
      await request('POST', '/api/v1/app/restore', { raw: restoreFile.text, contentType: 'application/json' });
      setRestoreFile(null);
      toast('Configuration restored. Reconnect the tunnel to apply runtime changes.', 'success', 9000);
      await refreshStatus();
    } catch (err) {
      toastError(err);
    } finally {
      setBusy('');
    }
  };

  const restore = () => {
    if (!restoreFile) { toast('Choose a backup file first.', 'warn'); return; }
    let parsed;
    try {
      parsed = JSON.parse(restoreFile.text);
    } catch {
      toast('That file is not valid backup JSON.', 'bad');
      return;
    }
    if (!parsed || parsed.version !== 1) { toast('That backup version is not supported.', 'bad'); return; }
    store.set({ dialog: html`<${ConfirmDialog} title="Restore this configuration"
      text=${`“${restoreFile.name}” replaces the current configuration. Runtime changes take effect when the tunnel reconnects.`}
      confirmLabel="Restore configuration"
      onClose=${closeDialog}
      onConfirm=${() => { closeDialog(); applyRestore(); }} />` });
  };

  const changePassword = async (event) => {
    event.preventDefault();
    const current = event.target.elements.current.value;
    const next = event.target.elements.next.value;
    const confirmValue = event.target.elements.confirm.value;
    if (next !== confirmValue) { toast('The new passwords do not match.', 'warn'); return; }
    setBusy('password');
    try {
      await web.password(current, next);
      event.target.reset();
      toast('Password changed.', 'success');
    } catch (err) {
      toastError(err);
    } finally {
      setBusy('');
    }
  };

  const logsNow = async () => {
    setBusy('logs');
    try {
      const list = await loadLogs(300);
      setLogs(list || []);
      setLogsAt(new Date().toISOString());
    } catch (err) {
      toastError(err);
    } finally {
      setBusy('');
    }
  };

  useEffect(() => { logsNow(); }, []);

  const downloadLogs = () => {
    const text = ((logs || []).filter(matchesLog)).map((entry) => `${entry.time} ${entry.level.toUpperCase()} ${entry.message}`).join('\n');
    const blob = new Blob([text || 'No matching log entries.'], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `bypath-logs-${new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)}.txt`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  };

  const matchesLog = (entry) => {
    if (logLevel !== 'all' && String(entry.level).toLowerCase() !== logLevel) return false;
    if (logFilter && !String(entry.message).toLowerCase().includes(logFilter.toLowerCase())) return false;
    return true;
  };
  const filteredLogs = (logs || []).filter(matchesLog);
  const importLists = Array.from(new Set((state.connections || []).map((connection) => connection.group).filter(Boolean))).sort();
  const selection = status.selection || {};

  return html`<div class="view-head">
    <div>
      <h1>Settings</h1>
      <div class="sub">Configuration is stored on this gateway. Changes here never edit a link, an import list or the saved next start.</div>
    </div>
    <div class="view-actions">
      <button class="btn primary" type="button" disabled=${busy === 'save'} onClick=${save}>${busy === 'save' ? 'Saving…' : 'Save changes'}</button>
    </div>
  </div>
  ${message ? html`<p class="notice info" role="status">${message}</p>` : null}

  ${!form ? html`<${Skeleton} rows=${6} />` : html`<form class="panel" onSubmit=${(e) => e.preventDefault()}>
    <h2>Gateway</h2>
    <div class="grid2">
      <label class="check"><input type="checkbox" checked=${!!form.gateway_mode} onChange=${(e) => set('gateway_mode', e.target.checked)} /> Transparent gateway mode</label>
      <label class="check"><input type="checkbox" checked=${!!form.native_tun} onChange=${(e) => set('native_tun', e.target.checked)} /> Native TUN (no tun2socks)</label>
      <label>LAN interface (empty = auto)
        <input type="text" value=${form.lan_interface || ''} placeholder="eth0" onInput=${(e) => set('lan_interface', e.target.value)} />
      </label>
      <label>DNS mode
        <select value=${form.dns_mode || 'strict'} onChange=${(e) => set('dns_mode', e.target.value)}>
          <option value="strict">strict (tunnel only, fail closed)</option>
          <option value="local">local (allow direct upstream)</option>
        </select>
      </label>
      <label>Preferred engine
        <select value=${form.preferred_engine || ''} onChange=${(e) => set('preferred_engine', e.target.value)}>
          <option value="">auto</option>
          <option value="sing-box">sing-box</option>
          <option value="xray">xray</option>
        </select>
      </label>
    </div>
    <label>DNS upstream servers (one per line)
      <textarea rows="3" value=${(form.dns_upstream || []).join('\n')}
        onInput=${(e) => set('dns_upstream', e.target.value.split('\n').map((line) => line.trim()).filter(Boolean))}></textarea>
    </label>
    <h2>Health checks</h2>
    <div class="grid2">
      <label class="check"><input type="checkbox" checked=${!!form.health_enabled} onChange=${(e) => set('health_enabled', e.target.checked)} /> Enabled</label>
      <label>Interval
        <input type="text" value=${form.health_interval || ''} placeholder="30s" onInput=${(e) => set('health_interval', e.target.value)} />
      </label>
    </div>
    <label>Health check URL
      <input type="text" value=${form.health_url || ''} placeholder="https://example.com" onInput=${(e) => set('health_url', e.target.value)} />
    </label>
    <h2>Isolation</h2>
    <label class="check"><input type="checkbox" checked=${!!form.isolation} onChange=${(e) => set('isolation', e.target.checked)} /> Isolate client traffic from this host</label>
    <p class="muted small">Internal management API: ${settings.listen || '127.0.0.1'}:${settings.api_port || 8080}. This is separate from the proxy and HTTPS panel and is not changed by proxy access controls.</p>
    <p class="footnote">Changing gateway mode, TUN, DNS or the LAN interface requires the tunnel to reconnect; connected clients lose traffic briefly.</p>
  </form>`}

  <div class="panel">
    <h2>Proxy Listening/Access</h2>
    <p class="muted">This controls the SOCKS/HTTP mixed proxy only. It does not change the web HTTPS panel or the internal management API.</p>
    ${proxy ? html`<div class="grid2">
      <label>SOCKS proxy port
        <input type="number" min="1" max="65535" step="1" value=${proxy.socks_port}
          onInput=${(e) => setProxy((current) => ({ ...current, socks_port: Number(e.target.value) }))} />
      </label>
      <label>Proxy listening address
        <select value=${proxy.socks_listen}
          onChange=${(e) => setProxy((current) => ({ ...current, socks_listen: e.target.value }))}>
          <option value="127.0.0.1">Localhost only — 127.0.0.1</option>
          ${settings.trusted_lan_ip ? html`<option value=${settings.trusted_lan_ip}>Trusted LAN — ${settings.trusted_lan_ip}</option>` : null}
          <option value="0.0.0.0">All IPv4 interfaces — 0.0.0.0</option>
        </select>
      </label>
    </div>
    <${KV} rows=${[
      ['Current configured endpoint', proxyEndpoint(settings.socks_listen || '127.0.0.1', settings.socks_port)],
      ['Proposed endpoint', proxyEndpoint(proxy.socks_listen, proxy.socks_port)],
      ['Effective listeners', (settings.effective_proxy_endpoints || []).join(', ') || 'Not verified'],
      ['Trusted client allow-list', (settings.trusted_lan_cidrs || []).join(', ') || settings.trusted_lan_cidr || 'Unavailable — LAN exposure is refused'],
      ['Web HTTPS panel', `${location.origin} (host TLS terminator; unchanged)`],
      ['Embedded web listener', settings.web_socket || `${settings.web_listen || '127.0.0.1'}:${settings.web_port || '—'}`],
      ['Internal management API', `${settings.listen || '127.0.0.1'}:${settings.api_port || 8080} (unchanged)`],
    ]} />
    <p class="notice warn">0.0.0.0 does not by itself restrict clients to the LAN. A broad proxy bind requires explicit confirmation and an owned firewall allow-list; other sources are rejected.</p>
    <p class="footnote">The trusted allow-list is host policy in <span class="mono">server.socks_trusted_cidrs</span>; it is validated against this host's interfaces and is not editable from this panel.</p>
    <button class="btn primary" type="button" disabled=${controlsBusy || !settings.service_restart_supported}
      onClick=${confirmProxy}>Apply proxy listener and restart Gateway</button>` : html`<${Skeleton} rows=${2} />`}
    ${!settings.service_restart_supported ? html`<p class="footnote">${settings.service_restart_reason || 'Supervised service operations require an installed systemd-managed Bypath service.'}</p>` : null}
  </div>

  ${operation ? html`<div class="panel" role="status" aria-live="polite">
    <h2>Gateway operation: ${operation.state}</h2>
    <p>${operation.message}</p>
    ${operation.old_endpoint ? html`<p class="mono">${operation.old_endpoint} → ${operation.proposed_endpoint}</p>` : null}
    ${terminalOperation(operation.state) ? html`<button class="btn ghost" onClick=${() => { sessionStorage.removeItem(operationKey); setOperationID(''); setOperation(null); }}>Dismiss result</button>` : null}
  </div>` : null}

  <div class="panel">
    <h2>What happens on the next start</h2>
    ${selection.state && selection.state !== 'S-OK'
      ? html`<${Banner} kind=${selection.state === 'S-DANGLING' ? 'bad' : 'warn'}
          title=${selection.state === 'S-UNSET' ? 'Next start is not set' : selection.state === 'S-DANGLING' ? 'The saved next-start connection no longer exists' : 'Next start differs from what is serving'}
          text=${selection.message || ''} />`
      : html`<p class="muted">The saved next start resolves to an existing connection today.</p>`}
    <p class="muted">If the saved selection is missing or no longer resolves, the current gateway start path takes the <strong>first testable connection it finds</strong> across these import lists: ${importLists.length ? importLists.join(', ') : 'no import lists yet'}. That scan order is not exposed or guaranteed, so the result is not predictable.</p>
    <p class="muted small">This panel does not change that behaviour. It only makes the saved choice visible and lets you set it explicitly. A Release 2 runtime change proposes refusing to start or using a declared default instead; that change is not active unless it is separately approved and deployed.</p>
    <div class="actions">
      <button class="btn ghost small" type="button" onClick=${() => navigate('connections')}>Choose the next-start connection</button>
    </div>
  </div>

  <div class="panel">
    <h2>Backup and restore</h2>
    <p class="muted">Backups contain configuration only: credentials, tokens and subscription addresses are excluded.</p>
    <div class="actions">
      <button class="btn ghost" type="button" disabled=${busy === 'backup'} onClick=${downloadBackup}>${busy === 'backup' ? 'Preparing…' : 'Download backup'}</button>
      <label class="filebtn">Restore from backup
        <input type="file" accept="application/json,.json" onChange=${chooseRestore} />
      </label>
      <button class="btn ghost" type="button" disabled=${!restoreFile || busy === 'restore'} onClick=${restore}>${busy === 'restore' ? 'Restoring…' : 'Restore selected file'}</button>
    </div>
    ${restoreFile ? html`<p class="small muted">Selected: ${restoreFile.name}</p>` : null}
  </div>

  <div class="panel">
    <h2>Gateway service</h2>
    <p class="muted">Reconnect restarts the current VPN tunnel while keeping the panel process alive. Restart Gateway service restarts Bypath under an independent systemd recovery supervisor, not the host. Both interrupt connected clients briefly.</p>
    <div class="actions">
      <button class="btn ghost" type="button" disabled=${controlsBusy} onClick=${() => openDialog(html`<${ConfirmDialog}
        title="Reconnect current VPN tunnel" text="Client traffic will pause while the currently serving VPN reconnects. The saved next-start connection is preserved."
        confirmLabel="Reconnect current tunnel" onClose=${closeDialog}
        onConfirm=${() => { closeDialog(); restartTunnel().catch(toastError); }} />`)}>Reconnect current VPN tunnel</button>
      <button class="btn primary" type="button" disabled=${controlsBusy || !settings.service_restart_supported} onClick=${confirmServiceRestart}>Restart Bypath Gateway service</button>
      <button class="btn danger" type="button" onClick=${() => openDialog(html`<${StopDaemonDialog} onClose=${closeDialog} />`)}>Stop Bypath daemon</button>
    </div>
  </div>

  <div class="panel">
    <h2>Administrator password</h2>
    <form onSubmit=${changePassword}>
      <div class="grid2">
        <label>Current password <input name="current" type="password" autocomplete="current-password" required /></label>
        <label>New password <input name="next" type="password" autocomplete="new-password" minlength="12" required /></label>
      </div>
      <label>Confirm new password <input name="confirm" type="password" autocomplete="new-password" minlength="12" required /></label>
      <button class="btn primary" type="submit" disabled=${busy === 'password'}>${busy === 'password' ? 'Changing…' : 'Change password'}</button>
    </form>
    <p class="footnote">The administrator exists only on this machine. Sessions expire after 24 hours or 12 hours idle.</p>
  </div>

  <div class="panel">
    <div class="view-head">
      <h2>Diagnostics and logs</h2>
      <div class="actions">
        <button class="btn ghost small" type="button" disabled=${busy === 'logs'} onClick=${logsNow}>Refresh</button>
        <button class="btn ghost small" type="button" onClick=${downloadLogs}>Export</button>
      </div>
    </div>
    <div class="toolbar">
      <input type="search" placeholder="Filter messages" aria-label="Filter log messages"
        value=${logFilter} onInput=${(e) => setLogFilter(e.target.value)} />
      <select aria-label="Filter by level" value=${logLevel} onChange=${(e) => setLogLevel(e.target.value)}>
        <option value="all">All levels</option>
        <option value="info">Info</option>
        <option value="warn">Warning</option>
        <option value="error">Error</option>
        <option value="debug">Debug</option>
      </select>
      <span class="muted small">${filteredLogs.length} of ${(logs || []).length}${logsAt ? ` · read ${new Date(logsAt).toLocaleTimeString()}` : ''}</span>
    </div>
    <div class="panel logs" style="margin-top:10px">
      <div class="log-list">
        ${filteredLogs.map((entry, index) => html`<div class="log-row" key=${`${entry.time}:${index}`}>
          <span class="t">${String(entry.time || '').slice(11, 19)}</span>
          <span class=${`l ${String(entry.level || '').toLowerCase()}`}>${entry.level}</span>
          <span>${entry.message}</span>
        </div>`)}
      </div>
      ${filteredLogs.length === 0 ? html`<p class="empty">No log entries match.</p>` : null}
    </div>
    <p class="footnote">Log messages are redacted by the gateway before they are stored. Credentials and raw subscription addresses never appear here.</p>
  </div>

  <div class="panel">
    <h2>Engines</h2>
    ${(Array.isArray(state.engines) ? state.engines : []).length === 0 ? html`<p class="empty">No tunnel engines were reported. The gateway may still be starting.</p>` : html`<div class="table-wrap"><table class="data">
      <thead><tr><th>Engine</th><th>Version</th><th>Source</th><th>Status</th></tr></thead>
      <tbody>${state.engines.map((engine) => html`<tr key=${engine.name}>
        <td><strong>${engine.name}</strong></td>
        <td class="mono small">${engine.version || '—'}</td>
        <td class="small">${engine.source || engine.path || '—'}</td>
        <td><span class=${`chip ${engine.ready ? 'healthy' : 'unavailable'}`}>${engine.ready ? 'ready' : 'not found'}</span></td>
      </tr>`)}</tbody>
    </table></div>`}
  </div>

  <div class="panel">
    <h2>About</h2>
    <${KV} rows=${[
      ['Version', status.version],
      ['Variant', status.variant],
      ['Commit', status.commit],
      ['Built', status.build_date],
      ['Gateway state', status.state ? fmtStateLabel(status.state) : '—'],
      ['API port', status.api_port],
      ['DNS port', status.dns_port],
      ['SOCKS port', status.socks_port],
      ['Connections', status.profile_count],
      ['Sources', status.subscription_count],
      ['Organisation layer', status.layer_migrated ? 'created' : 'not created'],
      ['Session started', state.statusAt ? fmtDate(state.statusAt) : '—'],
    ]} />
    <div class="actions" style="margin-top:10px">
      <button class="btn ghost small" type="button" onClick=${signOut}>Sign out of the panel</button>
    </div>
  </div>`;
}

function toForm(settings) {
  return {
    gateway_mode: !!settings.gateway_mode,
    native_tun: !!settings.native_tun,
    lan_interface: settings.lan_interface || '',
    dns_mode: settings.dns_mode || 'strict',
    preferred_engine: settings.preferred_engine || '',
    dns_upstream: settings.dns_upstream || [],
    health_enabled: !!settings.health_enabled,
    health_interval: settings.health_interval || '',
    health_url: settings.health_url || '',
    isolation: !!settings.isolation,
  };
}

function diffForm(original, current) {
  const patch = {};
  for (const key of Object.keys(current)) {
    const a = JSON.stringify(original[key]);
    const b = JSON.stringify(current[key]);
    if (a !== b) patch[key] = current[key];
  }
  return patch;
}
