// Overview: the one screen that answers "is traffic flowing, through what, and
// does the evidence agree". Everything else is one click away.

import { html, Chip, Banner, Empty, KV, Skeleton, ResultChip } from '../ui.js';
import { navigate } from '../nav.js';
import { statusWord, selectionInfoOf, servingName, fmtDuration, timeAgo, evidenceOf, verdictOf, connectionName, tunnelServing, healthEvidence } from '../format.js';
import { probeExit, restartTunnel, disconnectTunnel, restorePrevious, refreshStatus, loadResults } from '../data.js';
import { toastError, toast } from '../store.js';

const HERO_GLYPH = { ok: '✓', busy: '◌', down: '✕' };

export default function OverviewView({ state }) {
  const status = state.status;
  if (!status) {
    return html`<div class="view-head"><div><h1>Overview</h1><div class="sub">Reading the gateway state…</div></div></div>
      <${Skeleton} rows=${4} />`;
  }
  const word = statusWord(status);
  const health = healthEvidence(status);
  const selection = selectionInfoOf(status) || {};
  const connected = tunnelServing(status);
  const inFlight = !!status.running && ['CONNECTING', 'RECOVERING', 'DEGRADED'].includes(String(status.state || '').toUpperCase());
  const serving = connected ? (status.active_link || status.selected_link || '') : '';
  const heroName = serving || (inFlight ? (status.active_link || 'Starting…') : 'No connection is serving');
  const servingConn = connected ? (state.connections || []).find((c) => c.active || c.id === status.active_id) : null;
  const latest = (state.results || []).slice().sort((a, b) => String(b.tested_at || '').localeCompare(String(a.tested_at || '')))[0] || null;
  const layer = state.layer;
  const broken = !status.running || ['DISCONNECTED', 'FAILED', 'ERROR'].includes(String(status.state || '').toUpperCase());
  const firstRun = !!state.connectionsLoaded && (state.connections || []).length === 0;

  return html`<div class="view-head">
    <div>
      <h1>Overview</h1>
      <div class="sub">Traffic, the connection carrying it, and the evidence behind both. State is read from the gateway on every poll.</div>
    </div>
    <div class="view-actions">
      <button class="btn ghost small" type="button" onClick=${() => refreshStatus().catch(toastError)}>Refresh</button>
    </div>
  </div>

  <div class=${`hero ${word.kind === 'down' ? 'down' : word.kind === 'busy' ? 'busy' : ''}`}>
    <div class="eyebrow">
      <div class="ring" aria-hidden="true">${HERO_GLYPH[word.kind] || '·'}</div>
      <div>
        <div class="state-word">${word.word}</div>
        <div class="hero-name">${heroName}</div>
      </div>
      <div class="grow"></div>
      <div class="pills">
        ${status.protocol ? html`<span class="badge accent">${status.protocol.toUpperCase()}</span>` : null}
        ${status.engine ? html`<span class="badge">${status.engine}</span>` : null}
        ${status.gateway_mode ? html`<span class="badge">Gateway mode</span>` : html`<span class="badge">Proxy only</span>`}
        ${status.fallback_from ? html`<span class="badge warn">fallback from ${status.fallback_from}</span>` : null}
        ${health && health.identityFailure ? html`<span class="badge warn">exit not verified</span>` : null}
        ${health && health.forwardingFailure ? html`<span class="badge bad">tunnel not forwarding</span>` : null}
      </div>
    </div>
    <div class="muted">${word.explanation}</div>
    ${servingConn ? html`<div class="row small muted">
      <span>${servingConn.address || ''}${servingConn.port ? `:${servingConn.port}` : ''}</span>
      ${servingConn.layer_group ? html`<span>· ${servingConn.layer_group}</span>` : null}
      ${latest ? html`<span>· last test ${timeAgo(latest.tested_at)}</span>` : null}
    </div>` : null}
    <div class="facts">
      <div class="fact">
        <div class="k">Public exit</div>
        <div class="v mono">${state.exit ? (state.exit.error ? 'probe failed' : state.exit.ip) : (status.exit_ip || 'not checked')}</div>
      </div>
      <div class="fact">
        <div class="k">Uptime</div>
        <div class="v">${status.running ? fmtDuration(status.uptime_sec) : '—'}</div>
      </div>
      <div class="fact">
        <div class="k">Next start</div>
        <div class="v">${selection.selected_remark || (selection.state === 'S-UNSET' ? 'not set' : '—')}</div>
      </div>
      <div class="fact">
        <div class="k">Health</div>
        <div class="v">${health ? health.label : (status.last_health || (status.restarts ? `${status.restarts} restart${status.restarts === 1 ? '' : 's'}` : '—'))}</div>
        ${health && !health.verified
          ? html`<div class="sub muted">${health.text}</div>`
          : status.last_health ? html`<div class="sub muted">checked ${timeAgo(status.last_health)}</div>` : null}
      </div>
    </div>
    <div class="actions">
      <button class="btn primary" type="button" onClick=${() => navigate('connections')}>${broken ? 'Choose a connection' : 'Switch connection'}</button>
      <button class="btn ghost" type="button" disabled=${state.exitBusy} onClick=${() => probeExit().catch(toastError)}>${state.exitBusy ? 'Checking…' : 'Check exit IP'}</button>
      <button class="btn ghost" type="button" onClick=${() => restartTunnel().catch(toastError)}>Reconnect tunnel</button>
      <button class="btn ghost" type="button" disabled=${!status.running || String(status.state).toUpperCase() === 'DISCONNECTED'} onClick=${() => disconnectTunnel().catch(toastError)}>Disconnect</button>
      ${status.previous_id && status.previous_id !== status.active_id
        ? html`<button class="btn ghost" type="button" onClick=${() => restorePrevious().catch(toastError)}>Return to ${status.previous_link || 'previous'}</button>`
        : null}
    </div>
  </div>

  ${firstRun ? html`<div class="panel">
    <h2>First run: this gateway has no connections yet</h2>
    <p class="muted">Bypath ships without a provider, a subscription, a country policy or a saved next start. Nothing is routed until you add a source and choose a connection.</p>
    <ol class="muted small" style="margin:8px 0 12px 18px; line-height:1.7">
      <li><strong>Import a source.</strong> Paste a subscription address or a single proxy URI (VLESS, VMess, Trojan, Shadowsocks, SSH, WireGuard, OpenVPN). A matching organisation group is created for the new connections.</li>
      <li><strong>Choose the next start.</strong> Selection is explicit; Bypath does not pick a connection for you.</li>
      <li><strong>Verify before routing.</strong> A relay test proves the path a connection uses. An inconclusive test means the path was not proven — it is not a verdict that the connection is bad.</li>
    </ol>
    <div class="actions">
      <button class="btn primary" type="button" onClick=${() => navigate('sources')}>Import a source</button>
      <button class="btn ghost" type="button" onClick=${() => navigate('connections')}>Open connections</button>
      <button class="btn ghost" type="button" onClick=${() => navigate('tests', 'run')}>Run a test</button>
    </div>
    <h3 style="margin-top:16px">Three surfaces, three different risks</h3>
    <p class="muted small"><strong>This panel</strong> is the local management surface. It binds to loopback unless you deliberately widen it, and every browser session needs the administrator password set at setup. <strong>The internal management API</strong> on ${status.api_port ? `127.0.0.1:${status.api_port}` : 'loopback'} is separate: the CLI and TUI use it and it requires the gateway token. It is not the proxy and never carries traffic. <strong>The proxy listener</strong> is separate again: SOCKS/mixed on port ${status.socks_port || 2801}, with no authentication of its own. Keep it on localhost unless you have entered trusted client CIDRs and added the matching firewall rule; a LAN bind without both is refused.</p>
    <p class="muted small"><strong>Proxy only</strong> (the default) leaves this host's own routing alone: clients use the proxy explicitly. <strong>Gateway mode</strong> sends the whole host through the tunnel; it stays off until a connection exists, is selected, and its exit has been verified. Bypath never starts an empty full-tunnel gateway.</p>
  </div>` : null}

  <div class="cards">
    <button class="tile" type="button" onClick=${() => navigate('connections')} style="text-align:left">
      <div class="label">Connections</div>
      <div class="value">${status.profile_count ?? (state.connections || []).length}</div>
      <div class="sub">${(state.connections || []).filter((c) => c.requires_auth && !c.has_credentials).length || 'no'} credential gap(s)</div>
    </button>
    <button class="tile" type="button" onClick=${() => navigate('sources')} style="text-align:left">
      <div class="label">Sources</div>
      <div class="value">${status.subscription_count ?? (state.subscriptions || []).length}</div>
      <div class="sub">${(state.subscriptions || []).filter((s) => s.last_error).length} with an error</div>
    </button>
    <div class="tile">
      <div class="label">Public exit</div>
      <div class="value mono">${state.exit ? (state.exit.error ? '—' : state.exit.ip) : (status.exit_ip || '—')}</div>
      <div class="sub">${state.exit && !state.exit.error ? `checked ${timeAgo(state.exit.at)}` : 'checked on demand'}</div>
    </div>
    <button class="tile" type="button" onClick=${() => navigate('tests')} style="text-align:left">
      <div class="label">Latest measurement</div>
      <div class="value">${latest ? verdictOf(latest).label : 'None yet'}</div>
      <div class="sub">${latest ? evidenceOf(latest) || timeAgo(latest.tested_at) : 'Run a test to create evidence'}</div>
    </button>
    <button class="tile" type="button" onClick=${() => navigate('connections')} style="text-align:left">
      <div class="label">Organisation</div>
      <div class="value">${layer && layer.migrated ? `${layer.groups} group${layer.groups === 1 ? '' : 's'}` : 'Not created'}</div>
      <div class="sub">${layer && layer.migrated ? `${layer.entries} connections indexed${layer.orphaned ? ` · ${layer.orphaned} orphaned` : ''}` : 'Your import lists still drive everything'}</div>
    </button>
  </div>

  ${broken ? html`<div class="panel">
    <h2>No traffic is being routed</h2>
    <p class="muted">${status.running
      ? 'The tunnel is intentionally down. The panel and the CLI stay available; reconnect when you are ready.'
      : 'The Bypath daemon is not running, so this panel is showing the last known state. Start it on the host to restore service.'}</p>
    <div class="actions">
      <button class="btn primary" type="button" onClick=${() => navigate('connections')}>Choose a connection</button>
      ${status.selected_id ? html`<button class="btn ghost" type="button" onClick=${() => restartTunnel().catch(toastError)}>Reconnect ${status.selected_link || 'the saved connection'}</button>` : null}
    </div>
  </div>` : null}

  ${status.last_error && String(status.state).toUpperCase() !== 'FAILED'
    ? html`<div class="panel"><h2>Last error</h2><p class="notice bad">${status.last_error}</p></div>` : null}

  <div class="panel">
    <div class="view-head">
      <h2>Recent measurements</h2>
      <button class="btn ghost small" type="button" onClick=${() => { loadResults().catch(toastError); navigate('tests', 'results'); }}>All results</button>
    </div>
    ${(state.results || []).length === 0
      ? html`<${Empty} icon="◎" title="No measurements yet"
          text="Relay and latency tests prove what path a connection actually uses. Speed tests only run on connections with a proven relay result."
          action=${html`<button class="btn primary small" type="button" onClick=${() => navigate('tests', 'run')}>Open Tests</button>`} />`
      : html`<div class="clist">
          ${(state.results || []).slice().sort((a, b) => String(b.tested_at || '').localeCompare(String(a.tested_at || ''))).slice(0, 4).map((result) => html`
            <div class="crow" key=${`${result.connection_id}:${result.kind}:${result.tested_at}`} onClick=${() => navigate('tests', 'results')}>
              <div class="avatar">${result.kind === 'speed' ? 'SPD' : 'RT'}</div>
              <div class="c-main">
                <div class="c-name">${result.remark || result.connection_id}</div>
                <div class="c-sub">${result.kind === 'speed' ? 'Download speed' : 'Relay and latency'} · ${evidenceOf(result) || timeAgo(result.tested_at)}</div>
              </div>
              <div class="c-end"><${ResultChip} result=${result} /></div>
            </div>`)}
        </div>`}
  </div>

  ${status.selection && ['S-UNSET', 'S-DANGLING', 'S-AUTO'].includes(status.selection.state) ? html`<div class="panel">
    <h2>Why the next start matters</h2>
    <p class="muted">On the next start Bypath reads the saved selection. ${status.selection.state === 'S-DANGLING'
      ? 'This pair no longer resolves, so the gateway would choose an arbitrary connection from your import lists.'
      : 'When nothing is saved, the gateway chooses a connection itself, and that choice is not predictable.'}</p>
    <p class="muted small">Choosing a connection here is the only thing that changes the saved next start. Organisation edits never do.</p>
  </div>` : null}

  ${status.running ? html`<p class="footnote">State polled ${timeAgo(state.statusAt) || 'just now'}. Exit addresses are observed by an independent echo service; they are not configuration.</p>` : null}
`;
}
