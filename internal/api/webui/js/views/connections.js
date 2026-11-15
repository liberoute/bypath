// Connections: what you have, which one is serving, which one starts next, and
// the evidence for both. Organisation edits never touch the tunnel.

import { html, Chip, Banner, Empty, Skeleton, Drawer, KV, ResultChip } from '../ui.js';
import { useState, useEffect } from '../../vendor/hooks.module.js';
import { navigate } from '../nav.js';
import { api } from '../api.js';
import { store, toast, toastError } from '../store.js';
import {
  loadConnections, loadGroups, loadLayer, loadResults, migrateLayer,
  connectTo, disconnectTunnel, restorePrevious, probeExit, setSelection,
} from '../data.js';
import {
  connectionName, protocolShort, fmtLatency, timeAgo, verdictOf, evidenceOf,
  reasonText, pathKind, latestResult, tunnelServing,
} from '../format.js';
import {
  GroupDialog, MoveDialog, DeleteConnectionDialog, CredentialsDialog,
  ImportURIDialog, ImportOVPNDialog, TextDialog, ConfirmDialog,
} from '../dialogs.js';

const closeDialog = () => store.set({ dialog: null });
const openDialog = (node) => store.set({ dialog: node });

export default function ConnectionsView({ state }) {
  const [search, setSearch] = useState('');
  const [protocol, setProtocol] = useState('');
  const [groupFilter, setGroupFilter] = useState('__all');
  const [showHidden, setShowHidden] = useState(false);
  const [sort, setSort] = useState('order');
  const [drawer, setDrawer] = useState('');

  const status = state.status || {};
  const layer = state.layer;
  const migrated = !!(layer && layer.migrated);
  const readOnly = !!(layer && layer.read_only);
  const groups = state.groups || [];
  const connections = state.connections || [];
  const servingId = tunnelServing(status) ? (status.active_id || '') : '';
  const selectedId = (status.selection && status.selection.selected_id) || status.selected_id || '';

  const visible = connections.filter((connection) => {
    if (!showHidden && connection.hidden) return false;
    if (protocol && connection.protocol !== protocol) return false;
    if (search) {
      const haystack = [connectionName(connection), connection.address, connection.layer_group, connection.group, connection.remark]
        .filter(Boolean).join(' ').toLowerCase();
      if (!haystack.includes(search.toLowerCase())) return false;
    }
    return true;
  });

  const byStable = new Map(visible.map((connection) => [connection.stable_id || connection.id, connection]));
  const latencyOf = (connection) => {
    const result = latestResult(state.results || [], connection.stable_id || connection.id, 'latency');
    return result && result.status === 'ok' ? (result.p50_ms || result.latency_ms || 0) : null;
  };

  const sortRows = (rows) => {
    const copy = rows.slice();
    if (sort === 'name') {
      copy.sort((a, b) => connectionName(a).localeCompare(connectionName(b)));
    } else if (sort === 'latency') {
      copy.sort((a, b) => {
        const la = latencyOf(a);
        const lb = latencyOf(b);
        if (la === null && lb === null) return connectionName(a).localeCompare(connectionName(b));
        if (la === null) return 1;
        if (lb === null) return -1;
        return la - lb;
      });
    }
    return copy;
  };

  const groupSections = [];
  if (migrated && groupFilter === '__all' && groups.length > 0) {
    for (const group of groups) {
      if (group.id === '') continue;
      const rows = group.member_ids && Array.isArray(group.member_ids)
        ? group.member_ids.map((id) => byStable.get(id)).filter(Boolean)
        : [];
      groupSections.push({ group, rows: sortRows(rows) });
    }
    const ungrouped = visible.filter((connection) => !connection.layer_group_id);
    if (ungrouped.length) {
      groupSections.push({
        group: groups.find((g) => g.id === '') || { id: '', name: 'Ungrouped', count: ungrouped.length },
        rows: sortRows(ungrouped),
      });
    }
  } else {
    const rows = groupFilter === '__all'
      ? visible
      : groupFilter === ''
        ? visible.filter((connection) => !connection.layer_group_id)
        : visible.filter((connection) => connection.layer_group_id === groupFilter);
    if (rows.length) groupSections.push({
      group: groupFilter === '__all' ? null : groups.find((g) => g.id === groupFilter),
      rows: sortRows(rows),
    });
  }

  const totalVisible = groupSections.reduce((sum, section) => sum + section.rows.length, 0);
  const hiddenCount = connections.filter((connection) => connection.hidden).length;
  const activeConnection = tunnelServing(status)
    ? (connections.find((connection) => connection.active) || connections.find((connection) => connection.id === status.active_id))
    : null;
  const selectedConnection = connections.find((connection) => connection.stable_id === selectedId || connection.id === selectedId);
  const drawerConnection = connections.find((connection) => connection.stable_id === drawer || connection.id === drawer);

  const refreshAll = () => Promise.allSettled([loadConnections(), loadGroups(), loadLayer(), loadResults()]);

  const connect = async (connection) => {
    try {
      await connectTo(connection.id);
    } catch (err) {
      toastError(err);
    }
  };

  const toggleHidden = async (connection) => {
    try {
      await api.post('/layer/hide', { ids: [connection.stable_id || connection.id], hidden: !connection.hidden });
      await loadConnections();
      toast(connection.hidden ? 'Connection shown.' : 'Connection hidden from the list.', 'success');
    } catch (err) {
      toastError(err);
    }
  };

  return html`<div class="view-head">
    <div>
      <h1>Connections</h1>
      <div class="sub">Connect, organise and inspect. Groups are your labels; their order is not failover and never switches the tunnel.</div>
    </div>
    <div class="view-actions">
      <button class="btn primary" type="button" onClick=${() => openDialog(html`<${ImportURIDialog} groups=${groups}
        onClose=${closeDialog} onDone=${() => refreshAll()} />`)}>Import link</button>
      <button class="btn ghost" type="button" onClick=${() => openDialog(html`<${ImportOVPNDialog} groups=${groups}
        onClose=${closeDialog} onDone=${() => refreshAll()} />`)}>Import OpenVPN</button>
      ${migrated && !readOnly
        ? html`<button class="btn ghost" type="button" onClick=${() => openDialog(html`<${GroupDialog} groups=${groups}
            onClose=${closeDialog} onDone=${() => refreshAll()} />`)}>New group</button>`
        : null}
    </div>
  </div>

  ${layer && !migrated && state.layerPlan ? html`<${Banner} kind="info" title="Organisation is not created yet"
    text=${`Your ${state.layerPlan.entries ? state.layerPlan.entries.length : 0} connections are still exactly as imported. Creating the organisation layer only adds labels; it does not rewrite links or the saved next start.`}
    actions=${html`<button class="btn primary small" type="button" onClick=${() => openDialog(html`<${MigrationDialog}
      plan=${state.layerPlan} onClose=${closeDialog} onDone=${() => refreshAll()} />`)}>Review and create</button>`} />` : null}
  ${layer && !migrated && !state.layerPlan ? html`<p class="notice">The organisation layer is not available on this gateway. Connections below are read from the import lists directly.</p>` : null}
  ${readOnly ? html`<${Banner} kind="warn" title="Organisation layer is read-only"
    text=${layer.corrupt && layer.corrupt.length ? `Some organisation files are unreadable: ${layer.corrupt.join(', ')}. Editing is disabled to protect them.` : 'The layer could not be opened for writing. Connections still work.'} />` : null}

  ${activeConnection ? html`<div class="panel">
    <div class="row">
      <div class="grow">
        <div class="cap">Serving now</div>
        <div class="hero-name">${connectionName(activeConnection)}</div>
        <div class="row small muted" style="margin-top:4px">
          <span>${activeConnection.address}${activeConnection.port ? `:${activeConnection.port}` : ''}</span>
          <span>· ${activeConnection.protocol.toUpperCase()}</span>
          ${activeConnection.layer_group ? html`<span>· ${activeConnection.layer_group}</span>` : null}
          ${status.state ? html`<span>· ${String(status.state).toLowerCase()}</span>` : null}
        </div>
      </div>
      <div class="actions">
        <span class="chip serving">serving</span>
        <button class="btn ghost small" type="button" disabled=${state.exitBusy} onClick=${() => probeExit().catch(toastError)}>Check exit IP</button>
        <button class="btn ghost small" type="button" onClick=${() => restorePrevious().catch(toastError)} disabled=${!status.previous_id || status.previous_id === status.active_id}>Return to previous</button>
        <button class="btn ghost small" type="button" onClick=${() => disconnectTunnel().catch(toastError)}>Disconnect</button>
      </div>
    </div>
  </div>` : html`<div class="panel">
    <div class="row">
      <div class="grow">
        <div class="cap">Serving now</div>
        <div class="hero-name">${status.running ? 'Nothing is serving' : 'Gateway is not running'}</div>
        <div class="small muted" style="margin-top:4px">
          ${status.running ? 'The tunnel is down. No client traffic is routed until a connection is started.' : 'This panel shows the last known state. Start Bypath on the host to restore management.'}
        </div>
      </div>
      ${selectedConnection ? html`<button class="btn primary small" type="button" onClick=${() => connect(selectedConnection)}>Connect ${connectionName(selectedConnection)}</button>` : null}
    </div>
  </div>`}

  <div class="toolbar">
    <input type="search" placeholder="Search name, address or group" aria-label="Search connections"
      value=${search} onInput=${(e) => setSearch(e.target.value)} />
    <select aria-label="Filter by protocol" value=${protocol} onChange=${(e) => setProtocol(e.target.value)}>
      <option value="">All protocols</option>
      <option value="vless">VLESS</option>
      <option value="vmess">VMess</option>
      <option value="trojan">Trojan</option>
      <option value="shadowsocks">Shadowsocks</option>
      <option value="openvpn">OpenVPN</option>
    </select>
    <select aria-label="Sort connections" value=${sort} onChange=${(e) => setSort(e.target.value)}>
      <option value="order">Group order</option>
      <option value="name">Name</option>
      <option value="latency">Fastest measured</option>
    </select>
    <label class="check"><input type="checkbox" checked=${showHidden} onChange=${(e) => setShowHidden(e.target.checked)} />
      Show hidden${hiddenCount ? ` (${hiddenCount})` : ''}</label>
    <button class="btn ghost small" type="button" onClick=${() => refreshAll()}>Refresh</button>
  </div>

  ${migrated ? html`<div class="grail" role="tablist" aria-label="Filter by group">
    <button type="button" class=${groupFilter === '__all' ? 'gchip active' : 'gchip'} onClick=${() => setGroupFilter('__all')}>
      All <span class="count">${connections.filter((c) => showHidden || !c.hidden).length}</span>
    </button>
    ${groups.filter((g) => g.id !== '').map((group) => html`<button key=${group.id} type="button"
      class=${groupFilter === group.id ? 'gchip active' : 'gchip'} onClick=${() => setGroupFilter(group.id)}>
      ${group.name} <span class="count">${group.count || (group.member_ids || []).length}</span>
      ${activeConnection && activeConnection.layer_group_id === group.id ? html`<span class="serving-dot" title="Serving connection is in this group"></span>` : null}
    </button>`)}
    ${groups.some((g) => g.id === '')
      ? html`<button type="button" class=${groupFilter === '' ? 'gchip active' : 'gchip'} onClick=${() => setGroupFilter('')}>
          Ungrouped <span class="count">${(groups.find((g) => g.id === '') || {}).count || 0}</span>
        </button>`
      : null}
  </div>` : null}

  ${!state.connectionsLoaded ? html`<${Skeleton} rows=${5} />` : null}

  ${state.connectionsLoaded && totalVisible === 0 ? html`<${Empty} icon="≣"
    title=${connections.length === 0 ? 'No connections yet' : 'Nothing matches this filter'}
    text=${connections.length === 0
      ? 'Import a link, an OpenVPN profile or add a source. Every connection is stored locally on this gateway.'
      : 'Clear the search or choose another group.'}
    action=${connections.length === 0
      ? html`<button class="btn primary small" type="button" onClick=${() => openDialog(html`<${ImportURIDialog} groups=${groups} onClose=${closeDialog} onDone=${() => refreshAll()} />`)}>Import link</button>`
      : null} />` : null}

  ${state.connectionsLoaded && totalVisible > 0 ? html`<div class="panel">
    <div class="stack" style="gap:18px">
      ${groupSections.map((section) => html`<section class="stack" key=${section.group ? section.group.id : '__all'} style="gap:6px">
        ${section.group ? html`<div class="group-head">
          <span class="g-name">${section.group.name}</span>
          <span class="g-note">${section.rows.length} connection${section.rows.length === 1 ? '' : 's'} · order is not failover</span>
          ${migrated && !readOnly && section.group.id ? html`<button class="btn ghost small" type="button"
            onClick=${() => openDialog(html`<${GroupDialog} group=${augmentGroup(section.group, connections)}
              groups=${groups} onClose=${closeDialog} onDone=${() => refreshAll()} />`)}>Edit group</button>` : null}
        </div>` : null}
        ${section.rows.length === 0
          ? html`<p class="empty">No connections in this group yet. Open a connection and use “Move to group”.</p>`
          : html`<div class="clist">
          ${section.rows.map((connection) => html`<${ConnectionRow} key=${connection.stable_id || connection.id}
            connection=${connection} state=${state} serving=${!!servingId && (connection.active || connection.id === servingId)}
            selected=${connection.stable_id === selectedId || connection.id === selectedId}
            onOpen=${() => setDrawer(connection.stable_id || connection.id)} onConnect=${() => connect(connection)} />`)}
        </div>`}
      </section>`)}
    </div>
  </div>` : null}

  ${drawerConnection ? html`<${ConnectionDrawer} connection=${drawerConnection} state=${state}
    onClose=${() => setDrawer('')} onConnect=${() => connect(drawerConnection)}
    onRefresh=${() => refreshAll()} />` : null}
`;
}

function augmentGroup(group, connections) {
  const members = (group.member_ids || [])
    .map((id) => connections.find((connection) => (connection.stable_id || connection.id) === id))
    .filter(Boolean);
  return { ...group, members: members.map((c) => ({ id: c.stable_id || c.id, connection_id: c.id, remark: c.remark, display_name: c.display_name })) };
}

function MigrationDialog({ plan, onClose, onDone }) {
  const [busy, setBusy] = useState(false);
  const run = async () => {
    setBusy(true);
    try {
      await migrateLayer(false);
      onDone();
      onClose();
    } catch (err) {
      toastError(err);
      setBusy(false);
    }
  };
  return html`<${ConfirmDialog} title="Create the organisation layer"
    text="This adds sidecar files next to your profiles that record groups, display names and saved views. It does not rewrite links, import lists or the saved next start."
    confirmLabel=${busy ? 'Creating…' : 'Create layer'} busy=${busy} onClose=${onClose} onConfirm=${run} />`;
}

export function ConnectionRow({ connection, state, serving, selected, onOpen, onConnect }) {
  const relay = latestResult(state.results || [], connection.stable_id || connection.id, 'latency');
  const speed = latestResult(state.results || [], connection.stable_id || connection.id, 'speed');
  const latency = relay && relay.status === 'ok' ? (relay.p50_ms || relay.latency_ms) : 0;
  const needsCreds = connection.requires_auth && !connection.has_credentials;
  return html`<div class=${`crow ${serving ? 'serving' : ''}`} role="button" tabindex="0"
      onClick=${onOpen} onKeyDown=${(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onOpen(); } }}>
    <div class="avatar" aria-hidden="true">${protocolShort(connection.protocol)}<span class="p">${connection.engine || ''}</span></div>
    <div class="c-main">
      <div class="c-name">
        ${connectionName(connection)}
        ${serving ? html`<span class="chip serving">serving</span>` : null}
        ${selected && !serving ? html`<span class="chip serving">next start</span>` : null}
        ${connection.hidden ? html`<span class="chip skipped">hidden</span>` : null}
        ${connection.orphaned ? html`<span class="chip stale">orphaned</span>` : null}
        ${needsCreds ? html`<span class="chip degraded">credentials needed</span>` : null}
        ${connection.cdn ? html`<span class="badge">CDN</span>` : null}
      </div>
      <div class="c-sub">${connection.address}${connection.port ? `:${connection.port}` : ''}${connection.layer_group ? ` · ${connection.layer_group}` : (connection.group ? ` · ${connection.group}` : '')}${connection.from_subscription ? ` · source ${connection.from_subscription}` : ''}</div>
    </div>
    <div class="c-end">
      <span class="latency">${latency ? fmtLatency(latency) : '—'}</span>
      <${ResultChip} result=${relay} onClick=${(e) => { e.stopPropagation(); onOpen(); }} />
      <${ResultChip} result=${speed} onClick=${(e) => { e.stopPropagation(); onOpen(); }} />
      ${serving
        ? html`<button class="btn ghost small" type="button" onClick=${(e) => { e.stopPropagation(); onConnect(); }}>Reconnect</button>`
        : html`<button class="btn primary small" type="button" onClick=${(e) => { e.stopPropagation(); onConnect(); }}>Connect</button>`}
    </div>
  </div>`;
}

function ConnectionDrawer({ connection, state, onClose, onConnect, onRefresh }) {
  const [detail, setDetail] = useState(null);
  const [detailError, setDetailError] = useState('');
  const layer = state.layer;
  const migrated = !!(layer && layer.migrated);
  const readOnly = !!(layer && layer.read_only);
  const status = state.status || {};
  const serving = tunnelServing(status) && (connection.active || connection.id === status.active_id);
  const selectedId = (status.selection && status.selection.selected_id) || status.selected_id || '';
  const selected = connection.stable_id === selectedId || connection.id === selectedId;
  const results = state.results || [];
  const relay = latestResult(results, connection.stable_id || connection.id, 'latency');
  const speed = latestResult(results, connection.stable_id || connection.id, 'speed');
  const groups = state.groups || [];

  useEffect(() => {
    let live = true;
    api.get(`/connection?id=${encodeURIComponent(connection.id)}`)
      .then((value) => { if (live) setDetail(value); })
      .catch((err) => { if (live) setDetailError(err.message); });
    return () => { live = false; };
  }, [connection.id]);

  const openDialog = (node) => store.set({ dialog: node });

  const rename = () => openDialog(html`<${TextDialog} title="Display name" label="Name shown in the panel and TUI"
    value=${connection.display_name || ''} placeholder=${connection.remark}
    onSubmit=${async (name) => {
      await api.post('/layer/display-name', { id: connection.stable_id || connection.id, name });
      await loadConnections();
      toast('Display name saved. The stored link is unchanged.', 'success');
    }} onClose=${closeDialog} />`);

  const selectNext = async () => {
    try {
      await setSelection(connection.id);
      toast('Saved as the next start. The serving connection is unchanged.', 'success');
    } catch (err) {
      toastError(err);
    }
  };

  return html`<${Drawer} title=${connectionName(connection)} onClose=${onClose}>
    <div class="row">
      ${serving ? html`<span class="chip serving">serving</span>` : null}
      ${selected ? html`<span class="chip serving">next start</span>` : null}
      <span class="badge accent">${connection.protocol.toUpperCase()}</span>
      ${connection.engine ? html`<span class="badge">${connection.engine}</span>` : null}
      ${connection.tls ? html`<span class="badge">TLS</span>` : null}
      ${connection.reality ? html`<span class="badge">REALITY</span>` : null}
      ${connection.encrypted_vless ? html`<span class="badge">encrypted VLESS</span>` : null}
    </div>

    <section>
      <h3>Identity</h3>
      <${KV} rows=${[
        ['Address', `${connection.address}:${connection.port}`],
        ['Transport', connection.network || '—'],
        ['Import list', connection.group || '—'],
        ['Organisation group', connection.layer_group || 'Ungrouped'],
        ['Source', connection.from_subscription || detail && detail.source || 'manual import'],
        ['Credentials', connection.requires_auth ? (connection.has_credentials ? `required · ${detail && detail.credential_store === 'saved' ? 'stored encrypted' : 'kept for this session'}` : 'required · missing') : 'not required'],
        ['Health', connection.health || 'not checked'],
        ['Stable id', connection.stable_id || '—'],
      ]} />
      ${detailError ? html`<p class="notice bad">${detailError}</p>` : null}
      ${detail && (detail.warnings || []).length ? html`<ul class="bullets">${detail.warnings.map((warning) => html`<li key=${warning} class="small muted">${warning}</li>`)}</ul>` : null}
    </section>

    <section>
      <h3>Actions</h3>
      <div class="actions">
        ${serving
          ? html`<button class="btn ghost" type="button" onClick=${onConnect}>Reconnect this connection</button>`
          : html`<button class="btn primary" type="button" onClick=${onConnect}>Connect through this</button>`}
        <button class="btn ghost" type="button" disabled=${selected || readOnly} onClick=${selectNext}>Use for the next start</button>
        ${migrated && !readOnly ? html`<button class="btn ghost" type="button" onClick=${rename}>Edit display name</button>` : null}
        ${migrated && !readOnly ? html`<button class="btn ghost" type="button" onClick=${() => openDialog(html`<${MoveDialog}
          connection=${connection} groups=${groups} onClose=${closeDialog} onDone=${onRefresh} />`)}>Move to group</button>` : null}
        ${connection.requires_auth ? html`<button class="btn ghost" type="button" onClick=${() => openDialog(html`<${CredentialsDialog}
          connection=${connection} onClose=${closeDialog} onDone=${onRefresh} />`)}>${connection.has_credentials ? 'Replace credentials' : 'Set credentials'}</button>` : null}
        ${migrated && !readOnly ? html`<button class="btn ghost" type="button" onClick=${async () => {
          try {
            await api.post('/layer/hide', { ids: [connection.stable_id || connection.id], hidden: !connection.hidden });
            await loadConnections();
            toast(connection.hidden ? 'Connection shown.' : 'Connection hidden.', 'success');
          } catch (err) { toastError(err); }
        }}>${connection.hidden ? 'Show in list' : 'Hide from list'}</button>` : null}
        <button class="btn danger" type="button" onClick=${() => openDialog(html`<${DeleteConnectionDialog}
          connection=${connection} onClose=${closeDialog} onDone=${onRefresh} />`)}>Delete</button>
      </div>
      <p class="muted small">“Use for the next start” writes the saved selection but does not switch the running tunnel. Only Connect starts traffic.</p>
    </section>

    <section>
      <h3>Evidence <span class="muted small">newest first</span></h3>
      ${[relay, speed].filter(Boolean).length === 0 ? html`<p class="empty">No measurement yet. Run a relay test first; a speed test requires one.</p>` : null}
      ${[relay, speed].filter(Boolean).map((result) => html`<div class="evidence-box" key=${`${result.kind}:${result.tested_at}`}>
        <div class="row">
          <strong class="grow">${result.kind === 'speed' ? 'Download speed' : 'Relay and latency'}</strong>
          <${ResultChip} result=${result} />
        </div>
        <div class="small muted">${result.tested_at ? `${timeAgo(result.tested_at)} · ${pathKind(result)}` : ''}</div>
        ${result.status !== 'ok' ? html`<div class="small">${result.detail || reasonText(result.reason) || 'No usable evidence.'}</div>` : null}
        ${result.status === 'ok' ? html`<${KV} rows=${[
          result.kind === 'speed' ? ['Throughput', result.mbps ? `${result.mbps.toFixed(1)} Mbps` : '—'] : ['Median latency', fmtLatency(result.p50_ms || result.latency_ms)],
          result.kind === 'speed' ? ['Target', result.target || '—'] : ['p90 latency', fmtLatency(result.p90_ms)],
          ['Path proof', result.path ? `${result.path.level} · ${result.path.kind}` : '—'],
          ['Exit before', result.path && result.path.exit_ip_before],
          ['Exit after', result.path && result.path.exit_ip_after],
          ['Uplink address', result.path && result.path.uplink_ip],
          ['Serving exit', result.path && result.path.serving_exit_ip],
          ['Policy revision', result.path && result.path.policy_revision],
          ['Negative control', result.path && result.path.negative_control],
          ['Bytes counted', result.bytes ? `${result.bytes} B` : '—'],
          ['Note', result.path && result.path.note],
        ]} />` : null}
      </div>`)}
    </section>
  <//>`;
}
