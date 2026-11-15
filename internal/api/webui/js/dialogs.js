// Dialogs: destructive changes are always planned first and explain their
// impact. Group order is organisational only; no dialog offers failover.

import { html, Dialog, Banner, Chip, KV } from './ui.js';
import { useState, useEffect, useRef } from '../vendor/hooks.module.js';
import { api } from './api.js';
import { store } from './store.js';
import { toast, toastError, loadConnections, loadGroups, loadSources, setSelection, deleteSpeedTarget, validateSpeedTarget } from './data.js';
import { connectionName, fmtMB, reasonText, tunnelServing } from './format.js';

export function ConfirmDialog({ title, text, confirmLabel = 'Continue', danger, busy, onConfirm, onClose }) {
  return html`<${Dialog} title=${title} onClose=${onClose} footer=${html`
    <button class="btn ghost" type="button" onClick=${onClose}>Cancel</button>
    <button class="btn ${danger ? 'danger solid' : 'primary'}" type="button" disabled=${busy} onClick=${onConfirm}>${busy ? 'Working…' : confirmLabel}</button>
  `}>
    <p>${text}</p>
  <//>`;
}

export function TextDialog({ title, label, value = '', confirmLabel = 'Save', placeholder, onSubmit, onClose }) {
  const [text, setText] = useState(value);
  const [busy, setBusy] = useState(false);
  const submit = async () => {
    if (!text.trim()) { toast('Enter a value.', 'warn'); return; }
    setBusy(true);
    try {
      await onSubmit(text.trim());
      onClose();
    } catch (err) {
      toastError(err);
    } finally {
      setBusy(false);
    }
  };
  return html`<${Dialog} title=${title} onClose=${onClose} footer=${html`
    <button class="btn ghost" type="button" onClick=${onClose}>Cancel</button>
    <button class="btn primary" type="button" disabled=${busy} onClick=${submit}>${busy ? 'Saving…' : confirmLabel}</button>
  `}>
    <label>${label}
      <input type="text" value=${text} placeholder=${placeholder || ''} onInput=${(e) => setText(e.target.value)} autofocus />
    </label>
  <//>`;
}

export function GroupDialog({ group, groups, onClose, onDone }) {
  const editing = !!group;
  const [name, setName] = useState(group ? group.name : '');
  const [busy, setBusy] = useState(false);
  const [acknowledge, setAcknowledge] = useState(false);
  const [replacement, setReplacement] = useState('');
  const members = (group && group.members) || [];
  const memberIds = (group && group.member_ids) || [];
  const state = store.get();
  const status = state.status || {};
  const selection = status.selection || {};
  const servingId = tunnelServing(status) ? (selection.serving_id || status.active_id || '') : '';
  const selectedId = selection.selected_id || '';
  const servingMember = members.some((m) => m.id === servingId || m.connection_id === servingId);
  const selectedMember = members.some((m) => m.id === selectedId || m.connection_id === selectedId);
  const candidates = (state.connections || []).filter((c) => c.stable_id && !c.hidden && !memberIds.includes(c.stable_id));
  const canDeleteMembers = memberIds.length === 0 || (!servingMember
    && (!selectedMember || acknowledge || (!!replacement && memberIds.indexOf(replacement) < 0)));

  const save = async () => {
    if (!name.trim()) { toast('Give the group a name.', 'warn'); return; }
    setBusy(true);
    try {
      if (editing) {
        if (name.trim() !== group.name) await api.post('/layer/groups/rename', { id: group.id, name: name.trim() });
      } else {
        await api.post('/layer/groups/create', { name: name.trim() });
      }
      await Promise.all([loadGroups(), loadConnections()]);
      toast(editing ? 'Group saved.' : 'Group created.', 'success');
      onDone();
      onClose();
    } catch (err) {
      toastError(err);
    } finally {
      setBusy(false);
    }
  };

  const deleteGroup = async () => {
    setBusy(true);
    try {
      await api.post('/layer/groups/delete', { id: group.id, delete_members: false, options: {} });
      await Promise.all([loadGroups(), loadConnections()]);
      toast('Group deleted; its connections are kept.', 'success');
      onDone();
      onClose();
    } catch (err) {
      toastError(err);
      setBusy(false);
    }
  };

  const deleteMembers = async () => {
    setBusy(true);
    try {
      await api.post('/layer/groups/delete', {
        id: group.id,
        delete_members: true,
        options: { replace_with_id: replacement || '', acknowledge_unset: acknowledge },
      });
      await Promise.all([loadGroups(), loadConnections()]);
      toast(`Group and ${memberIds.length} connection${memberIds.length === 1 ? '' : 's'} deleted.`, 'success');
      onDone();
      onClose();
    } catch (err) {
      toastError(err);
      setBusy(false);
    }
  };

  return html`<${Dialog} title=${editing ? `Edit group ${group.name}` : 'New group'} onClose=${onClose} footer=${html`
    <button class="btn ghost" type="button" onClick=${onClose}>Cancel</button>
    <button class="btn primary" type="button" disabled=${busy} onClick=${save}>${busy ? 'Saving…' : editing ? 'Save name' : 'Create group'}</button>
  `}>
    <p class="muted">Groups organise your connections. Their order is only the order you see; it never causes failover or a tunnel switch.</p>
    <label>Group name
      <input type="text" value=${name} onInput=${(e) => setName(e.target.value)} autofocus maxlength="64" />
    </label>
    ${editing ? html`<section class="stack">
      <h3>Members <span class="muted small">${memberIds.length} connection${memberIds.length === 1 ? '' : 's'} · order is not failover</span></h3>
      ${memberIds.length === 0 ? html`<p class="empty">This group has no members yet. Move connections into it from Connections.</p>` : html`
        <div class="clist">
          ${members.map((member, index) => html`<div class="rule-row" key=${member.id}>
            <span class="mono small">${index + 1}</span>
            <span class="grow">${member.display_name || member.remark}</span>
            ${member.id === servingId || member.connection_id === servingId ? html`<${Chip} state="serving" label="serving" />` : null}
            ${member.id === selectedId || member.connection_id === selectedId ? html`<span class="badge">next start</span>` : null}
          </div>`)}
        </div>`}
    </section>` : null}
    ${editing ? html`<div class="panel" style="padding:12px">
      <h3>Delete this group</h3>
      <p class="muted small">Deleting the group alone keeps its connections and moves them out of any group. Deleting the group and its members removes ${memberIds.length} connection${memberIds.length === 1 ? '' : 's'} permanently.</p>
      <div class="stack">
        ${servingMember ? html`<${Banner} kind="bad" title="A member is serving traffic"
          text="Switch to another connection before deleting the members. The serving connection can never be deleted. You can still delete the empty group." />` : null}
        ${!servingMember && selectedMember ? html`<${Banner} kind="warn" title="A member is the saved next start"
          text="Choose a replacement, or explicitly acknowledge leaving the next start unset." />` : null}
        ${!servingMember && selectedMember ? html`<div class="stack">
          <label>Replacement for the next start
            <select value=${replacement} onChange=${(e) => { setReplacement(e.target.value); if (e.target.value) setAcknowledge(false); }}>
              <option value="">Choose a connection…</option>
              ${candidates.map((c) => html`<option key=${c.id} value=${c.stable_id}>${connectionName(c)}</option>`)}
            </select>
          </label>
          <label class="check">
            <input type="checkbox" checked=${acknowledge} onChange=${(e) => { setAcknowledge(e.target.checked); if (e.target.checked) setReplacement(''); }} />
            Leave the next start unset: Bypath will pick a connection by itself on the next start.
          </label>
        </div>` : null}
      </div>
      <div class="actions">
        <button class="btn danger small" type="button" disabled=${busy} onClick=${deleteGroup}>Delete group only</button>
        <button class="btn danger solid small" type="button" disabled=${busy || !canDeleteMembers} onClick=${deleteMembers}>Delete group and ${memberIds.length} connection${memberIds.length === 1 ? '' : 's'}</button>
      </div>
      <p class="footnote">Deleting members is permanent for these connections. A provider that still lists them can bring them back on the next source refresh.</p>
    </div>` : null}
  <//>`;
}

export function MoveDialog({ connection, groups, onClose, onDone }) {
  const [target, setTarget] = useState(connection.layer_group_id || '');
  const [busy, setBusy] = useState(false);
  const save = async () => {
    setBusy(true);
    try {
      await api.post('/layer/move', { ids: [connection.stable_id || connection.id], group_id: target });
      await Promise.all([loadGroups(), loadConnections()]);
      toast('Connection moved. Order is not failover.', 'success');
      onDone();
      onClose();
    } catch (err) {
      toastError(err);
    } finally {
      setBusy(false);
    }
  };
  return html`<${Dialog} title=${`Move ${connectionName(connection)}`} onClose=${onClose} footer=${html`
    <button class="btn ghost" type="button" onClick=${onClose}>Cancel</button>
    <button class="btn primary" type="button" disabled=${busy} onClick=${save}>${busy ? 'Moving…' : 'Move'}</button>
  `}>
    <p class="muted">Moving a connection changes only its organisation. It never switches the tunnel or the saved next start.</p>
    <label>Destination group
      <select value=${target} onChange=${(e) => setTarget(e.target.value)}>
        <option value="">Ungrouped</option>
        ${groups.filter((g) => g.id !== '').map((g) => html`<option key=${g.id} value=${g.id}>${g.name}</option>`)}
      </select>
    </label>
  <//>`;
}

export function DeleteConnectionDialog({ connection, onClose, onDone }) {
  const [plan, setPlan] = useState(null);
  const [error, setError] = useState('');
  const [replacement, setReplacement] = useState('');
  const [acknowledge, setAcknowledge] = useState(false);
  const [busy, setBusy] = useState(false);
  const [connections, setConnections] = useState([]);

  useEffect(() => {
    let live = true;
    api.get(`/connections/delete-plan?id=${encodeURIComponent(connection.id)}`)
      .then((impact) => { if (live) setPlan(impact); })
      .catch((err) => { if (live) setError(err.message); });
    loadConnections().then((list) => {
      if (live) setConnections((list || []).filter((c) => c.id !== connection.id && !c.hidden));
    }).catch(() => {});
    return () => { live = false; };
  }, [connection.id]);

  const blocked = plan && (!plan.allowed || plan.serving);
  const needsChoice = plan && plan.requires_replacement && !plan.serving;
  const canDelete = !blocked && (!needsChoice || !!replacement || acknowledge);

  const remove = async () => {
    setBusy(true);
    try {
      await api.post('/connections/delete', {
        id: connection.id,
        options: { replace_with_id: replacement || '', acknowledge_unset: acknowledge },
      });
      await Promise.all([loadConnections(), loadGroups()]);
      toast('Connection deleted.', 'success');
      onDone();
      onClose();
    } catch (err) {
      toastError(err);
    } finally {
      setBusy(false);
    }
  };

  return html`<${Dialog} title=${`Delete ${connectionName(connection)}`} onClose=${onClose} footer=${html`
    <button class="btn ghost" type="button" onClick=${onClose}>Cancel</button>
    <button class="btn danger solid" type="button" disabled=${busy || !canDelete} onClick=${remove}>${busy ? 'Deleting…' : 'Delete connection'}</button>
  `}>
    ${error ? html`<${Banner} kind="bad" title="Could not read the delete plan" text=${error} />` : null}
    ${!plan && !error ? html`<p class="muted">Checking what this delete would affect…</p>` : null}
    ${plan ? html`<div class="stack">
      ${plan.serving ? html`<${Banner} kind="bad" title="This connection is serving traffic" text="Switch to another connection first. The serving connection can never be deleted." />` : null}
      ${!plan.allowed && !plan.serving ? html`<${Banner} kind="bad" title="Deletion refused" text=${plan.message || 'The gateway refused this delete.'} />` : null}
      ${plan.selected && !plan.serving ? html`<${Banner} kind="warn" title="This connection is the saved next start" text="Deleting it without a replacement would leave the next start unset. Choose a replacement, or explicitly acknowledge leaving it unset." />` : null}
      ${needsChoice ? html`<div class="stack">
        <label>Replacement for the next start
          <select value=${replacement} onChange=${(e) => { setReplacement(e.target.value); if (e.target.value) setAcknowledge(false); }}>
            <option value="">Choose a connection…</option>
            ${connections.map((c) => html`<option key=${c.id} value=${c.id}>${connectionName(c)}</option>`)}
          </select>
        </label>
        <label class="check">
          <input type="checkbox" checked=${acknowledge} onChange=${(e) => { setAcknowledge(e.target.checked); if (e.target.checked) setReplacement(''); }} />
          Leave the next start unset: Bypath will pick a connection by itself on the next start.
        </label>
      </div>` : null}
      <${KV} rows=${[
        ['Impact', plan.message || (plan.serving ? 'refused' : 'removes one connection')],
        ['Saved next start', plan.selection && plan.selection.state ? plan.selection.state : '—'],
      ]} />
      <p class="muted small">This is permanent for a single connection. A provider that still lists it can bring it back on the next source refresh.</p>
    </div>` : null}
  <//>`;
}

export function SourceDeleteDialog({ subscription, onClose, onDone }) {
  const [plan, setPlan] = useState(null);
  const [error, setError] = useState('');
  const [replacement, setReplacement] = useState('');
  const [acknowledge, setAcknowledge] = useState(false);
  const [connections, setConnections] = useState([]);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let live = true;
    api.get(`/subscriptions/delete-plan?group=${encodeURIComponent(subscription.group)}&url=${encodeURIComponent(subscription.url)}`)
      .then((impact) => { if (live) setPlan(impact); })
      .catch((err) => { if (live) setError(err.message); });
    loadConnections().then((list) => { if (live) setConnections(list || []); }).catch(() => {});
    return () => { live = false; };
  }, [subscription.group, subscription.url]);

  const blocked = plan && (!plan.allowed || plan.serving);
  const needsChoice = plan && plan.requires_replacement && !plan.serving;
  const canDelete = !blocked && (!needsChoice || !!replacement || acknowledge);

  const remove = async () => {
    setBusy(true);
    try {
      await api.post('/subscriptions/delete', {
        group: subscription.group,
        url: subscription.url,
        options: { replace_with_id: replacement || '', acknowledge_unset: acknowledge },
      });
      await Promise.all([loadSources(), loadConnections()]);
      toast('Source deleted.', 'success');
      onDone();
      onClose();
    } catch (err) {
      toastError(err);
    } finally {
      setBusy(false);
    }
  };

  return html`<${Dialog} title="Delete source" onClose=${onClose} footer=${html`
    <button class="btn ghost" type="button" onClick=${onClose}>Cancel</button>
    <button class="btn danger solid" type="button" disabled=${busy || !canDelete} onClick=${remove}>${busy ? 'Deleting…' : 'Delete source and its connections'}</button>
  `}>
    ${error ? html`<${Banner} kind="bad" title="Could not read the delete plan" text=${error} />` : null}
    ${!plan && !error ? html`<p class="muted">Checking what this source contributes…</p>` : null}
    ${plan ? html`<div class="stack">
      <p>${plan.redacted_url}</p>
      ${plan.serving ? html`<${Banner} kind="bad" title="This source contains the serving connection" text="Switch to another connection first." />` : null}
      ${!plan.allowed && !plan.serving ? html`<${Banner} kind="bad" title="Deletion refused" text=${plan.message || 'The gateway refused this delete.'} />` : null}
      ${plan.selected && !plan.serving ? html`<${Banner} kind="warn" title="This source contains the saved next-start connection" text="Choose a replacement, or explicitly acknowledge leaving the next start unset." />` : null}
      ${needsChoice ? html`<div class="stack">
        <label>Replacement for the next start
          <select value=${replacement} onChange=${(e) => { setReplacement(e.target.value); if (e.target.value) setAcknowledge(false); }}>
            <option value="">Choose a connection…</option>
            ${connections.filter((c) => !plan.stable_ids.includes(c.stable_id)).map((c) => html`<option key=${c.id} value=${c.id}>${connectionName(c)}</option>`)}
          </select>
        </label>
        <label class="check">
          <input type="checkbox" checked=${acknowledge} onChange=${(e) => { setAcknowledge(e.target.checked); if (e.target.checked) setReplacement(''); }} />
          Leave the next start unset: Bypath will pick a connection by itself on the next start.
        </label>
      </div>` : null}
      <${KV} rows=${[
        ['Connections removed', String(plan.connection_count || 0)],
        ['Impact', plan.message || '—'],
      ]} />
    </div>` : null}
  <//>`;
}

export function CredentialsDialog({ connection, onClose, onDone }) {
  const username = useRef(null);
  const password = useRef(null);
  const save = useRef(null);
  const [busy, setBusy] = useState(false);
  const submit = async () => {
    if (!username.current.value.trim()) { toast('Enter a username.', 'warn'); return; }
    setBusy(true);
    try {
      await api.post('/connections/credentials', {
        id: connection.id,
        username: username.current.value.trim(),
        password: password.current.value,
        save: !!save.current.checked,
      });
      toast('Credentials stored.', 'success');
      await loadConnections();
      onDone();
      onClose();
    } catch (err) {
      toastError(err);
    } finally {
      setBusy(false);
    }
  };
  return html`<${Dialog} title=${`Credentials for ${connectionName(connection)}`} onClose=${onClose} footer=${html`
    <button class="btn ghost" type="button" onClick=${onClose}>Cancel</button>
    <button class="btn primary" type="button" disabled=${busy} onClick=${submit}>${busy ? 'Saving…' : 'Save credentials'}</button>
  `}>
    <p class="muted">Credentials are stored encrypted, or kept only for this gateway session. They are never shown again.</p>
    <label>Username <input ref=${username} type="text" autocomplete="off" /></label>
    <label>Password <input ref=${password} type="password" autocomplete="off" /></label>
    <label class="check"><input ref=${save} type="checkbox" /> Save encrypted on this machine</label>
  <//>`;
}

export function ImportURIDialog({ groups, onClose, onDone }) {
  const group = useRef(null);
  const uri = useRef(null);
  const [busy, setBusy] = useState(false);
  const run = async () => {
    if (!uri.current.value.trim()) { toast('Paste a link first.', 'warn'); return; }
    setBusy(true);
    try {
      const result = await api.post('/connections/import', {
        group: (group.current.value || '').trim() || 'default',
        uri: uri.current.value.trim(),
      });
      const created = (result.created || []).length;
      const skipped = (result.skipped || []).length;
      toast(`Imported ${created} link${created === 1 ? '' : 's'}${skipped ? `, skipped ${skipped} duplicate${skipped === 1 ? '' : 's'}` : ''}.`, 'success', 7000);
      await Promise.all([loadConnections(), loadGroups()]);
      onDone();
      onClose();
    } catch (err) {
      toastError(err);
    } finally {
      setBusy(false);
    }
  };
  return html`<${Dialog} title="Import link" onClose=${onClose} footer=${html`
    <button class="btn ghost" type="button" onClick=${onClose}>Cancel</button>
    <button class="btn primary" type="button" disabled=${busy} onClick=${run}>${busy ? 'Importing…' : 'Import'}</button>
  `}>
    <p class="muted">Paste a VLESS, VMess, Trojan or Shadowsocks link. Encrypted VLESS and REALITY parameters are preserved.</p>
    <label>Import list
      <input ref=${group} type="text" list="group-names" value="default" />
      <datalist id="group-names">${groups.map((g) => html`<option key=${g.id} value=${g.name}></option>`)}</datalist>
    </label>
    <label>Link <textarea ref=${uri} rows="5" placeholder="vless://…"></textarea></label>
  <//>`;
}

export function ImportOVPNDialog({ groups, onClose, onDone }) {
  const group = useRef(null);
  const name = useRef(null);
  const profile = useRef(null);
  const refs = useRef(null);
  const username = useRef(null);
  const password = useRef(null);
  const save = useRef(null);
  const [preview, setPreview] = useState(null);
  const [needsCreds, setNeedsCreds] = useState(false);
  const [busy, setBusy] = useState(false);

  const collect = async () => {
    const file = profile.current.files[0];
    if (!file) throw new Error('Choose an OpenVPN profile file first.');
    if (file.size > 1024 * 1024) throw new Error('The profile is larger than 1 MiB.');
    const text = await file.text();
    if (!text.trim()) throw new Error('The selected profile is empty.');
    const files = Array.from(refs.current.files || []);
    if (files.length > 24) throw new Error('At most 24 referenced files are accepted.');
    let total = 0;
    const uploaded = [];
    const seen = new Set();
    for (const referenced of files) {
      if (!/^[A-Za-z0-9._-]+$/.test(referenced.name)) throw new Error(`"${referenced.name}" is not a plain file name.`);
      if (seen.has(referenced.name.toLowerCase())) throw new Error(`"${referenced.name}" was selected twice.`);
      seen.add(referenced.name.toLowerCase());
      if (referenced.size > 512 * 1024) throw new Error(`"${referenced.name}" is larger than 512 KiB.`);
      total += referenced.size;
      if (total > 4 * 1024 * 1024) throw new Error('Referenced files exceed 4 MiB in total.');
      uploaded.push({ name: referenced.name, content: await referenced.text() });
    }
    const payload = {
      group: (group.current.value || '').trim() || 'default',
      name: (name.current.value || '').trim(),
      text,
      refs: uploaded,
    };
    if (username.current.value.trim()) {
      payload.username = username.current.value.trim();
      payload.password = password.current.value;
      payload.save_credentials = !!save.current.checked;
    }
    return payload;
  };

  const runPreview = async () => {
    setBusy(true);
    try {
      const payload = await collect();
      setPreview(await api.post('/connections/ovpn/preview', payload));
    } catch (err) {
      toastError(err);
    } finally {
      setBusy(false);
    }
  };

  const runImport = async () => {
    setBusy(true);
    try {
      const payload = await collect();
      const result = await api.post('/connections/ovpn/import', payload);
      const created = (result.created || []).length;
      for (const item of result.skipped || []) toast(`${item.name}: ${item.reason}`, 'warn', 9000);
      if (created) toast(`Imported "${payload.name || 'OpenVPN profile'}".`, 'success');
      await Promise.all([loadConnections(), loadGroups()]);
      onDone();
      onClose();
    } catch (err) {
      if (err.code === 'credentials_required') setNeedsCreds(true);
      toastError(err);
    } finally {
      setBusy(false);
    }
  };

  return html`<${Dialog} title="Import OpenVPN profile" onClose=${onClose} wide=${true} footer=${html`
    <button class="btn ghost" type="button" onClick=${onClose}>Cancel</button>
    <button class="btn ghost" type="button" disabled=${busy} onClick=${runPreview}>Preview</button>
    <button class="btn primary" type="button" disabled=${busy} onClick=${runImport}>${busy ? 'Working…' : 'Import'}</button>
  `}>
    <p class="muted">Upload the profile and the files it references. This panel never accepts server file paths; certificate and key contents are inlined into owner-only storage.</p>
    <div class="grid2">
      <label>Import list <input ref=${group} type="text" list="group-names-ovpn" value="default" />
        <datalist id="group-names-ovpn">${groups.map((g) => html`<option key=${g.id} value=${g.name}></option>`)}</datalist>
      </label>
      <label>Display name (optional) <input ref=${name} type="text" /></label>
    </div>
    <label>Profile file (.ovpn) <input ref=${profile} type="file" accept=".ovpn,.conf" /></label>
    <label>Referenced files (ca, cert, key, tls-auth) <input ref=${refs} type="file" multiple /></label>
    <div class=${needsCreds ? 'panel' : 'panel hidden'} style="padding:12px">
      <h3>Credentials required</h3>
      <div class="grid2">
        <label>Username <input ref=${username} type="text" autocomplete="off" /></label>
        <label>Password <input ref=${password} type="password" autocomplete="off" /></label>
      </div>
      <label class="check"><input ref=${save} type="checkbox" /> Save credentials encrypted on this machine</label>
    </div>
    ${preview ? html`<div class="evidence-box">
      <h4>Profile preview</h4>
      <${KV} rows=${[
        ['Name', preview.name],
        ['Server', `${preview.host}:${preview.port}`],
        ['Transport', preview.network],
        ['Username required', preview.requires_auth ? 'yes' : 'no'],
        ['Inline credentials', preview.has_inline_auth ? 'yes' : 'no'],
        ['Referenced files', (preview.cert_files || []).join(', ')],
        ['Warnings', (preview.warnings || []).join('; ')],
      ]} />
    </div>` : null}
  <//>`;
}

export function AddSourceDialog({ onClose, onDone }) {
  const url = useRef(null);
  const group = useRef(null);
  const [preview, setPreview] = useState(null);
  const [busy, setBusy] = useState(false);
  const runPreview = async () => {
    if (!url.current.value.trim()) { toast('Enter a source address.', 'warn'); return; }
    setBusy(true);
    try {
      setPreview(await api.post('/subscriptions/preview', { url: url.current.value.trim() }));
    } catch (err) {
      toastError(err);
    } finally {
      setBusy(false);
    }
  };
  const add = async () => {
    if (!url.current.value.trim()) { toast('Enter a source address.', 'warn'); return; }
    setBusy(true);
    try {
      const added = await api.post('/subscriptions/add', { url: url.current.value.trim(), group: (group.current.value || '').trim() });
      toast('Source added. Fetching its connections…', 'info');
      try {
        await api.post('/subscriptions/refresh', { group: added.group, url: added.url });
        toast('Source refreshed.', 'success');
      } catch (err) {
        toast(`Source stored, but the first refresh failed: ${err.message}`, 'warn', 9000);
      }
      await Promise.all([loadSources(), loadConnections()]);
      onDone();
      onClose();
    } catch (err) {
      toastError(err);
    } finally {
      setBusy(false);
    }
  };
  return html`<${Dialog} title="Add source" onClose=${onClose} footer=${html`
    <button class="btn ghost" type="button" onClick=${onClose}>Cancel</button>
    <button class="btn ghost" type="button" disabled=${busy} onClick=${runPreview}>Preview</button>
    <button class="btn primary" type="button" disabled=${busy} onClick=${add}>${busy ? 'Adding…' : 'Add source'}</button>
  `}>
    <p class="muted">The address is stored on this gateway. It is only shown redacted here and in the CLI.</p>
    <label>Source address <input ref=${url} type="text" placeholder="https://panel.example/sub/…" /></label>
    <label>Organisation group (optional override) <input ref=${group} type="text" maxlength="64" placeholder=${preview ? preview.group : 'Proposed from the URL name or host'} /></label>
    <p class="muted small">A matching group is created by default; name collisions get a numbered suffix. Only new connections join it. Refresh preserves moves and explicit Ungrouped choices. This is not failover.</p>
    ${preview ? html`<div class="evidence-box">
      <h4>Preview</h4>
      <${KV} rows=${[
        ['Proposed group', preview.group],
        ['Address', preview.redacted_url],
        ['Connections', String(preview.total)],
        ['Duplicates', String(preview.duplicates)],
        ['Rejected lines', String(preview.rejected_count || 0)],
        ['Truncated', preview.truncated ? 'yes' : 'no'],
      ]} />
      ${(preview.links || []).length === 0 ? html`<p class="notice">This source contains no usable links.</p>` : null}
      ${(preview.links || []).slice(0, 8).map((link) => html`<div class="small muted" key=${link.remark}>${link.remark} — ${link.protocol} ${link.address}:${link.port}</div>`)}
      ${(preview.rejected || []).map((item) => html`<div class="small muted" key=${`rejected-${item.line}`}>Line ${item.line} — ${reasonText(item.category)}: ${item.message}</div>`)}
    </div>` : null}
  <//>`;
}

export function ImportDumpDialog({ onClose, onDone }) {
  const group = useRef(null);
  const text = useRef(null);
  const file = useRef(null);
  const [busy, setBusy] = useState(false);
  const [report, setReport] = useState(null);
  const loadFile = async (event) => {
    const selected = event.target.files[0];
    if (selected) text.current.value = await selected.text();
  };
  const run = async () => {
    if (!text.current.value.trim()) { toast('Paste or choose a dump first.', 'warn'); return; }
    setBusy(true);
    try {
      const result = await api.post('/subscriptions/import', {
        group: (group.current.value || '').trim(),
        text: text.current.value,
      });
      const created = (result.created || []).length;
      const skipped = (result.skipped || []).length;
      const rejected = (result.diagnostics || []).length;
      toast(`Imported ${created} link${created === 1 ? '' : 's'}${skipped ? `, skipped ${skipped}` : ''}${rejected ? `, ${rejected} line${rejected === 1 ? '' : 's'} rejected` : ''}.`, rejected ? 'warn' : 'success', 7000);
      await Promise.all([loadSources(), loadConnections()]);
      onDone();
      if (rejected) {
        setReport(result);
        setBusy(false);
        return;
      }
      onClose();
    } catch (err) {
      toastError(err);
    } finally {
      setBusy(false);
    }
  };
  return html`<${Dialog} title="Import dump" onClose=${onClose} footer=${html`
    <button class="btn ghost" type="button" onClick=${onClose}>${report ? 'Close' : 'Cancel'}</button>
    <button class="btn primary" type="button" disabled=${busy} onClick=${run}>${busy ? 'Importing…' : 'Import'}</button>
  `}>
    <label>Organisation group (optional override) <input ref=${group} type="text" maxlength="64" placeholder="imported (numbered if already used)" /></label>
    <p class="muted small">Only newly imported connections join this group. Existing connections and the saved next start are unchanged. Groups are not failover.</p>
    <label>Dump file (optional) <input ref=${file} type="file" accept=".txt,.conf,text/plain" onChange=${loadFile} /></label>
    <label>Links <textarea ref=${text} rows="9" placeholder="Paste a subscription dump (one link per line)"></textarea></label>
    ${report ? html`<div class="evidence-box">
      <h4>Import result</h4>
      <${KV} rows=${[
        ['Group', report.group],
        ['Imported', String((report.created || []).length)],
        ['Skipped duplicates', String((report.skipped || []).length)],
        ['Rejected lines', String((report.diagnostics || []).length)],
      ]} />
      ${(report.skipped || []).map((item) => html`<div class="small muted" key=${`skip-${item.name}`}>Skipped ${item.name}: ${item.reason}</div>`)}
      ${(report.diagnostics || []).map((item) => html`<div class="small muted" key=${`rejected-${item.line}`}>Line ${item.line} — ${reasonText(item.category)}: ${item.message}</div>`)}
    </div>` : null}
  <//>`;
}

export function BudgetDialog({ request, onClose, onStart }) {
  const [budget, setBudget] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [usage, setUsage] = useState(null);

  useEffect(() => {
    let live = true;
    api.post('/tests/budget', request)
      .then((b) => { if (live) setBudget(b); })
      .catch((err) => { if (live) setError(err.message); });
    api.get('/tests/usage').then((u) => { if (live) setUsage(u); }).catch(() => {});
    return () => { live = false; };
  }, [request]);

  const start = async () => {
    setBusy(true);
    try {
      await onStart();
      onClose();
    } catch (err) {
      toastError(err);
      setBusy(false);
    }
  };

  const cap = budget ? (budget.monthly_cap_mb || 0) : 0;
  const usedMB = budget ? (budget.month_used_mb || 0) : 0;
  const overBudget = cap > 0 && !!budget && usedMB + budget.worst_case_mb > cap;
  const routeKind = budget && budget.route_check === 'DIRECT' ? 'direct' : budget && budget.route_check ? 'proxy' : '';

  return html`<${Dialog} title="Speed test budget" onClose=${onClose} footer=${html`
    <button class="btn ghost" type="button" onClick=${onClose}>Cancel</button>
    <button class="btn primary" type="button" disabled=${busy || !budget || overBudget} onClick=${start}>${busy ? 'Starting…' : 'Start speed test'}</button>
  `}>
    ${error ? html`<${Banner} kind="bad" title="Could not prepare the budget" text=${error} />` : null}
    ${!budget && !error ? html`<p class="muted">Checking the target and the traffic budget…</p>` : null}
    ${budget ? html`<div class="stack">
      <${Banner} kind=${overBudget ? 'bad' : 'info'}
        title=${overBudget ? 'Monthly budget would be exceeded' : 'Worst case before starting'}
        text=${overBudget
          ? `This run could use ${budget.worst_case_mb} MB on top of ${usedMB} MB already counted this month; the cap is ${cap} MB.`
          : `At most ${budget.worst_case_mb} MB, across ${budget.links} connection${budget.links === 1 ? '' : 's'}.`} />
      <${KV} rows=${[
        ['Target host', budget.target],
        ['Target address', budget.target_url],
        ['Route check', budget.route_check ? html`<span class="route-outcome ${routeKind}">${budget.route_check}</span>` : (budget.check_note || '—')],
        ['Per connection cap', `${budget.per_link_mb} MB`],
        ['Per batch cap', `${budget.per_batch_mb} MB`],
        ['Worst case', `${budget.worst_case_mb} MB`],
        ['Monthly cap', cap ? `${cap} MB (${usedMB} MB used)` : 'not set'],
        ['Upload testing', budget.upload_enabled ? 'enabled' : 'disabled — download only'],
        ['Order', 'serial, one connection at a time'],
      ]} />
      ${budget.check_note ? html`<p class="notice info">${budget.check_note}</p>` : null}
      <p class="muted small">A speed result requires a proven relay result for the same connection. Connections without one are skipped, not measured.</p>
      <p class="footnote">Counted bytes are payload read by Bypath. Protocol overhead and retransmissions are not included, so real link usage is higher. ${usage && usage.label ? usage.label : ''}</p>
    </div>` : null}
  <//>`;
}

export function StopDaemonDialog({ onClose }) {
  const [text, setText] = useState('');
  const [busy, setBusy] = useState(false);
  const stop = async () => {
    if (text.trim().toLowerCase() !== 'stop') { toast('Type “stop” to confirm.', 'warn'); return; }
    setBusy(true);
    try {
      const result = await api.post('/shutdown');
      toast(result.message || 'Daemon shutdown requested.', 'warn', 9000);
      onClose();
    } catch (err) {
      toastError(err);
      setBusy(false);
    }
  };
  return html`<${Dialog} title="Stop the Bypath daemon" onClose=${onClose} footer=${html`
    <button class="btn ghost" type="button" onClick=${onClose}>Cancel</button>
    <button class="btn danger solid" type="button" disabled=${busy || text.trim().toLowerCase() !== 'stop'} onClick=${stop}>${busy ? 'Stopping…' : 'Stop daemon'}</button>
  `}>
    <${Banner} kind="bad" title="The panel and CLI become unreachable" text="This stops the tunnel and the management service. You must start Bypath again on the host to recover access." />
    <label>Type “stop” to confirm
      <input type="text" value=${text} onInput=${(e) => setText(e.target.value)} autocomplete="off" />
    </label>
  <//>`;
}

export function TargetAddDialog({ onClose }) {
  const url = useRef(null);
  const [busy, setBusy] = useState(false);
  const add = async () => {
    if (!url.current.value.trim()) { toast('Enter an https URL.', 'warn'); return; }
    setBusy(true);
    try {
      const target = await api.post('/tests/targets', { url: url.current.value.trim() });
      toast(`Target added: ${target.host}`, 'success');
      onClose();
    } catch (err) {
      toastError(err);
    } finally {
      setBusy(false);
    }
  };
  return html`<${Dialog} title="Add download target" onClose=${onClose} footer=${html`
    <button class="btn ghost" type="button" onClick=${onClose}>Cancel</button>
    <button class="btn primary" type="button" disabled=${busy} onClick=${add}>${busy ? 'Adding…' : 'Add target'}</button>
  `}>
    <p class="muted">Only public https URLs on port 443 are accepted. The host is resolved and every address is checked before a run; redirects and private addresses are refused.</p>
    <label>Target URL <input ref=${url} type="text" placeholder="https://example.com/download.bin" /></label>
    <p class="footnote">Do not use a host that the routing policy sends DIRECT: a DIRECT download says nothing about the tunnel.</p>
  <//>`;
}

export function TargetDeleteDialog({ target, onClose }) {
  return html`<${ConfirmDialog} title="Delete download target" danger=${true}
    text=${`Remove ${target.host} from the speed-test registry? Results already recorded are kept.`}
    confirmLabel="Delete target" onClose=${onClose}
    onConfirm=${async () => {
      try { await deleteSpeedTarget(target.id); toast('Target deleted.', 'success'); onClose(); }
      catch (err) { toastError(err); }
    }} />`;
}

export { validateSpeedTarget, setSelection, reasonText, fmtMB };
