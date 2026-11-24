// Sources: where connections come from. A source is an address Bypath fetches;
// deleting one deletes the connections it contributed, so it is planned first.

import { html, Banner, Empty, Skeleton, RelTime } from '../ui.js';
import { useState } from '../../vendor/hooks.module.js';
import { store, toast, toastError } from '../store.js';
import { loadSources, loadConnections, loadGroups, loadLayer, refreshStatus, refreshSubscription, refreshAllSubscriptions } from '../data.js';
import { api } from '../api.js';
import { AddSourceDialog, ImportDumpDialog, SourceDeleteDialog } from '../dialogs.js';

const closeDialog = () => store.set({ dialog: null });
const openDialog = (node) => store.set({ dialog: node });

export default function SourcesView({ state }) {
  const [busyUrl, setBusyUrl] = useState('');
  const [refreshingAll, setRefreshingAll] = useState(false);
  const subscriptions = state.subscriptions || [];
  const layer = state.layer || null;

  const refreshOne = async (subscription) => {
    setBusyUrl(subscription.url);
    try {
      await refreshSubscription(subscription);
      toast(`Refreshed ${subscription.group}.`, 'success');
    } catch (err) {
      toastError(err);
    } finally {
      setBusyUrl('');
    }
  };

  const organize = async (subscription) => {
    setBusyUrl(subscription.url);
    try {
      const result = await api.post('/subscriptions/organize', { group: subscription.group, url: subscription.url });
      await Promise.all([loadSources(), loadConnections(), loadGroups(), loadLayer(), refreshStatus()]);
      toast(`Organized into ${result.layer_group}. The tunnel and next start are unchanged.`, 'success');
    } catch (err) {
      toastError(err);
    } finally {
      setBusyUrl('');
    }
  };

  const refreshAll = async () => {
    setRefreshingAll(true);
    try {
      const result = await refreshAllSubscriptions();
      toast(`Refreshed ${result.ok} source${result.ok === 1 ? '' : 's'}${result.failed ? `; ${result.failed} failed` : ''}.`,
        result.failed ? 'warn' : 'success', 7000);
    } catch (err) {
      toastError(err);
    } finally {
      setRefreshingAll(false);
    }
  };

  return html`<div class="view-head">
    <div>
      <h1>Sources</h1>
      <div class="sub">A source is a subscription address Bypath fetches. Removing a source removes the connections it contributed; that is planned before anything changes.</div>
    </div>
    <div class="view-actions">
      <button class="btn primary" type="button" onClick=${() => openDialog(html`<${AddSourceDialog} onClose=${closeDialog}
        onDone=${() => Promise.allSettled([loadSources(), loadConnections(), loadGroups(), loadLayer(), refreshStatus()])} />`)}>Add source</button>
      <button class="btn ghost" type="button" onClick=${() => openDialog(html`<${ImportDumpDialog} onClose=${closeDialog}
        onDone=${() => Promise.allSettled([loadSources(), loadConnections(), loadGroups(), loadLayer(), refreshStatus()])} />`)}>Import dump</button>
      <button class="btn ghost" type="button" disabled=${refreshingAll || subscriptions.length === 0} onClick=${refreshAll}>
        ${refreshingAll ? 'Refreshing…' : 'Refresh all'}
      </button>
    </div>
  </div>

  ${layer && layer.migrated && layer.orphaned ? html`<${Banner} kind="info" title=${`${layer.orphaned} connection${layer.orphaned === 1 ? '' : 's'} are no longer listed by any source`}
    text="Orphaned connections stay in your list and keep working; they are not deleted by a refresh. Delete them explicitly if you no longer want them." />` : null}

  ${!state.subscriptionsLoaded ? html`<${Skeleton} rows=${3} />` : null}

  ${state.subscriptionsLoaded && subscriptions.length === 0 ? html`<${Empty} icon="⇣" title="No sources yet"
    text="Add a subscription address or paste a dump. Sources are fetched from this gateway; links are stored locally and never leave it."
    action=${html`<button class="btn primary small" type="button" onClick=${() => openDialog(html`<${AddSourceDialog}
      onClose=${closeDialog} onDone=${() => Promise.allSettled([loadSources(), loadConnections(), loadGroups(), loadLayer(), refreshStatus()])} />`)}>Add source</button>`} />` : null}

  ${subscriptions.length > 0 ? html`<div class="panel table-wrap">
    <table class="data">
      <thead>
        <tr><th>Source / default group</th><th>Address</th><th class="num">Links</th><th>Last refresh</th><th>Last error</th><th>Actions</th></tr>
      </thead>
      <tbody>
        ${subscriptions.map((subscription) => html`<tr key=${`${subscription.group}:${subscription.url}`}>
          <td><strong>${subscription.group || 'default'}</strong>
            <div class="small muted">${subscription.layer_group || 'No default group'}</div>
          </td>
          <td class="small mono" style="overflow-wrap:anywhere">${subscription.redacted_url || '—'}</td>
          <td class="num">${subscription.link_count || 0}</td>
          <td><${RelTime} iso=${subscription.last_refresh} /></td>
          <td>${subscription.last_error
            ? html`<span class="notice bad small" title=${subscription.last_error}>${subscription.last_error}</span>`
            : html`<span class="muted small">none</span>`}</td>
          <td>
            <div class="actions nowrap">
              <button class="btn ghost small" type="button" disabled=${busyUrl === subscription.url || subscription.refreshing}
                onClick=${() => refreshOne(subscription)}>${busyUrl === subscription.url ? 'Refreshing…' : 'Refresh'}</button>
              ${!subscription.layer_group_id ? html`<button class="btn ghost small" type="button"
                title=${`Organize into ${subscription.proposed_group || subscription.group}; labels only, not failover`}
                disabled=${busyUrl === subscription.url || subscription.refreshing || (layer && layer.read_only)}
                onClick=${() => organize(subscription)}>Organize into group</button>` : null}
              <button class="btn danger small" type="button" onClick=${() => openDialog(html`<${SourceDeleteDialog}
                subscription=${subscription} onClose=${closeDialog}
                onDone=${() => Promise.allSettled([loadSources(), loadConnections(), loadGroups(), loadLayer(), refreshStatus()])} />`)}>Delete</button>
            </div>
          </td>
        </tr>`)}
      </tbody>
    </table>
  </div>` : null}

  <div class="panel">
    <h2>What a refresh does</h2>
    <p class="muted">A refresh re-reads the address and adds links that are new. It never deletes a connection that disappeared from the provider: the connection becomes orphaned and stays usable until you delete it. A refresh never switches the tunnel and never changes the saved next start.</p>
    <p class="muted">New connections join the source’s default organisation group. Your moves and explicit Ungrouped choices survive refreshes. Organize adds labels without rewriting import lists or the saved next start. A group is not failover.</p>
    <p class="footnote">The full address is stored on the gateway because it usually contains a token. It is only shown redacted here and in the CLI.</p>
  </div>
`;
}
