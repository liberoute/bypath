// The selection banner. Every state is read-only information derived from the
// gateway; a button here is the only way to change the saved next start, and it
// always names what it changes.

import { html, Banner } from './ui.js';
import { navigate } from './nav.js';
import { connectTo, setSelection, dismissSwitchSheet } from './data.js';
import { toastError, store } from './store.js';
import { utcStamp, tunnelServing } from './format.js';
import { useState, useEffect } from '../vendor/hooks.module.js';

export function selectionOf(status) {
  return (status && status.selection) || null;
}

export function selectionState(status) {
  const selection = selectionOf(status);
  return selection && selection.state ? selection.state : '';
}

function chooseConnection() {
  navigate('connections');
}

async function makeServe(id) {
  dismissSwitchSheet();
  try {
    await connectTo(id);
  } catch (err) {
    toastError(err);
  }
}

async function useAsNextStart(id) {
  try {
    await setSelection(id);
  } catch (err) {
    toastError(err);
  }
}

function usePanelState() {
  const [state, setState] = useState(store.get());
  useEffect(() => store.subscribe(setState), []);
  return state;
}

export function SelectionBanner({ compact = false }) {
  const state = usePanelState();
  const status = state.status;
  if (!status) return null;
  const selection = selectionOf(status) || {};
  const kind = selectionState(status);
  if (!kind || kind === 'S-OK') return null;
  const running = tunnelServing(status);
  const nameOf = (id) => {
    const connection = (state.connections || []).find((item) => item.stable_id === id || item.id === id);
    return connection ? (connection.display_name || connection.remark) : '';
  };

  if (kind === 'S-DIFF') {
    const nextName = selection.selected_remark || nameOf(selection.selected_id) || 'another connection';
    const serving = selection.serving_remark || nameOf(selection.serving_id) || 'the current connection';
    return html`<${Banner} kind="warn"
      title=${`Serving ${serving} · Next start: ${nextName}`}
      text="The tunnel is serving a different connection than the saved next start. A restart will use the saved one."
      actions=${html`
        ${selection.selected_id ? html`<button class="btn primary small" type="button" onClick=${() => makeServe(selection.selected_id)}>Make ${nextName} serve now</button>` : null}
        ${selection.serving_id ? html`<button class="btn ghost small" type="button" onClick=${() => useAsNextStart(selection.serving_id)}>Use ${serving} for the next start</button>` : null}
        <button class="btn ghost small" type="button" onClick=${chooseConnection}>Choose connection</button>
      `} />`;
  }

  if (kind === 'S-DANGLING') {
    return html`<${Banner} kind="bad" title="The saved next-start connection no longer exists"
      text=${selection.message || 'On the next start Bypath will choose a connection unpredictably from your import lists.'}
      actions=${html`<button class="btn primary small" type="button" onClick=${chooseConnection}>Choose connection</button>`} />`;
  }

  if (kind === 'S-UNSET') {
    return html`<${Banner} kind="warn" title="Next start: not set"
      text=${running
        ? 'Bypath will pick a connection by itself on the next start. The tunnel is running now, so nothing changes until it restarts.'
        : 'Bypath will pick a connection by itself on the next start. Choose one to make the next start predictable.'}
      actions=${html`<button class="btn primary small" type="button" onClick=${chooseConnection}>Choose connection</button>`} />`;
  }

  if (kind === 'S-AUTO') {
    const chosen = selection.selected_remark || nameOf(selection.selected_id) || 'a connection';
    const when = state.layer && state.layer.last_selection_at ? ` at ${utcStamp(state.layer.last_selection_at)}` : '';
    return html`<${Banner} kind="info" title=${`Bypath chose ${chosen} automatically${when}`}
      text="Nothing valid was selected, so the gateway picked a connection itself. Choose one to keep the next start predictable."
      actions=${html`<button class="btn primary small" type="button" onClick=${chooseConnection}>Choose connection</button>`} />`;
  }

  if (compact) return null;
  return html`<${Banner} kind="info" title=${kind}
    text=${selection.message || 'The saved next start could not be reconciled with the gateway.'} />`;
}
