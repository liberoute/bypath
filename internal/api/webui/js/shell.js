// Application shell: navigation, live status, persistent banners, the switch
// sheet and the mount point for every screen. It owns no business logic.

import { useEffect, useRef } from '../vendor/hooks.module.js';
import { html, Banner, Toasts, ErrorBoundary } from './ui.js';
import { store, toastError } from './store.js';
import { navigate, parseHash, signOut, useApp, VIEWS } from './nav.js';
import { SelectionBanner } from './selection.js';
import {
  refreshStatus,
  loadConnections,
  loadGroups,
  loadLayer,
  loadResults,
  loadSources,
  loadTargets,
  dismissSwitchSheet,
  restorePrevious,
} from './data.js';
import { statusWord, fmtClock, fmtDuration, timeAgo } from './format.js';
import OverviewView from './views/overview.js';
import ConnectionsView from './views/connections.js';
import SourcesView from './views/sources.js';
import TestsView from './views/tests.js';
import RoutingView from './views/routing.js';
import SettingsView from './views/settings.js';

const SCRIPTS = {
  overview: OverviewView,
  connections: ConnectionsView,
  sources: SourcesView,
  tests: TestsView,
  routing: RoutingView,
  settings: SettingsView,
};

const STATUS_CHIP = { ok: 'serving', busy: 'testing', down: 'unavailable' };

export function App() {
  const state = useApp();
  const lastSignature = useRef('');

  useEffect(() => {
    refreshStatus().catch(() => {});
    Promise.allSettled([
      loadConnections(),
      loadGroups(),
      loadLayer(),
      loadResults(),
      loadSources(),
      loadTargets(),
    ]);
  }, []);

  useEffect(() => {
    let live = true;
    let timer = null;
    const tick = async () => {
      try {
        const status = await refreshStatus();
        if (!live || !status) return;
        const selection = (status.selection && status.selection.state) || '';
        const signature = `${status.state}|${status.active_id}|${status.selected_id}|${selection}|${status.running}`;
        if (signature !== lastSignature.current) {
          lastSignature.current = signature;
          loadConnections().catch(() => {});
          loadGroups().catch(() => {});
        }
      } catch {
        // The banner is driven by statusError; keep polling quietly.
      }
    };
    const schedule = () => {
      if (timer) clearInterval(timer);
      timer = setInterval(tick, store.get().job ? 2000 : 4500);
    };
    schedule();
    const onVisible = () => {
      if (document.visibilityState === 'visible') tick();
    };
    document.addEventListener('visibilitychange', onVisible);
    return () => {
      live = false;
      if (timer) clearInterval(timer);
      document.removeEventListener('visibilitychange', onVisible);
    };
  }, [state.job && state.job.state]);

  useEffect(() => {
    const onHash = () => {
      const route = parseHash();
      store.set({ view: route.view, tab: route.tab || store.get().tab });
    };
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);

  const View = SCRIPTS[state.view] || OverviewView;
  const status = state.status;
  const word = statusWord(status);

  return html`<div class="shell">
    <aside class="rail">
      <div class="brand">BYPATH</div>
      <nav aria-label="Sections">
        ${VIEWS.map((view) => html`<button key=${view.id} type="button"
          class=${state.view === view.id ? 'active' : ''}
          aria-current=${state.view === view.id ? 'page' : null}
          onClick=${() => navigate(view.id)}>
          <span class="nav-glyph" aria-hidden="true">${view.glyph}</span>${view.label}
        </button>`)}
      </nav>
      <div class="rail-foot">
        <div class="small muted">${state.username || 'Administrator'}</div>
        <button class="btn ghost small" type="button" onClick=${signOut}>Sign out</button>
        <div class="build">${status ? `${status.version || ''} · ${status.commit || ''}` : ''}</div>
      </div>
    </aside>

    <header class="topbar">
      <div class="brand top-brand">BYPATH</div>
      <div class="spacer"></div>
      <div class="top-actions">
        ${state.job && !['done', 'failed', 'cancelled'].includes(state.job.state)
          ? html`<button class="jobpill" type="button" onClick=${() => navigate('tests', 'run')}>
              Testing ${state.job.completed || 0}/${state.job.total || 0}
            </button>`
          : null}
        <button class="chip ${STATUS_CHIP[word.kind] || 'untested'}" type="button"
          title=${word.explanation || ''} onClick=${() => navigate('overview')}>
          ${word.word}${status && status.state ? html` <span class="evidence">· ${status.state.toLowerCase()}</span>` : null}
        </button>
      </div>
    </header>

    <main>
      <div class="content">
        ${state.switchSheet ? html`<${SwitchSheet} sheet=${state.switchSheet} />` : null}
        ${!status && state.statusError
          ? html`<${Banner} kind="bad" title="Cannot reach the gateway"
              text=${state.statusError}
              actions=${html`<button class="btn ghost small" type="button" onClick=${() => refreshStatus().catch(toastError)}>Retry</button>`} />`
          : null}
        ${status && status.state === 'FAILED' && status.last_error
          ? html`<${Banner} kind="bad" title="The tunnel failed"
              text=${status.last_error}
              actions=${status.previous_id ? html`<button class="btn ghost small" type="button" onClick=${() => restorePrevious().catch(toastError)}>Restore ${status.previous_link || 'previous connection'}</button>` : null} />`
          : null}
        ${status && status.fallback_error
          ? html`<${Banner} kind="warn"
              title=${`Fallback: ${status.active_link || 'another connection'} is serving`}
              text=${`The requested connection failed: ${status.fallback_error}`}
              actions=${status.previous_id ? html`<button class="btn ghost small" type="button" onClick=${() => restorePrevious().catch(toastError)}>Return to ${status.previous_link || 'previous'}</button>` : null} />`
          : null}
        ${status && status.layer_warning
          ? html`<${Banner} kind="warn" title="Organisation data needs attention" text=${status.layer_warning} />`
          : null}
        ${status ? html`<${ErrorBoundary} label="The selection banner could not be shown"><${SelectionBanner} /><//>` : null}

        <${ErrorBoundary} key=${`view:${state.view}`} label=${`The ${state.view} screen could not be shown`}>
          <${View} state=${state} />
        <//>

        <p class="footnote">
          ${status ? `Gateway ${status.version || 'unknown'} · ${state.view === 'overview' ? `checked ${timeAgo(state.statusAt) || 'just now'}` : 'Bypath'}` : 'Bypath'}
        </p>
      </div>
    </main>

    <nav class="tabbar" aria-label="Sections">
      ${VIEWS.map((view) => html`<button key=${view.id} type="button"
          class=${state.view === view.id ? 'active' : ''}
          aria-current=${state.view === view.id ? 'page' : null}
          onClick=${() => navigate(view.id)}>
          <span class="nav-glyph" aria-hidden="true">${view.glyph}</span>${view.label}
        </button>`)}
    </nav>
  </div>
  ${state.dialog ? html`<${ErrorBoundary} key="dialog" label="This dialog could not be shown">${state.dialog}<//>` : null}
  <${Toasts} />`;
}

const STEP_ORDER = ['stopping', 'starting', 'verifying', 'done'];

function stepClass(phase, step) {
  if (phase === 'failed') {
    const reached = STEP_ORDER.indexOf(step);
    const failedAt = STEP_ORDER.indexOf('done') - 1;
    if (reached < failedAt) return 'done';
    return step === 'verifying' ? 'failed' : 'done';
  }
  const index = STEP_ORDER.indexOf(phase);
  const mine = STEP_ORDER.indexOf(step);
  if (mine < index) return 'done';
  if (mine === index) return 'now';
  return '';
}

function SwitchSheet({ sheet }) {
  const failed = sheet.phase === 'failed';
  const done = sheet.phase === 'done';
  const steps = html`<div class="steps">
    <span class=${stepClass(sheet.phase, 'stopping')}>1 Stop the old tunnel</span>
    <span class=${stepClass(sheet.phase, 'starting')}>2 Start the chosen connection</span>
    <span class=${stepClass(sheet.phase, 'verifying')}>3 Verify the path</span>
    <span class=${stepClass(sheet.phase, 'done')}>4 Done</span>
  </div>`;
  const facts = [];
  if (sheet.exit && sheet.exit.ip) facts.push(`Exit ${sheet.exit.ip}${sheet.exit.country ? ` · ${sheet.exit.country}` : ''}`);
  if (done && sheet.finishedAt && sheet.startedAt) {
    facts.push(`took ${fmtDuration(Math.max(1, Math.round((sheet.finishedAt - sheet.startedAt) / 1000)))}`);
  }
  return html`<div class=${`switch-sheet ${failed ? 'failed' : done ? 'done' : ''}`} role="status">
    <div class="row">
      <strong class="grow">${sheet.label}</strong>
      <span class="muted small">${fmtClock(sheet.startedAt)}</span>
      <button class="btn ghost small" type="button" onClick=${dismissSwitchSheet}>${done || failed ? 'Dismiss' : 'Hide'}</button>
    </div>
    ${steps}
    ${failed
      ? html`<${Banner} kind="bad" title="The switch did not complete" text=${sheet.message || 'The gateway kept its previous state or could not verify the new one.'}
          actions=${html`<button class="btn ghost small" type="button" onClick=${() => restorePrevious().catch(toastError)}>Restore previous connection</button>`} />`
      : null}
    ${done && facts.length ? html`<div class="muted small">${facts.join(' · ')}</div>` : null}
    ${!done && !failed ? html`<div class="muted small">Traffic pauses until the tunnel reports it is serving. This sheet stays until you dismiss it.</div>` : null}
  </div>`;
}
