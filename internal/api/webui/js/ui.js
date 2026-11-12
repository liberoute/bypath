// Shared visual components. Markup follows fable-v2/DESIGN_SYSTEM.md; state is
// always carried by a glyph and a word, never by colour alone.

import { h, Component, Fragment } from '../vendor/preact.module.js';
import { useEffect, useRef, useState } from '../vendor/hooks.module.js';
import htm from '../vendor/htm.module.js';
import { store } from './store.js';
import { timeAgo, utcStamp, verdictOf, evidenceOf } from './format.js';

export const html = htm.bind(h);

export const stateGlyph = {
  serving: '✓',
  healthy: '✓',
  degraded: '!',
  failed: '✕',
  unavailable: '⊘',
  inconclusive: '?',
  testing: '◌',
  untested: '–',
  stale: '◷',
  skipped: '»',
  cancelled: '■',
};

export function Chip({ state = 'untested', label, evidence, title, onClick }) {
  const word = label || state;
  const content = html`<span>${word}${evidence ? html` <span class="evidence">· ${evidence}</span>` : null}</span>`;
  if (onClick) {
    return html`<button type="button" class="chip ${state}" title=${title || ''} onClick=${onClick}>${content}</button>`;
  }
  return html`<span class="chip ${state}" title=${title || ''}>${content}</span>`;
}

export function ResultChip({ result, onClick }) {
  const verdict = verdictOf(result);
  return html`<${Chip}
    state=${verdict.state}
    label=${verdict.label}
    evidence=${evidenceOf(result)}
    title=${result && result.detail ? result.detail : verdict.label}
    onClick=${onClick} />`;
}

export function Banner({ kind = 'info', icon, title, text, actions, children }) {
  const glyph = icon || (kind === 'bad' ? '✕' : kind === 'warn' ? '!' : kind === 'ok' ? '✓' : 'i');
  return html`<div class="banner ${kind}" role=${kind === 'bad' ? 'alert' : 'status'}>
    <div class="b-icon" aria-hidden="true">${glyph}</div>
    <div>
      ${title ? html`<div class="b-title">${title}</div>` : null}
      ${text ? html`<div class="b-text">${text}</div>` : null}
      ${children}
    </div>
    ${actions ? html`<div class="b-actions">${actions}</div>` : null}
  </div>`;
}

export function Empty({ icon = '·', title, text, action }) {
  return html`<div class="empty">
    <span class="e-icon" aria-hidden="true">${icon}</span>
    ${title ? html`<strong>${title}</strong>` : null}
    ${text ? html`<div>${text}</div>` : null}
    ${action ? html`<div class="actions" style="justify-content:center;margin-top:12px">${action}</div>` : null}
  </div>`;
}

export function Skeleton({ rows = 3 }) {
  const items = [];
  for (let i = 0; i < rows; i += 1) items.push(html`<div class="skeleton" key=${i}></div>`);
  return html`<div class="stack" aria-hidden="true">${items}</div>`;
}

export function KV({ rows }) {
  return html`<div class="kv">
    ${(rows || []).filter(Boolean).map(([key, value]) => html`<div class="row" key=${key}>
      <span>${key}</span>
      <span>${value === null || value === undefined || value === '' ? '—' : value}</span>
    </div>`)}
  </div>`;
}

export function RelTime({ iso, prefix = '' }) {
  if (!iso) return html`<span class="muted">—</span>`;
  return html`<span title=${utcStamp(iso)}>${prefix}${timeAgo(iso)}</span>`;
}

export function Dialog({ title, children, footer, onClose, wide }) {
  const ref = useRef(null);
  useEffect(() => {
    const dialog = ref.current;
    if (dialog && !dialog.open) dialog.showModal();
    return () => {
      if (dialog && dialog.open) dialog.close();
    };
  }, []);
  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return undefined;
    const onCancel = (event) => {
      event.preventDefault();
      if (onClose) onClose();
    };
    dialog.addEventListener('cancel', onCancel);
    return () => dialog.removeEventListener('cancel', onCancel);
  }, [onClose]);
  return html`<dialog class="dlg" ref=${ref} style=${wide ? 'width:min(760px,calc(100vw - 32px))' : ''}>
    <div class="dlg-head">
      <h2>${title}</h2>
      <button class="btn ghost small" type="button" onClick=${onClose}>Close</button>
    </div>
    <div class="dlg-body">${children}</div>
    ${footer ? html`<div class="dlg-foot">${footer}</div>` : null}
  </dialog>`;
}

export function Drawer({ title, children, onClose }) {
  const closeRef = useRef(null);
  useEffect(() => {
    const onKey = (event) => {
      if (event.key === 'Escape' && onClose) onClose();
    };
    window.addEventListener('keydown', onKey);
    if (closeRef.current) closeRef.current.focus();
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);
  return html`<div class="scrim" onClick=${onClose}>
    <aside class="drawer" role="dialog" aria-modal="true" aria-label=${title} onClick=${(e) => e.stopPropagation()}>
      <div class="d-head">
        <div class="d-title">${title}</div>
        <button ref=${closeRef} class="btn ghost small" type="button" onClick=${onClose}>Close</button>
      </div>
      ${children}
    </aside>
  </div>`;
}

export function Tabs({ tabs, active, onChange }) {
  return html`<div class="tabs" role="tablist">
    ${tabs.map((tab) => html`<button
      key=${tab.id}
      type="button"
      role="tab"
      aria-selected=${active === tab.id ? 'true' : 'false'}
      class=${active === tab.id ? 'active' : ''}
      onClick=${() => onChange(tab.id)}>${tab.label}</button>`)}
  </div>`;
}

export function Progress({ completed = 0, total = 0, state = '' }) {
  const pct = total > 0 ? Math.min(100, Math.round((completed / total) * 100)) : 0;
  const tone = state === 'done' ? 'done' : state === 'failed' ? 'warn' : '';
  return html`<div class="progress" role="progressbar" aria-valuemin="0" aria-valuemax=${total || 0} aria-valuenow=${completed || 0}>
    <div class="bar ${tone}" style=${`width:${pct}%`}></div>
  </div>`;
}

export function Footnote({ children }) {
  return html`<p class="footnote">${children}</p>`;
}

export function ByteNote() {
  return html`<${Footnote}>
    Counted bytes are payload read by Bypath. Protocol overhead and retransmissions
    are not included, so real link usage is higher.
  <//>`;
}

export function Toasts() {
  const [toasts, setToasts] = useState(store.get().toasts);
  useEffect(() => store.subscribe((state) => setToasts(state.toasts)), []);
  return html`<div class="toasts" aria-live="polite">
    ${toasts.map((item) => html`<div class="toast ${item.kind}" key=${item.id}>${item.message}</div>`)}
  </div>`;
}

// One screen failing must not take the whole panel down: Preact's async
// rerender queue stops for good if an error escapes a component render.
export class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error) {
    // eslint-disable-next-line no-console
    console.error('panel render failed', error);
  }

  render() {
    if (!this.state.error) return this.props.children;
    return html`<div class="banner bad" role="alert">
      <div class="b-icon" aria-hidden="true">✕</div>
      <div>
        <div class="b-title">${this.props.label || 'This screen could not be shown'}</div>
        <div class="b-text">${String((this.state.error && this.state.error.message) || this.state.error)}</div>
      </div>
      <div class="b-actions"><button class="btn ghost small" type="button"
        onClick=${() => this.setState({ error: null })}>Try again</button></div>
    </div>`;
  }
}

export { Fragment };
