// Section list and the one hook that connects a view to the shared store.

import { useEffect, useState } from '../vendor/hooks.module.js';
import { store } from './store.js';
import { web } from './api.js';

export const VIEWS = [
  { id: 'overview', label: 'Overview', glyph: '◉' },
  { id: 'connections', label: 'Connections', glyph: '≣' },
  { id: 'sources', label: 'Sources', glyph: '⇣' },
  { id: 'tests', label: 'Tests', glyph: '◎' },
  { id: 'routing', label: 'Routing', glyph: '⇢' },
  { id: 'settings', label: 'Settings', glyph: '⚙' },
];

const viewIds = new Set(VIEWS.map((view) => view.id));

export function parseHash() {
  const raw = String(location.hash || '').replace(/^#\/?/, '');
  const [view, tab] = raw.split('/');
  return {
    view: viewIds.has(view) ? view : 'overview',
    tab: tab || '',
  };
}

export function navigate(view, tab) {
  const next = viewIds.has(view) ? view : 'overview';
  const hash = tab ? `#/${next}/${tab}` : `#/${next}`;
  if (location.hash !== hash) {
    history.pushState(null, '', hash);
  }
  store.set({ view: next, tab: tab === undefined ? store.get().tab : tab });
  window.scrollTo({ top: 0, behavior: 'auto' });
}

export function useApp() {
  const [state, setState] = useState(store.get());
  useEffect(() => store.subscribe(setState), []);
  return state;
}

export async function signOut() {
  try {
    await web.logout();
  } catch {
    // The cookie is cleared server-side as well; reloading shows the sign-in.
  }
  location.reload();
}
