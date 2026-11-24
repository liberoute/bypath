// One tiny observable store shared by every screen. Views subscribe through
// useApp(); server state stays authoritative and is replaced, never mutated.

const initial = {
  authenticated: false,
  username: '',
  view: 'overview',
  tab: '',

  status: null,
  statusAt: '',
  statusError: '',

  connections: [],
  connectionsLoaded: false,
  groups: [],
  groupsLoaded: false,
  layer: null,
  layerPlan: null,

  results: [],
  resultsLoaded: false,
  subscriptions: [],
  subscriptionsLoaded: false,

  settings: null,
  settingsLoaded: false,
  engines: [],
  logs: [],
  logsAt: '',

  targets: [],
  targetsLoaded: false,
  usage: null,

  exit: null,
  exitBusy: false,
  busy: '',

  job: null,
  jobPolling: false,

  switchSheet: null,
  drawer: '',
  dialog: null,

  toasts: [],
};

let state = { ...initial };
const listeners = new Set();

export const store = {
  get() {
    return state;
  },
  set(patch) {
    const next = typeof patch === 'function' ? patch(state) : patch;
    state = { ...state, ...next };
    for (const fn of listeners) fn(state);
  },
  subscribe(fn) {
    listeners.add(fn);
    return () => listeners.delete(fn);
  },
  reset() {
    state = { ...initial, authenticated: state.authenticated, username: state.username, view: state.view, tab: state.tab };
    for (const fn of listeners) fn(state);
  },
};

let toastSeq = 0;

export function toast(message, kind = 'info', timeout = 4500) {
  const id = ++toastSeq;
  store.set((s) => ({ toasts: [...s.toasts, { id, message: String(message), kind }] }));
  if (timeout > 0) {
    setTimeout(() => {
      store.set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) }));
    }, timeout);
  }
}

export function toastError(err, fallback = 'Something went wrong.') {
  const message = err && err.message ? err.message : fallback;
  const hint = err && err.hint ? ` — ${err.hint}` : '';
  toast(message + hint, 'error', 9000);
}
