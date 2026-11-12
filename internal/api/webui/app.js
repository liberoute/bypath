// Panel entry. The static sign-in forms are plain HTML so they work before any
// framework code runs; the authenticated application is mounted only after the
// session endpoint confirms it.

import { h, render } from './vendor/preact.module.js';
import { request, setCSRF, onSessionLost } from './js/api.js';
import { store } from './js/store.js';
import { App } from './js/shell.js';
import { parseHash } from './js/nav.js';
import { operationKey } from './js/operations.js';

const $ = (id) => document.getElementById(id);

let mounted = false;
let currentUser = '';

function bootMessage(message, retry = false) {
  const boot = $('boot');
  const text = $('boot-message');
  const button = $('boot-retry');
  if (text) text.textContent = message;
  if (button) button.hidden = !retry;
  if (boot) boot.hidden = false;
}

function authMessage(message) {
  const node = $('auth-message');
  if (!node) return;
  node.textContent = message || '';
  node.hidden = !message;
}

function showAuth(message, setupRequired, setupCodeRequired) {
  if (mounted) {
    render(null, $('shell'));
    mounted = false;
  }
  const boot = $('boot');
  const auth = $('auth');
  const shell = $('shell');
  if (boot) boot.hidden = true;
  if (shell) shell.hidden = true;
  if (auth) auth.hidden = false;
  const login = $('auth-login');
  const setup = $('auth-setup');
  if (login) login.hidden = !!setupRequired;
  if (setup) setup.hidden = !setupRequired;
  const codeLabel = $('setup-code') ? $('setup-code').parentElement : null;
  if (codeLabel) codeLabel.hidden = !setupCodeRequired;
  authMessage(message || '');
}

function showApp() {
  const boot = $('boot');
  const auth = $('auth');
  const shell = $('shell');
  if (boot) boot.hidden = true;
  if (auth) auth.hidden = true;
  if (shell) shell.hidden = false;
  authMessage('');
  const route = parseHash();
  store.set({ authenticated: true, username: currentUser, view: route.view, tab: route.tab });
  if (!mounted) {
    render(h(App), shell);
    mounted = true;
  }
  if (!location.hash) {
    history.replaceState(null, '', '#/overview');
  }
}

function setBusy(form, busy) {
  const button = form ? form.querySelector('button[type="submit"]') : null;
  if (!button) return;
  button.disabled = busy;
  if (busy) {
    button.dataset.label = button.textContent;
    button.textContent = form.id === 'auth-setup' ? 'Creating…' : 'Signing in…';
  } else if (button.dataset.label) {
    button.textContent = button.dataset.label;
  }
}

function wireForms() {
  const login = $('auth-login');
  const setup = $('auth-setup');
  const retry = $('boot-retry');

  if (retry) {
    retry.addEventListener('click', () => {
      bootMessage('Loading the panel…');
      bootSession();
    });
  }

  if (login) {
    login.addEventListener('submit', async (event) => {
      event.preventDefault();
      authMessage('');
      setBusy(login, true);
      try {
        const result = await request('POST', '/api/v1/web/login', {
          json: {
            username: $('login-username').value.trim(),
            password: $('login-password').value,
          },
        });
        currentUser = result.username || '';
        setCSRF(result.csrf);
        login.reset();
        showApp();
      } catch (err) {
        authMessage(err.message || 'Sign-in failed.');
      } finally {
        setBusy(login, false);
      }
    });
  }

  if (setup) {
    setup.addEventListener('submit', async (event) => {
      event.preventDefault();
      const password = $('setup-password').value;
      const confirm = $('setup-confirm').value;
      authMessage('');
      if (password !== confirm) {
        authMessage('The passwords do not match.');
        return;
      }
      if (password.length < 12) {
        authMessage('The password must be at least 12 characters.');
        return;
      }
      setBusy(setup, true);
      try {
        const result = await request('POST', '/api/v1/web/setup', {
          json: {
            username: $('setup-username').value.trim(),
            password,
            setup_code: $('setup-code').value.trim(),
          },
        });
        currentUser = result.username || '';
        setCSRF(result.csrf);
        setup.reset();
        showApp();
      } catch (err) {
        authMessage(err.message || 'Setup failed.');
      } finally {
        setBusy(setup, false);
      }
    });
  }
}

async function bootSession() {
  try {
    const session = await request('GET', '/api/v1/web/session');
    if (session && session.authenticated) {
      currentUser = session.username || '';
      setCSRF(session.csrf);
      showApp();
      return;
    }
    showAuth(sessionStorage.getItem(operationKey) ? 'Gateway is available again. Sign in to read the supervised restart or rollback result.' : '', !!session.setup_required, !!session.setup_code_required);
  } catch (err) {
    bootMessage(err && err.message ? err.message : 'Cannot reach the gateway.', true);
  }
}

onSessionLost(() => {
  setCSRF('');
  currentUser = '';
  store.reset();
  store.set({ authenticated: false });
  const pendingOperation = sessionStorage.getItem(operationKey);
  if (pendingOperation) history.replaceState(null, '', '#/settings');
  showAuth(pendingOperation ? 'Gateway is back. Sign in again to read the supervised operation result.' : 'Your session expired. Sign in again.', false, false);
});

wireForms();
bootSession();
