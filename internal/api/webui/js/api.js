// Same-origin JSON transport for the panel. The CSRF token lives in memory
// only; the session cookie is HttpOnly and never read here.

let csrf = '';
let sessionLost = () => {};

export function setCSRF(token) {
  csrf = token || '';
}

export function onSessionLost(handler) {
  sessionLost = typeof handler === 'function' ? handler : () => {};
}

export class ApiError extends Error {
  constructor(message, code, hint, status) {
    super(message);
    this.name = 'ApiError';
    this.code = code || '';
    this.hint = hint || '';
    this.status = status || 0;
  }
}

export async function request(method, path, options = {}) {
  const headers = { Accept: 'application/json' };
  if (csrf && method !== 'GET' && method !== 'HEAD') headers['X-CSRF-Token'] = csrf;
  const init = { method, headers, credentials: 'same-origin' };
  if (options.json !== undefined) {
    headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(options.json);
  } else if (options.raw !== undefined) {
    headers['Content-Type'] = options.contentType || 'application/octet-stream';
    init.body = options.raw;
  }
  const controller = options.timeoutMs ? new AbortController() : null;
  const timer = controller ? setTimeout(() => controller.abort(), options.timeoutMs) : null;
  if (controller) init.signal = controller.signal;
  let response;
  let text;
  try {
    response = await fetch(path, init);
    text = await response.text();
  } catch (err) {
    throw new ApiError('Cannot reach the gateway. Check the connection and try again.', 'network', '', 0);
  } finally {
    if (timer) clearTimeout(timer);
  }
  let data = null;
  if (text) {
    try { data = JSON.parse(text); } catch { data = text; }
  }
  if (response.status === 401 && data && data.code === 'unauthenticated') {
    sessionLost();
    throw new ApiError('Your session expired. Sign in again.', 'unauthenticated', '', 401);
  }
  if (!response.ok) {
    const message = (data && typeof data === 'object' && data.message)
      || (typeof data === 'string' && data)
      || `Request failed (${response.status})`;
    throw new ApiError(message, data && data.code, data && data.hint, response.status);
  }
  return data;
}

const app = (path) => `/api/v1/app${path}`;

export const api = {
  get: (path) => request('GET', app(path)),
  post: (path, json) => request('POST', app(path), json === undefined ? {} : { json }),
  patch: (path, json) => request('PATCH', app(path), { json }),
  del: (path) => request('DELETE', app(path)),
};

export const web = {
  session: () => request('GET', '/api/v1/web/session'),
  login: (username, password) => request('POST', '/api/v1/web/login', { json: { username, password } }),
  setup: (payload) => request('POST', '/api/v1/web/setup', { json: payload }),
  logout: () => request('POST', '/api/v1/web/logout'),
  password: (current, next) => request('POST', '/api/v1/web/password', {
    json: { current_password: current, new_password: next },
  }),
};
