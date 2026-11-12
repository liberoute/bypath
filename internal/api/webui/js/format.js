// Presentation helpers. They translate API values into the shared vocabulary
// used by the web panel and the TUI; no scoring decision lives here.

export function timeAgo(iso) {
  if (!iso) return '';
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return String(iso);
  const seconds = Math.round((Date.now() - then) / 1000);
  if (seconds < 5) return 'just now';
  if (seconds < 60) return `${seconds} s ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours} h ago`;
  const days = Math.round(hours / 24);
  if (days < 30) return `${days} d ago`;
  const months = Math.round(days / 30);
  return `${months} mo ago`;
}

export function utcStamp(iso) {
  if (!iso) return '';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return String(iso);
  const pad = (n) => String(n).padStart(2, '0');
  return `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())} UTC`;
}

export function fmtClock(value) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
}

export function fmtDate(value) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString([], { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' });
}

export function fmtDuration(seconds) {
  if (seconds === null || seconds === undefined || seconds < 0) return '—';
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = Math.floor(seconds % 60);
  if (days) return `${days} d ${hours} h`;
  if (hours) return `${hours} h ${minutes} m`;
  if (minutes) return `${minutes} m ${secs} s`;
  return `${secs} s`;
}

export function fmtMB(bytes) {
  if (!bytes && bytes !== 0) return '—';
  const mb = bytes / (1024 * 1024);
  if (mb >= 1024) return `${(mb / 1024).toFixed(2)} GB`;
  if (mb >= 10) return `${mb.toFixed(1)} MB`;
  return `${mb.toFixed(2)} MB`;
}

export function fmtLatency(ms) {
  if (!ms) return '—';
  return `${ms} ms`;
}

export const REASON_TEXT = {
  CONFIG_NOT_ISOLATED: 'the test-tunnel configuration is not isolated',
  PATH_DIRECT_TARGET: 'the destination would go DIRECT, not through the tunnel',
  EXIT_EQUALS_UPLINK: 'traffic left directly instead of through the tunnel',
  EXIT_EQUALS_SERVING: 'the exit matches the serving connection, so ownership is unproven',
  EXIT_AMBIGUOUS: 'two identity services disagreed about the exit',
  EXIT_CHANGED: 'the exit changed during the measurement',
  EXIT_UNKNOWN: 'the exit identity could not be determined',
  POLICY_CHANGED: 'the routing policy changed during the measurement',
  CONTROL_FAILED: 'the DIRECT control failed, so route decisions are not trustworthy',
  ROUTE_EXPLAIN_UNAVAILABLE: 'the routing policy could not be evaluated for a target',
  ISOLATION_UNVERIFIED: 'isolated-test isolation has not been verified on this host',
  TARGET_REJECTED: 'the download target was rejected by the security checks',
  BUDGET_REACHED: 'the traffic budget was reached',
  NO_PROVEN_RESULT: 'a proven relay result is required before a speed test',
};

export function reasonText(code) {
  if (!code) return '';
  return REASON_TEXT[code] || String(code).toLowerCase().replace(/_/g, ' ');
}

const RESULT_STATE = {
  ok: 'healthy',
  inconclusive: 'inconclusive',
  unavailable: 'unavailable',
  failed: 'failed',
  skipped: 'skipped',
  cancelled: 'cancelled',
};

const RESULT_LABEL = {
  ok: 'Healthy',
  inconclusive: 'Inconclusive',
  unavailable: 'Unavailable',
  failed: 'Failed',
  skipped: 'Not run',
  cancelled: 'Cancelled',
};

export function verdictOf(result) {
  if (!result) return { state: 'untested', label: 'Untested' };
  if (result.superseded) return { state: 'stale', label: 'Superseded' };
  if (result.stale || proofStale(result)) return { state: 'stale', label: 'Stale' };
  if (result.status === 'ok' && !verifiedResult(result)) return { state: 'inconclusive', label: 'Inconclusive' };
  return {
    state: RESULT_STATE[result.status] || 'untested',
    label: RESULT_LABEL[result.status] || 'Untested',
  };
}

export function evidenceOf(result) {
  if (!result) return '';
  if (result.superseded) return 'a later attempt invalidated this proof';
  if (result.status === 'ok' && !verifiedResult(result)) return 'stale or incomplete path proof; not ranked';
  if (result.status === 'ok') {
    const parts = [];
    if (result.kind === 'speed' && result.mbps) parts.push(`${result.mbps.toFixed(1)} Mbps`);
    else if (result.p50_ms) parts.push(`${result.p50_ms} ms`);
    if (result.tested_at) parts.push(timeAgo(result.tested_at));
    return parts.join(' · ');
  }
  if (result.status === 'inconclusive') return reasonText(result.reason);
  if (result.detail) return result.detail;
  if (result.reason) return reasonText(result.reason);
  return result.tested_at ? timeAgo(result.tested_at) : '';
}

export function pathKind(result) {
  if (!result || !result.path) return '';
  if (result.path.kind === 'live') return 'measured on the live tunnel';
  if (result.path.kind === 'isolated') return 'measured on an isolated test tunnel';
  return result.path.kind || '';
}

export function proofStale(result) {
  const t = Date.parse(result && result.tested_at);
  return !Number.isFinite(t) || Date.now() - t > 24 * 3600 * 1000 || t > Date.now() + 60000;
}

export function verifiedResult(result) {
  const p = result && result.path;
  if (!result || result.status !== 'ok' || result.category !== 'verified_working_connection'
      || result.stale || result.superseded || proofStale(result) || !p) return false;
  if (p.proof_version !== 'P5' || p.kind !== 'isolated' || p.level !== 'L1+L2'
      || p.config_audit !== 'pass' || !p.isolation_verified || !p.engine_owned || !p.tunneled_https
      || !/^[a-f0-9]{64}$/.test(p.config_sha256 || '') || !/^[a-f0-9]{64}$/.test(p.profile_sha256 || '')) return false;
  if (!p.uplink_ip || !p.exit_ip_before || p.exit_ip_before !== p.exit_ip_after
      || p.exit_ip_before === p.uplink_ip || p.exit_ip_before === p.serving_exit_ip) return false;
  const echoes = p.echoes || [];
  if (echoes.length < 2 || !echoes[0].service || echoes[0].service === echoes[1].service
      || echoes.some((echo) => echo.ip !== p.exit_ip_before)) return false;
  return result.kind === 'speed' ? result.mbps > 0 && result.bytes > 0 && result.seconds > 0 : result.p50_ms > 0 || result.latency_ms > 0;
}

export function invalidateSupersededResults(results) {
  const latest = new Map();
  for (const r of results || []) {
    if (['ok', 'skipped'].includes(r.status)) continue;
    const cur = latest.get(r.connection_id);
    if (!cur || Date.parse(r.tested_at) >= Date.parse(cur.tested_at)) latest.set(r.connection_id, r);
  }
  return (results || []).map((r) => {
    const last = latest.get(r.connection_id);
    return last && r.status === 'ok' && Date.parse(last.tested_at) >= Date.parse(r.tested_at)
      ? { ...r, superseded: true } : r;
  });
}

export function latestResult(results, connectionId, kind) {
  let best = null;
  for (const result of results || []) {
    if (result.connection_id !== connectionId) continue;
    if (kind && result.kind !== kind) continue;
    if (!best || String(result.tested_at || '') > String(best.tested_at || '')) best = result;
  }
  return best;
}

export function connectionName(connection) {
  if (!connection) return 'Unknown connection';
  return connection.display_name || connection.remark || connection.id;
}

export function protocolShort(protocol) {
  const value = String(protocol || '').toLowerCase();
  switch (value) {
    case 'vless': return 'VL';
    case 'vmess': return 'VM';
    case 'trojan': return 'TR';
    case 'shadowsocks': return 'SS';
    case 'openvpn': return 'OV';
    case 'wireguard': return 'WG';
    case 'ssh': return 'SH';
    case 'hysteria2': return 'HY';
    case 'tuic': return 'TU';
    default: return value.slice(0, 2).toUpperCase() || '—';
  }
}

const HEALTH_LABEL = {
  VERIFIED: 'Verified',
  TUNNEL_DOWN: 'Tunnel down',
  DATA_PATH_DOWN: 'Data path down',
  EXIT_UNKNOWN: 'Exit unverified',
  UPLINK_UNVERIFIED: 'Uplink unverified',
  EXIT_IS_UPLINK: 'Exit is uplink',
};

export const HEALTH_TEXT = {
  VERIFIED: '',
  TUNNEL_DOWN: 'No probe endpoint answered through the tunnel. This is a forwarding failure, not an identity lookup failure.',
  DATA_PATH_DOWN: 'The local data path is unhealthy, so client traffic cannot be forwarded.',
  EXIT_UNKNOWN: 'The tunnel answered, but the exit address could not be identified.',
  UPLINK_UNVERIFIED: 'The tunnel answered, but the direct uplink could not be measured, so the exit cannot be proven.',
  EXIT_IS_UPLINK: 'The tunnel answered, but the exit equals the direct uplink, so the probe may have gone DIRECT.',
};

// healthEvidence turns the gateway's health proof into vocabulary the panels
// share. A failed identity lookup is never rendered as a dead tunnel: the
// gateway reports tunnel_answered separately for exactly that distinction.
export function healthEvidence(status) {
  if (!status || !status.health_code) return null;
  const code = String(status.health_code).toUpperCase();
  return {
    code,
    label: HEALTH_LABEL[code] || fmtStateLabel(code),
    verified: code === 'VERIFIED',
    tunnelAnswered: !!status.health_tunnel_answered,
    forwardingFailure: code === 'TUNNEL_DOWN' || code === 'DATA_PATH_DOWN',
    identityFailure: code === 'EXIT_UNKNOWN' || code === 'UPLINK_UNVERIFIED' || code === 'EXIT_IS_UPLINK',
    text: HEALTH_TEXT[code] || status.health_detail || '',
    detail: status.health_detail || '',
    exitIP: status.health_exit_ip || '',
    uplinkSamples: status.health_uplink_samples || 0,
  };
}

export function statusWord(status) {
  if (!status) return { word: 'Loading', kind: 'busy', explanation: 'Reading the gateway state…' };
  if (!status.running) {
    return {
      word: 'Stopped',
      kind: 'down',
      explanation: 'The gateway is not running. Manage it on the host, or start it again.',
    };
  }
  const raw = String(status.state || '').toUpperCase();
  switch (raw) {
    case 'CONNECTED':
      return { word: 'Serving', kind: 'ok', explanation: 'Client traffic is routed through the serving connection.' };
    case 'CONNECTING':
      return { word: 'Connecting', kind: 'busy', explanation: 'The tunnel is starting. Traffic pauses until it is ready.' };
    case 'RECOVERING':
      return { word: 'Recovering', kind: 'busy', explanation: 'The gateway is recovering the tunnel after a failure.' };
    case 'DEGRADED': {
      const health = healthEvidence(status);
      if (health && health.identityFailure) {
        return { word: 'Degraded', kind: 'busy', explanation: `${health.text} Traffic is not certified until the exit is proven.` };
      }
      if (health && health.forwardingFailure) {
        return { word: 'Degraded', kind: 'busy', explanation: health.text };
      }
      return { word: 'Degraded', kind: 'busy', explanation: 'The tunnel is up but its health checks are failing.' };
    }
    case 'FAILED':
    case 'ERROR':
      return { word: 'Failed', kind: 'down', explanation: 'The tunnel could not be established. Check the last error below.' };
    case 'DISCONNECTED':
      return { word: 'Disconnected', kind: 'down', explanation: 'The tunnel is intentionally down; the panel and CLI stay available.' };
    default:
      return { word: raw || 'Unknown', kind: raw === 'CONNECTED' ? 'ok' : 'busy', explanation: '' };
  }
}

export function selectionInfoOf(status) {
  return (status && status.selection) || null;
}

// A link is only "serving" once the tunnel reports CONNECTED. During CONNECTING
// or after DISCONNECTED the last active id still exists, but no traffic flows.
export function tunnelServing(status) {
  if (!status || !status.running) return false;
  return String(status.state || '').toUpperCase() === 'CONNECTED';
}

export function servingName(status) {
  if (!status) return '';
  return status.active_link || status.selected_link || '';
}

export function servingId(status) {
  if (!status) return '';
  return status.active_id || status.selected_id || '';
}

export function splitID(id) {
  if (!id) return { group: '', remark: '' };
  const at = id.indexOf(':');
  if (at < 1) return { group: '', remark: id };
  return { group: id.slice(0, at), remark: id.slice(at + 1) };
}

export function fmtStateLabel(raw) {
  return String(raw || '').replace(/_/g, ' ').toLowerCase().replace(/^\w/, (c) => c.toUpperCase());
}

export function scrollToId(id) {
  const node = document.getElementById(id);
  if (node) node.scrollIntoView({ behavior: 'smooth', block: 'start' });
}
