export const operationKey = 'bypath-service-operation';
export const terminalOperation = (state) => ['serving', 'failed', 'rolled_back'].includes(state);

export function proxyEndpoint(address, port) {
  return `socks5://${address}:${port}`;
}

export function validateProxy(port, address, settings) {
  if (!Number.isInteger(port) || port < 1 || port > 65535) return 'Enter a port from 1 to 65535.';
  if ([22, 53, 80, 443, 8443, settings.api_port, settings.dns_port, settings.web_port].includes(port)) {
    return 'That port is reserved for management, DNS, SSH or HTTPS.';
  }
  if (!['127.0.0.1', '0.0.0.0', settings.trusted_lan_ip].filter(Boolean).includes(address)) {
    return 'Choose localhost, the trusted LAN address or all IPv4 interfaces.';
  }
  return '';
}

export async function pollOperation(read, update, options = {}) {
  const wait = options.wait || ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
  const now = options.now || Date.now;
  const deadline = now() + (options.timeoutMs || 240000);
  while (now() < deadline) {
    if (options.cancelled && options.cancelled()) return null;
    try {
      const operation = await read();
      update(operation);
      if (terminalOperation(operation.state)) return operation;
    } catch (err) {
      if (err.status === 401) {
        update({ state: 'authentication_required', message: 'Gateway is back. Sign in again to read the supervised result.' });
        return null;
      }
      if (err.status && ![502, 503, 504].includes(err.status)) throw err;
      update({ state: 'restarting', message: 'Panel temporarily unavailable; waiting for the independently supervised gateway operation.' });
    }
    await wait(options.intervalMs || 1200);
  }
  update({ state: 'unconfirmed', message: 'The browser wait expired. The supervisor may still be recovering. Sign in and check the result; do not repeat the operation.' });
  return null;
}
