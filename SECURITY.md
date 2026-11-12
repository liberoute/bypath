# Security

Bypath is a root network service. This document states what it protects, what
it does not, and how to report a problem.

## Scope of this pre-release

`v3.0.0-rc.1` is a release candidate. It has been exercised on fresh amd64
installations and an emulated arm64 environment, with the test matrix described
in [RELEASE_NOTES.md](RELEASE_NOTES.md). It has not been through an external
security audit. Treat it accordingly.

## Trust model

- **The host is trusted.** Bypath runs as root, creates TUN devices, installs
  firewall rules and reads its own configuration. Anyone with root on the host
  can control the gateway regardless of Bypath's settings.
- **The `bypath` system group is root-equivalent administration.** Members can
  reach the control socket, which exposes connections, credentials, routing and
  engine paths. Adding an account to this group is equivalent to granting sudo.
- **The management API is authenticated.** It binds `127.0.0.1:8080` by
  default. A root daemon refuses tokenless TCP; over TCP you need
  `server.api_token` or a panel administrator session. The first panel
  administrator is created only from a local visit, proven by a one-time setup
  code written `0600` next to the runtime state and deleted after use.
- **The proxy listener is not authenticated.** SOCKS5/HTTP has no client
  authentication by design. Its protection is the bind address, the explicit
  trusted-CIDR allow-list and the firewall rules Bypath installs. A LAN bind
  without an allow-list is refused.
- **Tunnel content is between you and your proxy server.** Bypath does not
  operate the server and cannot vouch for its logging, jurisdiction or
  trustworthiness. Your provider's terms and the law where you and the server
  are located apply.

## What Bypath does not protect against

- A compromised host, a compromised kernel, or an attacker with root.
- Malware already running as the user who can read that user's traffic.
- IPv6 forwarding: gateway mode drops forwarded IPv6 rather than leaking it,
  but IPv6 correctness is not otherwise validated in this pre-release.
- A malicious proxy server or subscription. Imported links are not audited.
- Traffic that bypasses the gateway because a client ignores the DNS or gateway
  setting you gave it.

## Exposure rules enforced by the software

| Surface | Default | To expose it deliberately |
|---|---|---|
| Management API | `127.0.0.1:8080` | Set `server.api_token`; never bind it to a public address. |
| Web panel | Disabled, loopback when enabled | `server.web.allow_lan: true` plus authentication; prefer a reverse proxy. |
| SOCKS/HTTP proxy | `127.0.0.1:2801` | `server.socks_allow_lan: true` **and** `server.socks_trusted_cidrs`; Bypath's firewall rejects other sources. |
| Gateway DNS | Only in gateway mode | Gateway mode is opt-in and requires a free port 53. |
| Control socket | `root:bypath`, `0660`, private directory | Add trusted administrators to the `bypath` group. |
| Tunnel egress | Gateway mode | Enabling gateway mode after verifying a connection. |

Bypath never takes over port 53, never stops another resolver or VPN, and never
rewrites the default route, DHCP or global firewall policy during installation.

## Secret handling

- Imported proxy links, subscription URLs, OpenVPN profiles and credentials are
  stored with owner-only permissions: Unix `0600`/`0700`, and a protected DACL
  with a single owner ACE on Windows.
- Per-run engine configurations and temporary credential files are deleted when
  the link, tunnel or failed import no longer needs them. Cleanup only removes
  files owned by that operation.
- Logs redact API tokens, passwords and private-key material before they are
  exposed through the panel or the log ring buffer.
- `bypath doctor` never prints credentials, raw subscription URLs or
  unredacted link URIs.
- Backups created from the panel contain configuration only; credentials,
  tokens and subscription addresses are excluded.
- Never paste a proxy URI, subscription URL, API token or OpenVPN credential
  into a bug report. A subscription URL usually contains its own credential.

## Reporting a vulnerability

Do not open a public issue for a security problem. Use the repository's private
security advisory feature (Security → Advisories → Report a vulnerability) and
include:

- the affected version (`bypath version`);
- a description of the impact and the conditions required;
- reproduction steps or a proof of concept with all credentials and addresses
  replaced by documentation values;
- any suggested remediation.

Please allow time for a fix and a coordinated disclosure. Do not test against
systems you do not own or have permission to test, and do not include real
subscription tokens, credentials or third-party infrastructure details in a
report.

## Hardening checklist

- Keep the management API on loopback; use the control socket locally.
- Set `server.api_token` if anything other than the TUI/CLI must talk to the API.
- Enable the panel only when you need it, and prefer loopback or a reverse
  proxy with TLS.
- On a LAN proxy bind, keep `socks_trusted_cidrs` as narrow as possible and
  verify the effective firewall rules with `bypath doctor`.
- Keep only trusted administrators in the `bypath` group.
- Run `bypath doctor` after every upgrade and after any listener change.
