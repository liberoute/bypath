# Changelog

This branch starts a new, independently constructed public history for Bypath.
Earlier internal development history is not part of it. Entries below describe
the public release candidate only.

## v3.0.0-rc.2 — pre-release

Reliability corrections for rc.1, with the public tree based on the rc.1
release (`3518bef`). `main` and the `v3.0.0-rc.1` tag are unchanged.

### Exit identity and activation

- First-run activation and `doctor --egress` use the multi-oracle health-proof
  architecture instead of one hardcoded `api.ipify.org` request. Every identity
  service is probed with a bounded timeout, and an unreachable identity service
  is reported as UNVERIFIED rather than as a dead tunnel.
- Tunnel connectivity is proven separately by non-Cloudflare data-path
  endpoints when no identity service answers. Gateway activation is allowed in
  that case with an explicit UNVERIFIED warning.
- Still fail closed: a tunnel with no passing data path is refused, and an exit
  that equals the host's direct address (including one inconsistent oracle
  answer that matches it) is refused.
- Added tests for blocked oracles, inconsistent answers, a reachable tunnel and
  an actually failed tunnel.

### Service persistence

- New `bypath setup --enable-service`: after a verified start, enable the unit
  at boot and verify `systemctl is-enabled` reports `enabled`.
- The interactive wizard offers the same choice only after a start that reached
  `CONNECTED` and passed the exit-identity check. Installation alone still never
  enables or starts the unit.
- INSTALL.md and installer output document start vs. enable vs. gateway mode.

### DNS and installer reliability

- Native TUN no longer points `/etc/resolv.conf` at `127.0.0.1` when the gateway
  DNS listener uses a nonstandard port (which made host DNS, and therefore an
  installer rerun, fail). With the systemd-resolved stub, a bypath-managed
  drop-in forwards host DNS to `127.0.0.1:<port>` and is removed on stop.
  Without the stub, host DNS is left untouched and the limitation is logged.
- `systemd-resolved` and `dnsmasq` are no longer stopped when the gateway uses a
  nonstandard port and there is no conflict.
- The wizard warns that DHCP and standard client DNS settings cannot express a
  port when 5335 (or another nonstandard port) is used.
- Uninstall and `--purge` remove `/run/bypath-control` along with the runtime
  directory, so no control socket survives.

## v3.0.0-rc.1 — pre-release

First public release candidate. Pre-release: not a stable release, not marked
"latest", and not production-ready for untested platforms.

### Installation and first run

- New version-pinned installer (`install.sh`) with host preflight: OS,
  architecture, systemd, TUN, iptables/nftables, existing DNS services, port
  conflicts, memory, disk, existing installation, interfaces and default route.
- Downloads `bypath-linux-<arch>` and verifies it against the release
  `SHA256SUMS` before installing. Refuses `latest` and non-exact tags.
- Atomic install to `/opt/bypath/bypath` with the previous binary kept for
  rollback. The systemd unit is written but not enabled or started.
- `--dry-run`, `--non-interactive`, `--uninstall` (keeps configuration),
  `--purge`, and `--rollback` are supported. Re-running the installer is
  idempotent.
- The installer never stops a resolver, rewrites `/etc/resolv.conf`, changes
  routes, DHCP, the default gateway or the firewall, or opens a LAN listener
  without an explicit answer.

### First-run wizard (`bypath setup`)

- Ten-step guided configuration: LAN interface, trusted client subnets, gateway
  or proxy-only mode, proxy port, proxy listener, DNS, connection import,
  selection and verification, management panel, review before activation.
- Fresh configuration contains no connection, no subscription, no provider, no
  credential, no assumed location and no preconfigured production DNS server.
  The default routing rule is `default → proxy`.
- Gateway mode is staged with `gateway.enabled: false` until a connection has
  been verified. An empty full-tunnel gateway is never started.
- The management API defaults to `127.0.0.1`. A LAN proxy bind requires explicit
  trusted client CIDRs and Bypath's own firewall allow-list.
- `--dry-run` prints the exact configuration that would be written, with the
  API token redacted.

### `bypath doctor`

- New read-only diagnostic report covering: installation and service state,
  configuration validity, engine availability and compatibility, TUN and
  native-TUN, routing and fail-closed DNS policy, DNS service conflicts, trusted
  LAN and firewall state, management API and panel exposure, proxy listener
  reachability, connection configuration, and (with `--egress`) measured tunnel
  egress versus the direct exit address.
- `--json` emits a structured report; `-v` prints detail for every check.
  Credentials, tokens, raw subscription URLs and unredacted link URIs are never
  printed.

### Web onboarding and controls

- Empty-state onboarding in the panel: import a source, review the
  auto-created group, select the next-start connection, understand verification
  and inconclusive results, and read which surface exposes what.
- Panels distinguish the loopback management UI, the internal management API and
  the unauthenticated proxy listener, including the port each one uses.
- Supervised service restart and proxy listener changes with staged, removable
  operations.

### Engines

- Release builds (`-tags full`) embed sing-box 1.14.4 and Xray 26.10.31.
- Managed engine and tun2socks downloads are pinned by version and SHA-256 and
  fail closed on an unlisted platform.
- Native TUN is preferred when the engine supports it. A failure to establish
  native TUN is reported instead of silently switching to a legacy datapath.
- OpenVPN profile import validates the profile, inlines referenced certificate
  and key files, confines file references to the profile directory, removes
  credential files from the profile, and rejects directives that execute code
  or change host state.

### Routing

- Rule-based routing supports `geoip:`, `geosite:`, `domain`,
  `domain_suffix`, `ip_cidr` and `default` matchers.
- Routing edits warn when a direct rule and a tunnel rule overlap, because the
  overlap changes where the traffic exits. Warnings no longer assume a country
  or a geographic location.
- Legacy whitelist configuration still loads, with a deprecation notice.

### Security and privacy

- No provider account, profile, certificate, key, subscription address or
  personal credential ships in the source tree, configuration defaults, tests,
  fixtures, documentation or release assets.
- Documentation and fixtures use documentation IP ranges (RFC 5737) and
  `.example` domains.
- The public source tree and history are independently audited; the release
  branch does not inherit the private development history.

### Known limitations

- IPv6 gateway egress is not validated; forwarded IPv6 is dropped in gateway
  mode.
- Supported release targets are Linux amd64 and Linux arm64. arm64 validation
  was performed in an emulated environment; no native arm64 board was used.
- Country routing needs external geo data from the v2fly release feeds, which
  are not hash-pinned in this pre-release.
- OpenVPN links require an external sing-box 1.14+ binary.
- The proxy listener has no client authentication.
