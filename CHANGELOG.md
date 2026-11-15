# Changelog

This branch starts a new, independently constructed public history for Bypath.
Earlier internal development history is not part of it. Entries below describe
the public release candidate only.

## v3.0.0-rc.3 — pre-release

Connectivity corrections for rc.2, built on the rc.2 tree. `main` and the rc.1/rc.2 tags are
unchanged. Release candidate; the public tag is created from the reviewed export.

### WebSocket links over TLS

- A `ws` link that advertises `alpn=h2` (as some subscription providers do) no
  longer offers HTTP/2. A WebSocket upgrade is HTTP/1.1 (RFC 6455); when the
  server negotiated h2 the upgrade was rejected and every tunnelled request
  failed with EOF even though TCP, DNS and the certificate were fine. Both the
  sing-box and the Xray generator now negotiate `http/1.1` only for WebSocket
  transports, and leave other transports' ALPN untouched.
- Reproduced in the emulated ARM64 lab against a lab subscription fixture:
  `alpn=h2` ended in EOF,
  `alpn=http/1.1` returned HTTP 204 in 1.9 s. Regression test added.

### Selecting the connection shown by `bypath list`

- `bypath list` prints the display name (flag emoji stripped, provider prefix
  removed, truncated); `bypath select` compared only the raw remark, so an
  operator could not select the name that was shown. `select` now accepts the
  displayed name when it identifies exactly one link, keeps an exact raw match
  preferred, and refuses an ambiguous name with a pointer to the list index.

### Embedded engine and uTLS

- Full builds now compile sing-box with `with_utls` (Makefile, CI matrix and
  the embed-tag job), so links with a uTLS fingerprint (`fp=chrome`) start the
  embedded engine instead of failing and falling back to a downloaded binary.
- A new engine test starts a synthetic VLESS+TLS+ws outbound with a fingerprint
  and fails when the build lacks the tag, so a release tag set that drops
  `with_utls` breaks CI instead of degrading at runtime.
- The CI build step passes multi-word tag sets to `go build` as a single
  argument.

### Country split routing (opt-in)

- `routing.country_split` makes one country's published domain list and IP
  ranges go direct while every unmatched destination keeps the proxy default.
  Empty keeps the shipped proxy-only policy; the panel and the API toggle it.
- The panel plan and the generated engine config come from the same ordered
  rule list. Geo coverage is engine-aware (sing-box `.srs` rule sets, Xray
  `.dat` categories); enabling a split provisions its assets first and refuses
  an unusable one, and an applied change is snapshot-backed and rolled back if
  the restart fails.
- The runtime gateway now passes the split to its config generator. Previously
  the panel planned the split while the engine kept proxying every destination.

### Split DNS, engine gating and geo assets (review remediation)

- The country split is refused for OpenVPN profiles (DNS stays inside the
  tunnel) in addition to Xray. The legacy tun2socks data path is untested with
  the split.

- **Correction of the earlier DNS claim.** The split's DNS behaviour for LAN
  clients comes from the gateway's own DNS forwarder, not from the engine's
  `dns-direct` routing. That forwarder used to resolve every name through the
  tunnel, so domestic names stopped resolving during a tunnel outage even
  though the split sent their connections direct. The new `gateway.direct_dns`
  is the trusted resolver for names the plan sends `direct`; proxied names never
  use it, a failure returns SERVFAIL instead of falling back to another path,
  and the panel warns when a split has no direct resolver (in that case domestic
  names still resolve through the tunnel and fail during an outage).
- **Xray refuses the country split.** Xray's DNS module cannot route a resolver
  through the tunnel, so the previous `proxyTag` design was a no-op that would
  have disclosed domestic lookups to the tunnel resolver and proxied lookups to
  a local one. Generation and apply now refuse the split on xray with that
  reason, and the panel plan marks the split entries as skipped. The xray DNS
  section is rebuilt around the tunnel resolver (first, `skipFallback`,
  `disableFallback`) with no plaintext fallback for proxied names.
- **Plan-order DNS classification.** The engine's resolve steps and the DNS
  section now walk the same ordered rule list as the route: a proxy exception
  above a DIRECT class keeps its name off the direct resolver, and a DIRECT
  default resolves unmatched names domestically. The legacy whitelist path is
  covered too.
- **Xray routing corrections.** A DIRECT/deny/named default is expressed as an
  all-addresses rule evaluated in the second `IPIfNonMatch` pass, so it no
  longer hides geoip rules; every suffix list gets a `domain:` label boundary so
  a look-alike host cannot match as a keyword; the tunnel resolver is pinned in
  front of user rules; and generation refuses a plan where an unusable proxy or
  deny geo asset would fall through to a DIRECT default.
- **Staged policy visibility.** After a reload that still needs a restart, the
  routing screen now reports `restart_required` with the pending fields instead
  of presenting the saved policy as live.
- **Pinned Xray databases.** `geoip.dat` and `geosite.dat` are downloaded from
  immutable v2fly release tags and must match the SHA-256 published with that
  release, under a size cap; a mismatch is refused and leaves the existing
  asset in place.

### Release contract

- The installer's default variant is the full build; `--variant lite` selects the
  lite build explicitly. Architectures without a published full build are refused
  with that instruction.
- Release assets are named `bypath-<variant>-<os>-<arch>` and listed in `SHA256SUMS`
  (the installer verifies against that file). Version tags and `release/**`
  branches run validation and stage the assets as a workflow artifact; they do not
  publish. Publication is a manual step.
- Release binaries take their BuildDate from the source commit time, so the same
  commit produces the same binary.
- Deferred to RC4 as documented limitations: direct resolver reachability under
  native TUN (R3-01), the native-TUN health-check false status (R3-02), the silent
  stale-pidfile exit (R3-03), and the doctor port-53 false FAIL (R3-04).

### Validation

- rc.3 final lab (2026-11-15, candidate `6cca71a`, gateway native TUN, single
  NIC, `country_split: ir`, health check enabled at 60 s): domestic HTTPS
  (`www.irna.ir`) stayed 200 and proxied HTTPS (`example.com`) failed closed
  while the tunnel server was blocked; the uplink carried no packet to the
  proxied destination. Engine SIGKILL: both failed until a manual restart,
  about 12 s to recovery. Legacy tun2socks with the split matched native TUN.
  This is lab evidence, not a field test.
- Known issues: the native-TUN health check can report `DEGRADED` /
  `EXIT_IS_UPLINK` on a healthy gateway; a stale pidfile makes `run` exit
  silently with status 1; `bypath doctor` reports port 53 as in use while the
  daemon itself is running. Domestic sites are unavailable while the engine is
  down (fail-closed); systemd `Restart=on-failure` restarts the service, which
  was not measured in the lab.

- Native ARM64 proxy acceptance by an external tester (Raspberry Pi / DietPi):
  HTTP 204 through the SOCKS5 listener, embedded engine running in-process, no
  missing-uTLS error. Gateway Mode was not exercised by that proxy acceptance.
- External native ARM64 beta report (REPORTED, not re-run here): proxy
  connectivity, web panel access and Gateway startup with 11 doctor checks
  passed; Iranian and international IP-check sites returned the same public IP,
  the symptom the split policy addresses.
- AMD64 lab (TESTED, sing-box, strict DNS): an Iranian domain and an Iranian IP
  went direct while `example.com` used the tunnel, and SOCKS egress differed
  from direct egress; disabling the split through the authenticated API removed
  the split rules and proxied the Iranian site; rollback restored both.
- Emulated ARM64 lab checks for the ALPN change and the embedded-engine start.

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

### Host DNS crash recovery

- The bypath resolver override now lives in `/run/systemd/resolved.conf.d` and
  is swept by the unit's `ExecStartPre`/`ExecStopPost`
  (`bypath host-dns restore`). A stop, a failed start, SIGKILL and a supervised
  restart all return the host to its own upstream; a reboot clears the `/run`
  file even if the daemon never got to clean up.
- The hook removes only a file whose content is exactly what bypath writes,
  never touches an administrator's snippet, and steps aside when the gateway
  listener is still answering so it cannot race a healthy instance. A legacy
  drop-in left in `/etc/systemd/resolved.conf.d` by an earlier build is removed
  as well.
- `systemd-resolved` is still never disabled; only its upstream is redirected
  while the gateway runs, and the restart is skipped during shutdown.

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

- Release builds (`-tags full`) embed sing-box 1.14.4 and the Xray-core library 26.3.27 (`v1.260327.0`); a managed external Xray binary is pinned to 26.10.31.
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
- Supported release targets are Linux amd64 and Linux arm64. arm64 validation by
  the project was performed in an emulated environment; an external tester's
  native proxy-mode acceptance of the earlier a20c705 candidate is REPORTED, not
  re-run and not of this build.
- Country routing needs external geo data from the v2fly release feeds, which
  are not hash-pinned in this pre-release.
- OpenVPN links require an external sing-box 1.14+ binary.
- The proxy listener has no client authentication.
