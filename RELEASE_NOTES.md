# Bypath v3.0.0-rc.4 — pre-release

rc.4 is the fourth public release candidate of Bypath, a self-hosted network
gateway and proxy manager. It is built on the rc.3 tree and adds benchmark
approval correctness, crash-consistent proxy-guard ownership, and measurement
and speed-reporting corrections. This is a **pre-release**: it is not marked
"latest", it is not a stable release, and it makes no support claim beyond the
targets below.

## Behaviour change: benchmark selection needs approval

`bypath bench` no longer changes the selected link on its own.

- At a terminal it asks `Auto-select this link? [y/N]`; only a typed `y`/`yes`
  or `--yes` selects.
- On a pipe, closed stdin or EOF it never approves and prints
  `Selection unchanged (non-interactive; pass --yes to select the best link).`
- **`bench --auto` no longer implies approval.** On non-interactive stdin it
  refuses before benchmarking unless `--yes` is also passed: exit 1 with
  `--auto needs --yes when stdin is not a terminal; nothing was benchmarked and
  the selection is unchanged`. Cron jobs and scripts that used `bench --auto`
  must add `--yes`.
- `bench --help`/`-h` prints usage and exits 0 without probing; unknown options
  and positional arguments exit 1 with usage and change nothing.
- `--single N` still probes one row and never changes the active link; `-g`/
  `--group` filtering and row numbering are unchanged.

## Changes in rc.4

21 implementation commits since `v3.0.0-rc.3`, plus documentation-only
commits (23 in total at this review). The full technical record is in
[CHANGELOG.md](CHANGELOG.md).

- **Proxy guard lifecycle.** The guard lease is an abstract Unix socket scoped
  to the network namespace, backed by `/var/lib/bypath/proxy-guard.lock` for
  lock-aware builds. Ownership is proved from the record; record-free chains
  are never adopted; a failed install or interrupted stop touches only objects
  it can prove; a chain that cannot be attributed is retained and can block
  startup until resolved; a loopback listener needs no `iptables` access.
  Changing the installed binary follows stop → verify → swap → start (below).
- **Measurement correctness.** WebSocket early-data hints are translated for
  both engines; startup proves TLS and HTTP through the tunnel before
  CONNECTED; probes are forced through the tunnel; the uplink oracle is bound
  to the physical interface; the serving link falls back to an isolated
  instance; a carried HTTPS answer with an unproven exit is kept as
  `measured`/`exit_unverified` instead of being discarded.
- **Speed and latency.** Fast delay is reported separately from the full
  sample; transfers get a 45 s budget on top of the 25 s setup window and
  report phase, elapsed time, TLS/TTFB and bytes; a non-2xx target is
  `TARGET_REJECTED`, never a speed result.
- **Benchmark isolation and pinning.** A serving gateway caps concurrent
  benchmark sessions at one (`tests.max_sessions`, default 1, hard cap 3);
  `tests.bootstrap_dns` pins tested endpoints through validated private LAN
  resolvers and reports the failing stage.
- **CLI.** Help paths are non-interactive and pipe-safe; the bench approval gate
  and its regression suite are described above.

## Upgrade and guard migration

Changing the installed binary follows the same order for upgrades and rollback
when a proxy guard may be installed. An install or upgrade never stops, starts
or restarts the service; only `install.sh --rollback` stops a running service
before restoring the previous binary, and it starts the service again only if
it was running.

```bash
sudo bypath stop
sudo iptables -S BYPATH_PROXY_IN        # must report no chain
sudo ./install.sh --version v3.0.0-rc.4
sudo systemctl start bypath
```

Keep `/var/lib/bypath` mounted and do not delete `proxy-guard.lock` or
`BYPATH_PROXY_IN` by hand. Builds older than every lock (`d175a19`, `bb11c37`)
cannot be excluded while they run; a current daemon that detects an ownership
change stops instead of serving unguarded. If the verify step still reports a
chain, do not delete it by hand and do not proceed: automatic recovery requires
verifiable ownership, an unattributable chain is retained, and startup refuses
it. See [INSTALL.md](INSTALL.md#upgrade) and
[TROUBLESHOOTING.md](TROUBLESHOOTING.md#changing-the-binary-while-a-guard-is-installed).

## Install

```bash
VERSION=v3.0.0-rc.4
mkdir bypath-install && cd bypath-install
curl -fsSLO "https://github.com/liberoute/bypath/releases/download/$VERSION/install.sh"
curl -fsSLO "https://github.com/liberoute/bypath/releases/download/$VERSION/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS
sudo bash install.sh --version "$VERSION"
```

The installer verifies its downloads against `SHA256SUMS`, installs to
`/opt/bypath`, writes a systemd unit **without enabling or starting it**, and
then runs the ten-step first-run wizard. It never changes interfaces, routes,
DHCP, DNS resolution settings or global firewall policy, and it never stops
another resolver. See `INSTALL.md` for non-interactive, offline, rollback and
uninstall forms.

Full documentation: `README.md`, `QUICKSTART.md`, `INSTALL.md`,
`CONFIGURATION.md`, `TROUBLESHOOTING.md`, `SECURITY.md`, `CHANGELOG.md`.

## Assets

| Asset | Purpose |
|---|---|
| `install.sh` | Version-pinned installer for this tag |
| `bypath-full-linux-amd64`, `bypath-full-linux-arm64` | Default installer builds (`-tags full`) |
| `bypath-lite-linux-amd64`, `bypath-lite-linux-arm64` | Lite builds, selected with `install.sh --variant lite` |
| `bypath-full-linux-arm`, `bypath-lite-linux-arm`, `bypath-lite-linux-mipsle` | Built; installed by hand, see the platform table |
| `bypath-{full,lite}-{darwin-amd64,darwin-arm64,windows-amd64.exe}` | Built; no installer and no support claim |
| `SHA256SUMS` | SHA-256 of every asset above, `install.sh` and `THIRD_PARTY_NOTICES.md` |
| `THIRD_PARTY_NOTICES.md` | Dependency inventory and licenses |

This release publishes 13 binaries (6 full, 7 lite; see the build matrix in `.github/workflows/build.yml`), plus `install.sh`, `THIRD_PARTY_NOTICES.md` and `SHA256SUMS`: 16 files in total.

The binaries embed sing-box 1.14.4 and Xray-core library 26.3.27 (`v1.260327.0`), and the pinned
tun2socks 2.5.2 helper. Licence: GPL-3.0-or-later, as a combined work with
sing-box and tun2socks (GPL-3.0) and Xray-core (MPL-2.0). Sources for the
pinned dependencies are listed in `THIRD_PARTY_NOTICES.md`. Every asset is
verified against `SHA256SUMS`; it is not cryptographically signed.

## Supported platforms

| Platform | Status |
|---|---|
| Debian/Ubuntu amd64 | Installed and exercised on a clean virtual machine |
| Debian/Ubuntu/Armbian arm64 | Exercised under emulation by the project; an earlier candidate has an external native proxy-mode report only |
| Other amd64/arm64 distributions | Best effort, no claim |
| linux arm (armv7), linux mipsle | Built; refused by the installer, install by hand after verifying `SHA256SUMS` |
| Windows, macOS | Built (full and lite); no installer and no support claim |
| 386, riscv64 | Not built |

Cross-compilation alone is not treated as evidence of native support.

## What is in this candidate

- **Installer and first run.** Host preflight (OS, arch, systemd, TUN,
  iptables/nftables, DNS services, port conflicts, memory, disk, existing
  install), checksum-verified download, atomic install with rollback, and an
  idempotent rerun. The first-run wizard covers interface, trusted client
  subnets, gateway or proxy-only, proxy port and listener, DNS, connection
  import, verification, panel, and a review before activation.
- **Clean defaults.** A fresh configuration has no connection, no provider, no
  credential, no assumed location and no preconfigured DNS. The management API
  defaults to loopback, and a LAN proxy bind requires explicit trusted CIDRs.
- **`bypath doctor`.** Read-only report on installation, engine compatibility,
  TUN and native TUN, routing and fail-closed DNS, resolver conflicts, trusted
  LAN and firewall, panel/API exposure and authentication, proxy reachability,
  connection configuration, plus `--egress` to compare tunnel and direct exit
  addresses. `--json` for structured output.
- **Web onboarding and controls.** Empty-state guidance, source import with an
  auto-created group, selection, honest verification verdicts, clear separation
  of panel, management API and proxy listeners, and supervised restart and
  proxy-port changes that can be rolled back.
- **Benchmark control.** Results keep carried connectivity separate from a
  proven exit, rank fast delay beside the full sample, report transfer phase
  and progress, and never change the selection without explicit approval.
- **Crash-consistent proxy guard.** Guard ownership is recorded and leased.
  Stop, upgrade and rollback reconcile a chain left by a crash only when the
  record and the installed rules prove that ownership; a record-free or
  unverifiable chain is never adopted, is retained, and can block startup until
  an operator resolves it.

## Known limitations

- IPv6 gateway egress is not validated; forwarded IPv6 is dropped in gateway
  mode.
- ARMv7 and mipsle builds are published but the installer refuses them; install
  by hand after verifying `SHA256SUMS`.
- ARM64 runtime was not re-tested on native hardware for this candidate; an
  earlier candidate has an external native proxy-mode report only.
- Country routing needs external geo data. The shipped sing-box rule sets are
  pinned; the Xray feeds are refused for the split.
- OpenVPN links require an external sing-box 1.14+ binary; no OpenVPN profile
  ships with this release.
- The proxy listener has no client authentication; keep it on loopback or
  restrict it to trusted client subnets and Bypath's firewall allow-list.
- Native TUN requires a host that permits TUN and firewall changes. Container
  installs where `/etc/resolv.conf` is bind-mounted can use proxy-only mode.
- Release assets are checksum-verified with SHA-256 but are not signed.
- rc.3 deferred items R3-01 (direct resolver reachability under native TUN),
  R3-02 (native-TUN health-check false status), R3-03 (stale-pidfile exit) and
  R3-04 (doctor port-53 false FAIL) are not recorded as fixed in this
  candidate.

## Reporting problems

Attach `bypath version`, `sudo bypath doctor --json` and
`sudo journalctl -u bypath -n 200 --no-pager`. Review them first: they redact
credentials, tokens and subscription URLs, but hostnames, interface names and
addresses remain visible.

## Historical release notes

### v3.0.0-rc.3

rc.3 added the connectivity corrections and security closure described in
[CHANGELOG.md](CHANGELOG.md#v300-rc3--pre-release). Its assets remain available.
It published the same 13-binary matrix (6 full, 7 lite) as 16 files including
`SHA256SUMS`, exercised on fresh amd64 installations and under emulated arm64
only, with the same IPv6, authentication and external-geo limitations.

### Changes in rc.2

rc.2 is built from the same public tree as rc.1. `main` and the
`v3.0.0-rc.1` tag are unchanged; rc.1 remains available.

- **Exit identity no longer depends on one service.** Activation probes several
  independent address-echo services with bounded timeouts. Tunnel connectivity
  is proven separately from exit identity: if every identity service is blocked
  but traffic passes, the gateway is allowed with the exit marked UNVERIFIED —
  never Healthy or VERIFIED. An exit equal to the direct address, or a tunnel
  that carried no traffic, still fails closed. `bypath doctor --egress` uses the
  same evidence.
- **Service persistence is an explicit choice.** Installation still does not
  enable the unit. After a verified first-run start the wizard offers to enable
  it at boot (`--enable-service` for non-interactive runs) and verifies the
  result. Starting, enabling and enabling gateway mode are documented as three
  separate actions.
- **Host DNS survives a nonstandard gateway DNS port.** With a listener on, for
  example, 5335, `/etc/resolv.conf` is no longer pointed at a bare `127.0.0.1`
  that cannot express the port. When the systemd-resolved stub is in use,
  Bypath writes a managed drop-in to forward host DNS to the listener and
  removes it on stop; otherwise host DNS is left untouched and the limitation is
  logged. systemd-resolved and dnsmasq are not stopped when they do not hold the
  gateway's port.
- **The 5335 choice is explained up front.** The wizard warns that standard DHCP
  and client DNS settings cannot specify a port, so every client must be pointed
  at the gateway address and port explicitly.
- **Purge is complete.** The runtime control-socket directory
  `/run/bypath-control` is removed by uninstall and `--purge`.
