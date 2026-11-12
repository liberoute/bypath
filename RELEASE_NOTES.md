# Bypath v3.0.0-rc.2 — pre-release

The second public release candidate of Bypath, a self-hosted network gateway
and proxy manager, containing reliability corrections for rc.1. This is a
**pre-release**: it is not marked "latest", it is not a stable release, and it
makes no support claim beyond the targets below.

## Changes in rc.2

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

## Install

```bash
VERSION=v3.0.0-rc.2
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
| `bypath-linux-amd64` | Linux amd64 binary (`-tags full`) |
| `bypath-linux-arm64` | Linux arm64 binary (`-tags full`) |
| `SHA256SUMS` | SHA-256 of every asset above and `THIRD_PARTY_NOTICES.md` |
| `THIRD_PARTY_NOTICES.md` | Dependency inventory and licenses |

The binaries embed sing-box 1.14.4 and Xray-core 26.10.31, and the pinned
tun2socks 2.5.2 helper. Licence: GPL-3.0-or-later, as a combined work with
sing-box and tun2socks (GPL-3.0) and Xray-core (MPL-2.0). Sources for the
pinned dependencies are listed in `THIRD_PARTY_NOTICES.md`.

## Supported platforms

| Platform | Status |
|---|---|
| Debian/Ubuntu amd64 | Installed and exercised on a clean virtual machine |
| Debian/Ubuntu/Armbian arm64 | Exercised under emulation only; no native arm64 board was used |
| Other amd64/arm64 distributions | Best effort, no claim |
| armv7, 386, riscv64, Windows, macOS | Not built; refused by the installer |

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

## Known limitations

- IPv6 gateway egress is not validated; forwarded IPv6 is dropped in gateway
  mode.
- arm64 was validated under emulation only.
- Country routing needs external geo data whose feeds are not hash-pinned in
  this pre-release.
- OpenVPN links require an external sing-box 1.14+ binary; no OpenVPN profile
  ships with this release.
- The proxy listener has no client authentication; keep it on loopback or
  restrict it to trusted client subnets and Bypath's firewall allow-list.
- Native TUN requires a host that permits TUN and firewall changes. Container
  installs where `/etc/resolv.conf` is bind-mounted can use proxy-only mode.

## Reporting problems

Attach `bypath version`, `sudo bypath doctor --json` and `sudo journalctl -u
bypath -n 200 --no-pager`. Review them first: they redact credentials, tokens
and subscription URLs, but hostnames, interface names and addresses remain
visible.
