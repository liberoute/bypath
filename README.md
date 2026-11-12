# Bypath

Bypath is a self-hosted network gateway for Linux. It routes traffic from your
own devices through a proxy server you control, either transparently (devices
use the Bypath machine as their gateway and DNS server) or as a SOCKS5/HTTP
proxy for individual applications.

Bypath is provider-neutral. It ships with no account, no subscription, no
server, no credentials and no routing policy based on where you live. You add
your own connection (a proxy URI or a subscription URL you are entitled to use)
during first-run setup.

> **Pre-release:** `v3.0.0-rc.1`. This is a release candidate for testing. It is
> not marked "latest" on GitHub and it is not a stable release. Read
> [RELEASE_NOTES.md](RELEASE_NOTES.md) and [SECURITY.md](SECURITY.md) before
> exposing it to a network.

## Modes

| Mode | What Bypath changes | Who uses it |
|---|---|---|
| **Proxy-only** | Opens a mixed SOCKS5/HTTP listener on localhost. No routes, DNS, firewall or interface changes. | Applications configured to use a proxy. |
| **Transparent gateway** | Clients set their gateway and DNS to the Bypath host. Bypath creates a TUN device, redirects DNS and installs its own scoped firewall chains. | Devices that cannot use a proxy directly. |

A fresh installation is proxy-only with the gateway disabled. Bypath never
starts an empty full-tunnel gateway: the gateway is only enabled after a
connection has been imported, selected and verified.

This release is tested on **Linux amd64** and **Linux arm64**. Debian, Ubuntu
and Debian-derived distributions are the intended targets. Other platforms and
architectures are unbuilt or unverified; the installer refuses them unless you
pass `--allow-unsupported`, and no support is claimed for them. Windows and
macOS builds are not part of this release.

## Install

The release is version-pinned. Download the installer and the checksum list
from the release you intend to install, verify them, then run the installer.
Do not use a `/releases/latest` URL.

```bash
VERSION=v3.0.0-rc.1
curl -fsSLO "https://github.com/liberoute/bypath/releases/download/$VERSION/install.sh"
curl -fsSLO "https://github.com/liberoute/bypath/releases/download/$VERSION/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS
sudo bash install.sh --version "$VERSION"
```

The installer:

- detects the distribution, architecture, systemd, TUN, iptables/nftables,
  existing DNS services, port conflicts, memory, disk and any existing install;
- downloads the matching `bypath-linux-<arch>` binary and verifies its SHA-256
  against the release `SHA256SUMS` before installing;
- installs to `/opt/bypath/bypath`, links `/usr/local/bin/bypath`, creates the
  `bypath` system group and writes a systemd unit **without enabling or
  starting it**;
- hands off to the interactive first-run wizard, which reviews the
  configuration and starts nothing that was not confirmed.

It never stops `systemd-resolved`, `dnsmasq`, NetworkManager or another VPN,
never rewrites `/etc/resolv.conf`, never changes routes, DHCP or the default
gateway, and never opens a listener on the LAN without an explicit answer.

Useful installer options:

| Option | Effect |
|---|---|
| `--dry-run` | Report the host and the plan; change nothing. Works unprivileged. |
| `--non-interactive` | Take every first-run answer from flags. |
| `--mode proxy\|gateway` | First-run mode. |
| `--interface NAME`, `--trusted-cidr CIDR` | Gateway/LAN specifics. Never assumed. |
| `--socks-port`, `--listen localhost\|lan\|all`, `--listen-ip` | Proxy listener. |
| `--dns-port`, `--dns-upstream` | Gateway DNS. |
| `--web off\|loopback\|lan`, `--web-port` | Management panel listener. |
| `--uri`, `--subscription`, `--group`, `--select` | Import and select a connection during setup. |
| `--start-service`, `--enable-gateway` | Explicitly start the unit / enable gateway mode after review. |
| `--uninstall`, `--purge`, `--rollback` | Remove (keep data), remove everything, or restore the previous binary. |

See [INSTALL.md](INSTALL.md) for the full procedure, the non-interactive form
and recovery steps.

## First run

`bypath setup` walks through ten steps. Every answer is printed back in a
review block before anything is written:

1. LAN interface (only detected interfaces are offered; nothing is assumed).
2. Trusted client subnets (required before the proxy can listen on the LAN).
3. Mode: transparent gateway or proxy-only.
4. Proxy port (default `2801`).
5. Proxy listener: localhost, the detected LAN address, or all IPv4 interfaces.
6. DNS: gateway port and upstreams. A busy port 53 is reported, never stolen.
7. A proxy URI, a subscription URL, or skip.
8. The action to take for the first connection: select and verify it.
9. Management panel: off, loopback, or LAN with authentication.
10. Review, then activation. Gateway mode stays staged and disabled until you
    verify a connection.

Then check the result:

```bash
bypath doctor            # read-only report
bypath doctor -v         # include per-check detail
bypath doctor --json     # machine-readable report
bypath doctor --egress   # measure tunnel and direct exit addresses
```

`bypath doctor` reports configuration validity, engine compatibility, TUN and
native-TUN availability, routing and fail-closed DNS rules, DNS service
conflicts, trusted-LAN and firewall state, management API and panel exposure,
proxy listener reachability, connection configuration and, when the gateway is
running, verified tunnel egress. It changes nothing on its own. With the
exception of `--egress`, which sends network requests to measure exit
addresses, it is read-only. It never prints credentials, raw subscription URLs
or unredacted link URIs.

## Daily use

```bash
bypath status                   # gateway state and tunnel health
bypath run                      # start the gateway in the foreground
bypath stop                     # stop the daemon and its listeners
bypath list                     # connections and groups
bypath select <name|number>     # choose the active connection
bypath sub add <url>            # register a subscription (creates its group)
bypath sub update               # refresh subscriptions
bypath bench --auto             # bounded speed test, select the best link
bypath engines                  # engine availability
bypath version                  # version, commit, build variant
bypath                          # interactive terminal UI
```

The browser panel is disabled by default. When enabled it listens on loopback
and the first local visit creates the administrator account. It is a separate
surface from the SOCKS/HTTP proxy and from the internal management API.

## Access model

The daemon runs as root and exposes one management surface through the CLI,
the TUI and the web panel. They share one application contract and the same
authority.

- **The `bypath` system group is privileged administration.** Membership is
  equivalent to membership in `sudo` or `docker`: a member can redirect the
  tunnel, read stored credentials and change the listeners. Add only trusted
  administrators.
- **The management API needs a credential.** The API binds `127.0.0.1:8080` by
  default. A root daemon refuses tokenless TCP access; the CLI and TUI use the
  control socket. A panel session or `server.api_token` is required over TCP.
- **The SOCKS/HTTP proxy is unauthenticated.** It binds loopback unless you
  explicitly configure a LAN bind. A LAN bind requires the trusted-CIDR
  allow-list, which is validated against the host's interfaces; Bypath installs
  its own firewall rules that reject other sources.
- **The control socket is a filesystem boundary**, `root:bypath`, mode `0660`.
  It protects the API token and the configuration file from disclosure; it does
  not limit what a member can make the daemon do.

## How routing works

Rules map traffic to the `direct` outbound, the `proxy` outbound, or a named
external outbound. They are evaluated in order and private IP ranges always go
direct. A fresh installation ships one rule — `default → proxy` — and no
country or personal exception. Country rules are opt-in, for example:

```yaml
routing:
  rules:
    - match: geoip:<cc>          # country code you choose
      outbound: direct
    - match: geosite:<cc>
      outbound: direct
    - match: default
      outbound: proxy
```

Bypath warns when an edit sends traffic direct while another rule tunnels an
overlapping domain, because that changes where traffic exits. It does not assume
where you are or which sites should stay local.

## Engines and protocols

Bypath supports VMess, VLESS (including Reality, XHTTP and VLESS Encryption),
Trojan, Shadowsocks, WireGuard, SSH, SOCKS5 and HTTP URI links, plus OpenVPN
profile files. Which links an engine can serve depends on the engine. This
release is built with both engines embedded:

| Engine | Notes |
|---|---|
| sing-box 1.14.4 | Embedded. Native TUN for transparent gateway mode. Required for OpenVPN endpoint support. |
| Xray 26.10.31 | Embedded. Required for XHTTP and VLESS Encryption links. Country rules need `geoip.dat`/`geosite.dat`, fetched at runtime from the v2fly release feeds without a pinned hash. |

Tun2socks is used only when a selected engine cannot provide a native TUN
datapath. In a `full` build it is embedded; otherwise Bypath uses a
checksum-pinned download or an existing binary on `PATH`. Bypath never silently
switches a native-TUN gateway to a legacy datapath; if native TUN fails, the
startup fails and the reason is reported.

OpenVPN profiles are validated at import and stored self-contained (external
certificate, key and TLS files are inlined). Directives that execute code or
change host state (`up`, `down`, `plugin`, `script-security`, `route-up`,
`management`, ...) are rejected. The profile directory is confined: absolute
paths, UNC/drive-letter paths and traversal outside it are refused. OpenVPN
profiles are run through an external sing-box binary of version 1.14 or newer,
because the endpoint runner is only validated there.

## Requirements (gateway mode)

- Root, `iptables`, `iproute2`, TUN support (`/dev/net/tun`).
- systemd is recommended for supervision. Without it the gateway must be
  supervised by another service manager.
- Port 53 must be free for gateway DNS. Bypath will not take it from an existing
  resolver; you must resolve the conflict yourself or choose proxy-only mode.

Proxy-only mode needs only the binary and a reachable proxy endpoint.

## Building from source

```bash
git clone https://github.com/liberoute/bypath.git
cd bypath
git checkout v3.0.0-rc.1
make build          # host build, no embedded engines
make build-full     # embedded sing-box + xray (matches release binaries)
```

Release binaries are built with `-tags full` for `linux/amd64` and
`linux/arm64`. Cross-compilation alone is not a support claim.

## Documentation

- [QUICKSTART.md](QUICKSTART.md) — install to first working connection.
- [INSTALL.md](INSTALL.md) — installer options, non-interactive install,
  upgrade, rollback, uninstall.
- [CONFIGURATION.md](CONFIGURATION.md) — configuration reference.
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — diagnosis and common failures.
- [SECURITY.md](SECURITY.md) — threat model, exposure rules and reporting.
- [RELEASE_NOTES.md](RELEASE_NOTES.md) — what this pre-release contains and
  what it does not.
- [CHANGELOG.md](CHANGELOG.md) — changes in this release.
- [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) — embedded components and
  their licenses.

## Limitations

- IPv6 gateway egress is not validated. Gateway mode drops forwarded IPv6
  instead of leaking it; IPv4 is the supported gateway path.
- Only Linux amd64 and arm64 are built and tested for this release. arm64 was
  exercised in an emulated environment; see [RELEASE_NOTES.md](RELEASE_NOTES.md).
- Country routing depends on external geo data. Missing geo files fail the rule
  rather than silently matching everything.
- The proxy listener itself has no client authentication. Access control is the
  bind address, the trusted-CIDR allow-list and Bypath's firewall rules.
- A proxy URI or profile you import is your responsibility to use lawfully and
  within the provider's terms.

## License

Bypath is distributed under the **GNU General Public License, version 3 or
later**. See [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
The full release build embeds GPL-3.0 sing-box code, which is why the combined
work is distributed under GPL-3.0-or-later.
