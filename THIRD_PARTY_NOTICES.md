# Third-party notices

Bypath is distributed under the GNU General Public License, version 3 or later
(see [LICENSE](LICENSE)). The `v3.0.0-rc.1` release binaries are built with
`-tags full`, which statically links the GPL-licensed sing-box libraries and,
for the legacy datapath, the GPL-licensed tun2socks binary. The combined work is
therefore distributed under GPL-3.0-or-later, and the corresponding source is
available: this repository at the release tag plus the exact module versions
pinned in `go.mod` and `go.sum`. `make build-full` reproduces the release
build. GPL-licensed components are obtained from their upstream repositories.

## Binaries in the release

| Component | Version | License | Copyright |
|---|---|---|---|
| Bypath | v3.0.0-rc.1 | GPL-3.0-or-later | Bypath contributors |
| sing-box (embedded library and CLI code) | 1.14.4 | GPL-3.0-or-later | Copyright (C) 2022 nekohasekai / SagerNet contributors |
| sagernet/sing libraries (sing, sing-tun, sing-openvpn, sing-vmess, sing-shadowsocks, sing-quic, sing-mux, sing-shadowtls and related modules) | pinned in `go.mod` | GPL-3.0-or-later | Sagernet contributors |
| tun2socks (embedded asset in `full embed_tun2socks` builds) | 2.5.2 | GPL-3.0 | xjasonlyu/tun2socks contributors |
| Xray-core (embedded library) | 26.10.31 | MPL-2.0 | XTLS and V2Ray contributors |

The source for the Xray-core files covered by the Mozilla Public License 2.0 is
available in the `github.com/xtls/xray-core` module at the version pinned in
`go.mod`. The MPL-2.0 text is available at <https://mozilla.org/MPL/2.0/>.
Modifications to MPL-covered files, if any, are part of this repository's
history at the release tag.

## Direct Go dependencies

These modules are compiled into the binaries. Each entry lists the license of
the module's own `LICENSE` file as inspected at the pinned version.

| Module | Version | License |
|---|---|---|
| github.com/charmbracelet/bubbletea | v1.3.10 | MIT |
| github.com/charmbracelet/lipgloss | v1.1.0 | MIT |
| github.com/gorilla/mux | v1.8.1 | BSD-3-Clause |
| github.com/mattn/go-runewidth | v0.0.27 | MIT |
| github.com/miekg/dns | v1.1.72 | BSD-3-Clause |
| github.com/prometheus/client_golang | v1.23.2 | Apache-2.0 |
| github.com/sagernet/sing | v0.9.7-0.20261023115459-5dc452e537bf | GPL-3.0-or-later |
| github.com/sagernet/sing-box | v1.14.4 | GPL-3.0-or-later |
| github.com/xtls/xray-core | v1.260327.0 | MPL-2.0 |
| golang.org/x/crypto | v0.54.0 | BSD-3-Clause |
| golang.org/x/sys | v0.47.0 | BSD-3-Clause |
| gopkg.in/yaml.v3 | v3.0.1 | MIT and Apache-2.0 |
| pgregory.net/rapid | v1.1.0 | MPL-2.0 (test only) |

## Transitive dependencies

`go.sum` pins every transitive module. Those modules carry their own licenses
inside their source distributions (MIT, BSD-2-Clause, BSD-3-Clause,
Apache-2.0, ISC, MPL-2.0 and GPL-3.0-or-later). Before redistributing a
modified build, review the license of every module you add or upgrade.

## Runtime dependencies

| Component | Role | License |
|---|---|---|
| External sing-box 1.14+ (optional) | Runs OpenVPN profile endpoints | GPL-3.0-or-later |
| `iptables` / `ip6tables` / `nftables` (optional) | Gateway routing and isolation rules | GPL-2.0 (iptables), GPL-2.0 (nftables) |
| `iproute2` (optional) | Routing and interface management | GPL-2.0 |
| Documentation geo data from v2fly (optional) | `geoip.dat`, `geosite.dat` for country rules | See the v2fly project |

Bypath invokes system tools; it does not bundle them. Their licenses apply to
the copies installed on your system.

## Asset digests

The embedded tun2socks binaries and the downloadable sing-box, Xray and
tun2socks artefacts are pinned by version and SHA-256 in
`internal/engine/artifacts.go` and the `Makefile`. A platform without a recorded
digest fails closed rather than downloading an unverified binary.
