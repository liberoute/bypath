# Bypath — TODO

## 🔴 Priority

- [x] **install.sh** — Interactive installer with auto-install of all dependencies + proxy support + non-interactive mode
- [x] **Configurable SOCKS port** — Read from `server.socks_port` in config (default: 2801)
- [x] **Auto-create default.yaml** — On first run, generate config with sane defaults
- [x] **Path resolution** — Auto-detect installed vs local mode (internal/paths package)
- [x] **Remove separate HTTP proxy** — Mixed inbound handles both SOCKS5 and HTTP
- [x] **TUI port change** — Change SOCKS port from TUI Home tab
- [x] **sing-box 1.12+ DNS fix** — Use `{"type":"udp","server":"1.1.1.1","server_port":53}` format
- [x] **VPN detection bypass** — bypass_domains for direct routing of detection endpoints
- [x] **sing-box TUN inbound** — Native TUN mode: sing-box creates TUN + handles DNS natively
- [x] **xray fallback** — Per-link engine fallback: if sing-box fails, automatically try xray (and vice versa)
- [x] **Reality support** — pbk/sid/fingerprint from VLESS URI → sing-box utls + xray realitySettings
- [x] **xray domainStrategy** — IPIfNonMatch for socks5h compatibility (geoip:ir matches even when browser sends domain)
- [x] **verifyConnection native TUN** — Use `--interface localIP` to bypass auto_route when checking connectivity
- [x] **verifyConnection CDN false positive** — Use gstatic.com/msftconnecttest.com/captive.apple.com instead of cp.cloudflare.com (CDN edge always answers the old check, giving false success)
- [x] **xray geosite guard** — `xrayGeositeAvailable()` skips geosite:ir rule when geosite.dat is missing; prevents xray crash on devices without xray system package
- [x] **geosite rule_set consistency** — DNS rules only reference tags that are defined in route rule_set section
- [x] **xray downloader** — Extract binary from zip/tar.gz, clean up archive, verify binary exists
- [x] **geo multi-country** — Download geoip+geosite .srs for all supported countries (ir, cn, us, ru, tr, de, fr, gb, ae)
- [x] **bypath version geo status** — Per-country .srs status, Gateway Helpers section (tun2socks/dns2socks arch validation)
- [x] **GitHub releases** — CI/CD pipeline publishes lite+full binaries for all targets on tag push
- [x] **Self-healing gateway** — `cleanupPreviousRun()` on every `Start()`: kills tracked child PIDs, flushes iptables/routing, restores resolv.conf. Crash or kill -9 no longer breaks the network.
- [x] **DNS intercept for DHCP clients** — iptables PREROUTING REDIRECT `:53 → bypath dns_port` in both modes. LAN clients with DHCP-assigned DNS need no manual change.
- [x] **resolv.conf backup/restore** — Backs up original before overwriting; restores on stop.
- [x] **sub update while running** — Routes subscription HTTP through local SOCKS proxy when bypath is active (avoids stale resolv.conf → 127.0.0.1).
- [x] **bench all groups** — `bypath bench` (no `-g`) tests every group, shows per-group results, selects best across all groups.
- [x] **systemd crash loop** — `StartLimitIntervalSec=0` + `PrivateTmp=false` in service unit.
- [x] **CDN links HTTPS issue** — CDN-based vless links only relay HTTP, not HTTPS. Gateway now async-tests HTTPS after start and warns if CDN link can't relay it.

## 🟡 Medium

- [ ] **Auto-reconnect** — If tunnel drops, auto reconnect. If 3 failures, switch to next link.
- [ ] **Health check timer** — Every 60s connectivity check. If fail → restart engine.
- [x] **systemd installer** — install.sh creates and enables service file.
- [ ] **Subscription auto-update** — Every 24h auto sub update (timer or goroutine).
- [~] **DHCP server** — DNS intercept via iptables REDIRECT is in place (v2.5.8). Full DHCP server (auto-push GW setting) still pending.
- [ ] **sing-box 1.14 migration** — Remove deprecated env vars, use proper `domain_resolver` and new DNS server format.
- [ ] **Upload speed test** — Add upload test to bench (currently only download).
- [ ] **Full build (zero deps)** — Embed sing-box + xray + tun2socks in the binary.
- [ ] **TUI: confirm dialogs** — Before delete/restart, ask "are you sure?"
- [x] **tun2socks arch validation** — Detect wrong-arch binary on install, auto-reinstall correct version.
- [x] **xray geo data in install.sh** — Download geoip.dat/geosite.dat for xray if missing.

## 🟢 Nice to have

- [ ] **Web UI** — Simple embedded dashboard (static files). Status, switch link, bench from browser.
- [ ] **Metrics (Prometheus)** — `/metrics` endpoint for monitoring.
- [ ] **Windows gateway** — WinDivert for routing without TUN.
- [ ] **mTLS for API** — API accessible only with certificate.
- [ ] **Multi-hop chain** (In Progress) — Core configgen & CLI implemented; API/TUI/Status pending.
- [ ] **sing-box as Go library** — Run in-process instead of spawning (full build).
- [ ] **xray as Go library** — Same as above for xray.
- [ ] **Config hot-reload** — Change config without restart.
- [ ] **Per-client routing** — Each client (MAC/IP) has separate rules.
- [ ] **Bandwidth limiter** — Per-client speed limit.
- [ ] **TUI: server details view** — Show full link info on a detail page.
- [ ] **Export/import profiles** — Share configs between devices.

## ✅ Done (moved to CHANGELOG.md)

- VLDR bug with comma-separated SNI lists fixed in configgen and main.go bench.
- xray domainStrategy: `IPIfNonMatch` (final; dns2socks resolves via tunnel → real IPs → geoip:ir correct)
- install.sh proxy support + geo multi-country download
- per-link engine fallback (sing-box ↔ xray)
- verifyConnection hang fix under native TUN mode
- self-healing cleanupPreviousRun, DNS intercept, resolv.conf lifecycle (v2.5.8)

## ⚠️ Known Issues

- CDN-based vless links (Cloudflare Workers, port 443 with TLS) only relay HTTP traffic, not HTTPS.
- Some subscription server links only accept connections from Iranian IPs (server-side restriction).
- sing-box 1.13 rejects `detour: "direct"` on DNS servers — must use no detour.
- Gateway verify needs 2s delay after sing-box start (port ready ≠ outbound ready).
- Some subscription URLs are only accessible via proxy (CLI `bypath sub update` now auto-routes via SOCKS if bypath is running; TUI also supports `o`/`p`).
- `sub update` replaces ALL links in a group (by design — subscription is source of truth for that group).
- geosite .srs only available for `ir` and `cn` from Chocolate4U; other countries have geoip only.
