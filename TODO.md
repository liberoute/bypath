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
- [x] **geosite rule_set consistency** — DNS rules only reference tags that are defined in route rule_set section
- [x] **xray downloader** — Extract binary from zip/tar.gz, clean up archive, verify binary exists
- [x] **geo multi-country** — Download geoip+geosite .srs for all supported countries (ir, cn, us, ru, tr, de, fr, gb, ae)
- [x] **bypath version geo status** — Per-country .srs status, Gateway Helpers section (tun2socks/dns2socks arch validation)
- [x] **GitHub releases** — CI/CD pipeline publishes lite+full binaries for all targets on tag push
- [ ] **CDN links HTTPS issue** — CDN-based vless links only relay HTTP, not HTTPS. Detect and warn user.

## 🟡 Medium

- [ ] **Auto-reconnect** — If tunnel drops, auto reconnect. If 3 failures, switch to next link.
- [ ] **Health check timer** — Every 60s connectivity check. If fail → restart engine.
- [x] **systemd installer** — install.sh creates and enables service file.
- [ ] **Subscription auto-update** — Every 24h auto sub update (timer or goroutine).
- [ ] **DHCP server** — Clients auto-get DNS/GW. No manual config needed.
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
- xray domainStrategy fixed: IPIfNonMatch (was AsIs, then fixed again in v2.5.6)
- install.sh proxy support + geo multi-country download
- per-link engine fallback (sing-box ↔ xray)
- verifyConnection hang fix under native TUN mode

## ⚠️ Known Issues

- CDN-based vless links (Cloudflare Workers, port 443 with TLS) only relay HTTP traffic, not HTTPS.
- Some subscription server links only accept connections from Iranian IPs (server-side restriction).
- sing-box 1.13 rejects `detour: "direct"` on DNS servers — must use no detour.
- Gateway verify needs 2s delay after sing-box start (port ready ≠ outbound ready).
- Some subscription URLs are only accessible via proxy (use `o`/`p` in TUI to update via tunnel).
- `sub update` replaces ALL links in a group (by design — subscription is source of truth for that group).
- geosite .srs only available for `ir` and `cn` from Chocolate4U; other countries have geoip only.
