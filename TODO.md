# Bypath — TODO

## 🔴 Priority

- [x] **install.sh** — Interactive installer script with auto-install of all dependencies
- [x] **Configurable SOCKS port** — Read from `server.socks_port` in config (default: 2801)
- [x] **Auto-create default.yaml** — On first run, generate config with sane defaults
- [x] **Path resolution** — Auto-detect installed vs local mode (internal/paths package)
- [x] **Remove separate HTTP proxy** — Mixed inbound handles both SOCKS5 and HTTP
- [x] **TUI port change** — Change SOCKS port from TUI Home tab
- [x] **sing-box 1.11 DNS fix** — Use `address: "udp://1.1.1.1"` format
- [ ] **VPN detection bypass** — Mobile carrier apps (Irancell, Hamrah-e-Aval) call `cloudflare.com/cdn-cgi/trace` and detect VPN from the `loc` field. Force these endpoints direct so they always return `loc=IR`. Known domains: `cloudflare.com/cdn-cgi/trace`, `ip-api.com`, `ipinfo.io`, `api.myip.com`.
- [ ] **sing-box TUN inbound** — Remove tun2socks and dns2socks. Let sing-box create TUN device + handle DNS. Result: one less process, lower latency.
- [ ] **xray fallback** — If sing-box fails with a config, automatically try xray + tun2socks.
- [ ] **Reality support** — Read pbk, sid, fingerprint from profile and put in sing-box config. Currently reality links fail silently.
- [ ] **digikala proxy mode** — digikala.com times out because DNS resolves to non-IR CDN IP via tunnel DNS. Need geosite-ir or domain-based whitelist rules.
- [ ] **CDN links HTTPS issue** — CDN-based vless links (Cloudflare Workers, port 443) only relay HTTP, not HTTPS. Need to detect and warn user, or auto-skip for HTTPS-required use.

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

## 🟢 Nice to have

- [ ] **Web UI** — Simple embedded dashboard (static files). Status, switch link, bench from browser.
- [ ] **Metrics (Prometheus)** — `/metrics` endpoint for monitoring.
- [ ] **Windows gateway** — WinDivert for routing without TUN.
- [ ] **mTLS for API** — API accessible only with certificate.
- [ ] **Multi-hop chain** — hop1 (vmess) → hop2 (wireguard) → internet.
- [ ] **sing-box as Go library** — Instead of spawning process, run in-process (full build).
- [ ] **xray as Go library** — Same as above for xray.
- [ ] **Config hot-reload** — Change config without restart.
- [ ] **Per-client routing** — Each client (MAC/IP) has separate rules.
- [ ] **Bandwidth limiter** — Per-client speed limit.
- [ ] **TUI: server details view** — Show full link info (URI, all params) on a detail page.
- [ ] **Export/import profiles** — Share configs between devices.

## ✅ Done (moved to CHANGELOG.md)

## ⚠️ Known Issues

- CDN-based vless links (Cloudflare Workers, port 443 with TLS) only relay HTTP traffic, not HTTPS. These links work for bench (short HTTP test) but fail for real browsing.
- `VLDR` type links with comma-separated SNI lists need the first-entry fix (done in configgen, but bench uses different code path in main.go — both fixed now).
- sing-box 1.13 rejects `detour: "direct"` on DNS servers — must use no detour.
- Gateway verify needs 2s delay after sing-box start (port ready ≠ outbound ready).
- Some subscription URLs are only accessible via proxy (use `o`/`p` in TUI to update via tunnel).
- `sub update` replaces ALL links in a group (by design — subscription is source of truth for that group).
