# Bypath — TODO

## 🔴 Priority


- [x] **Full build (zero deps)** — Embed sing-box + xray + tun2socks in the binary.
- [x] **TUI: confirm dialogs** — Before delete/restart, ask "are you sure?"
- [x] **Metrics (Prometheus)** — `/metrics` endpoint for monitoring.
- [x] **sing-box as Go library** — Run in-process instead of spawning (full build).
- [x] **xray as Go library** — Same as above for xray.
- [x] **Config hot-reload** — Change config without restart.
- [ ] **Auto-reconnect** — If tunnel drops, auto reconnect. If 3 failures, switch to next link.
- [ ] **Health check timer** — Every 60s connectivity check. If fail → restart engine.
- [ ] **sing-box 1.14 migration** — Remove deprecated env vars, use proper `domain_resolver` and new DNS server format.

## 🟡 Medium

- [ ] **Subscription auto-update** — Every 24h auto sub update (timer or goroutine).
- [~] **DHCP server** — DNS intercept via iptables REDIRECT is in place (v2.5.8). Full DHCP server (auto-push GW setting) still pending.
- [ ] **Upload speed test** — Add upload test to bench (currently only download).

## 🟢 Nice to have

- [ ] **Web UI** — Simple embedded dashboard (static files). Status, switch link, bench from browser.
- [ ] **Windows gateway** — WinDivert for routing without TUN.
- [ ] **mTLS for API** — API accessible only with certificate.
- [ ] **Multi-hop chain** (In Progress) — Core configgen & CLI implemented; API/TUI/Status pending.
- [ ] **Per-client routing** — Each client (MAC/IP) has separate rules.
- [ ] **Bandwidth limiter** — Per-client speed limit.
- [ ] **TUI: server details view** — Show full link info on a detail page.
- [ ] **Export/import profiles** — Share configs between devices.

## ⚠️ Known Issues

- CDN-based vless links (Cloudflare Workers, port 443 with TLS) only relay HTTP traffic, not HTTPS.
- Some subscription server links only accept connections from Iranian IPs (server-side restriction).
- sing-box 1.13 rejects `detour: "direct"` on DNS servers — must use no detour.
- Gateway verify needs 2s delay after sing-box start (port ready ≠ outbound ready).
- Some subscription URLs are only accessible via proxy (CLI `bypath sub update` now auto-routes via SOCKS if bypath is running; TUI also supports `o`/`p`).
- `sub update` replaces ALL links in a group (by design — subscription is source of truth for that group).
- geosite .srs only available for `ir` and `cn` from Chocolate4U; other countries have geoip only.
