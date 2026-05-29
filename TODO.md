# Bypath — TODO

## 🔴 Priority

- [ ] **VPN detection bypass** — Mobile carrier apps (Irancell, Hamrah-e-Aval) call `cloudflare.com/cdn-cgi/trace` and detect VPN from the `loc` field. Force these endpoints direct so they always return `loc=IR`. Known domains: `cloudflare.com/cdn-cgi/trace`, `ip-api.com`, `ipinfo.io`, `api.myip.com`.
- [ ] **sing-box TUN inbound** — Remove tun2socks and dns2socks. Let sing-box create TUN device + handle DNS. Result: one less process, lower latency.
- [ ] **xray fallback** — If sing-box fails with a config, automatically try xray + tun2socks.
- [ ] **Reality support** — Read pbk, sid, fingerprint from profile and put in sing-box config. Currently reality links fail silently.
- [ ] **digikala proxy mode** — digikala.com times out because DNS resolves to non-IR CDN IP via tunnel DNS. Need geosite-ir or domain-based whitelist rules.
- [ ] **CDN links HTTPS issue** — CDN-based vless links (Cloudflare Workers, port 443) only relay HTTP, not HTTPS. Need to detect and warn user, or auto-skip for HTTPS-required use.

## 🟡 Medium

- [ ] **Auto-reconnect** — If tunnel drops, auto reconnect. If 3 failures, switch to next link.
- [ ] **Health check timer** — Every 60s connectivity check. If fail → restart engine.
- [ ] **systemd installer** — `bypath install` creates and enables service file.
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

## ✅ Done (v2.3.0)

- [x] TUI redesign — tab-based (Home / Servers / Subscriptions)
- [x] Inline speed test in Servers tab (p=ping, s=full, t=single)
- [x] Download speed test (KB/s via cloudflare speed endpoint)
- [x] SOCKS5 and HTTP proxy as outbound protocol
- [x] HTTP proxy inbound (port 8888)
- [x] API token authentication
- [x] PID file management (no more pkill)
- [x] Server delete (CLI + TUI)
- [x] Subscription delete (CLI + TUI)
- [x] Group create/rename from TUI
- [x] Default group protection (subs auto-create named groups)
- [x] Active link indicator (⚡) in server list
- [x] Auto-restart gateway on server select
- [x] Status check (relay delay + exit IP + country)
- [x] Sub update via proxy (for filtered sub URLs)
- [x] Engine selection (sing-box vs xray) via config
- [x] SNI spoofing via config
- [x] SNI comma-separated fix in configgen
- [x] TLS insecure for vless (CDN compatibility)
- [x] DNS circular dependency fix (no detour on DNS server)
- [x] Whitelist working in proxy mode (sniff + resolve + geoip)
- [x] Gateway fallback searches correct group
- [x] Skip info links (port<10, 0.0.0.0) everywhere
- [x] Verify connection uses socks5h + cp.cloudflare.com
- [x] Race condition fix in TUI (tea.Cmd instead of goroutine)
- [x] `sub update` without -g updates all groups
- [x] `list` shows all groups with links
- [x] `select -g` flag support

## ✅ Done (v2.2.0)

- [x] Whitelist IR moved from iptables/ipset to sing-box geoip rule_set
- [x] TUI menu (bubbletea) — start/stop/status/sub without flash
- [x] TUI bench page — live progress, ping/relay, sort, select
- [x] Parallel bench — all links tested simultaneously
- [x] vless/reality/comma-SNI fix in config generation
- [x] Column alignment with runewidth
- [x] Subscription support (add/update/list)
- [x] Auto-fallback — if first link fails, try others
- [x] CLI commands: run, stop, add, list, select, bench, sub, test, engines, update
- [x] CI/CD pipeline (GitHub Actions) — test, lint, build, release
- [x] Docker integration test (lite + full build from scratch)
- [x] Auto-release on push to main (dev build)
- [x] sing-box 1.13 compatibility (route actions, local geoip, DNS over tunnel)
- [x] Proxy mode whitelist (sniff + resolve via tunnel DNS + geoip-ir)
- [x] Update checker with proper semver comparison
- [x] TUI update notification
- [x] Dead code cleanup (removed legacy fetcher, unused methods)

## ⚠️ Known Issues

- CDN-based vless links (Cloudflare Workers, port 443 with TLS) only relay HTTP traffic, not HTTPS. These links work for bench (short HTTP test) but fail for real browsing.
- `VLDR` type links with comma-separated SNI lists need the first-entry fix (done in configgen, but bench uses different code path in main.go — both fixed now).
- sing-box 1.13 rejects `detour: "direct"` on DNS servers — must use no detour.
- Gateway verify needs 2s delay after sing-box start (port ready ≠ outbound ready).
- Some subscription URLs are only accessible via proxy (use `o`/`p` in TUI to update via tunnel).
- `sub update` replaces ALL links in a group (by design — subscription is source of truth for that group).
