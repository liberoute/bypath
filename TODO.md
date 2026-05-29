# Bypath — TODO

## 🔴 Priority

- [ ] **VPN detection bypass** — Mobile carrier apps (Irancell, Hamrah-e-Aval) call `cloudflare.com/cdn-cgi/trace` and detect VPN from the `loc` field. Force these endpoints direct so they always return `loc=IR`. Known domains: `cloudflare.com/cdn-cgi/trace`, `ip-api.com`, `ipinfo.io`, `api.myip.com`.
- [ ] **sing-box TUN inbound** — Remove tun2socks and dns2socks. Let sing-box create TUN device + handle DNS. Result: one less process, lower latency.
- [ ] **xray fallback** — If sing-box fails with a config, automatically try xray + tun2socks.
- [ ] **Full build (zero deps)** — Embed sing-box + xray + tun2socks in the binary. User downloads one file.
- [ ] **Reality support** — Read pbk, sid, fingerprint from profile and put in sing-box config. Currently reality links fail.
- [ ] **TUI bench: download/upload** — After ping and relay, real speed test (download KB/s).
- [ ] **digikala proxy mode** — digikala.com times out in proxy mode because DNS resolves to non-IR CDN IP via tunnel DNS. Need geosite-ir or domain-based whitelist rules.

## 🟡 Medium

- [ ] **Auto-reconnect** — If tunnel drops, auto reconnect. If 3 failures, switch to next link.
- [ ] **Health check timer** — Every 60s connectivity check. If fail → restart engine.
- [ ] **systemd installer** — `bypath install` creates and enables service file.
- [ ] **Subscription auto-update** — Every 24h auto sub update (timer or goroutine).
- [ ] **DHCP server** — Clients auto-get DNS/GW. No manual config needed.
- [ ] **Bench: skip info links** — Links with port 0 or Farsi address should be skipped (partially done).
- [ ] **sing-box 1.14 migration** — Remove deprecated env vars, use proper `domain_resolver` and new DNS server format.

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

## ✅ Done

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
