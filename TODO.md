# Bypath — TODO

## 🔴 Priority

- [ ] **Cross-platform: macOS** — `detectNetwork()` crashes on darwin (runs `ip route` which doesn't exist). Fix: add darwin branch using `route -n get default`. After fix, macOS degrades to PROXY ONLY mode same as Windows. install.sh already supports darwin.
- [ ] **Cross-platform: Windows installer** — Binary works (PROXY ONLY mode). Missing: native installer. Need `install.ps1` (PowerShell) so users don't need WSL/Git Bash.
- [ ] **Cross-platform: Android** — Add `android/arm64` + `android/arm` to build matrix. Via Termux: `bypath run` works as SOCKS5 proxy (no TUN/root needed). `detectNetwork()` needs android branch (same as darwin path, uses Go `net` stdlib fallback).


## 🟡 Medium

- [ ] **Subscription auto-update** — Every 24h auto sub update (timer or goroutine).
- [~] **DHCP server** — DNS intercept via iptables REDIRECT is in place (v2.5.8). Full DHCP server (auto-push GW setting) still pending.
- [ ] **Upload speed test** — Add upload test to bench (currently only download).
- [ ] **Auto-reconnect** — If tunnel drops, auto reconnect. If 3 failures, switch to next link.
- [ ] **Health check timer** — Every 60s connectivity check. If fail → restart engine.
- [ ] **sing-box 1.14 migration** — Remove deprecated env vars, use proper `domain_resolver` and new DNS server format.

## 🟢 Nice to have

- [ ] **Web UI** — Simple embedded dashboard (static files). Status, switch link, bench from browser.
- [ ] **Windows gateway** — WinDivert for routing without TUN (full gateway, not just SOCKS5 proxy).
- [ ] **macOS gateway** — pfctl + utun for full LAN routing (full gateway, not just SOCKS5 proxy).
- [ ] **Android VPN** — Android VpnService API (requires APK, not just Termux binary).
- [ ] **mTLS for API** — API accessible only with certificate.
- [ ] **Multi-hop chain** (In Progress) — Core configgen & CLI implemented; API/TUI/Status pending.
- [ ] **Per-client routing** — Each client (MAC/IP) has separate rules.
- [ ] **Bandwidth limiter** — Per-client speed limit.
- [ ] **TUI: server details view** — Show full link info on a detail page.
- [ ] **Export/import profiles** — Share configs between devices.

## ⚠️ Known Issues

- **VLESS + XHTTP** — needs xray (not sing-box). Fixed in local `v2.6.6-xhttp` (parse mode/extra + `xhttpSettings` + auto-prefer xray). Ensure system xray is recent enough for XHTTP. **GitHub release tag still pending.**
- **Sub fetch from IR** — panel `:2083` / some CDNs TLS-timeout on direct path. Use SOCKS-after-start, env proxy, or `sub import`.
- CDN-based vless links (Cloudflare Workers, port 443 with TLS) only relay HTTP traffic, not HTTPS (older known issue; not the same as XHTTP config bug).
- Some subscription server links only accept connections from Iranian IPs (server-side restriction).
- sing-box 1.13 rejects `detour: "direct"` on DNS servers — must use no detour.
- Gateway verify needs 2s delay after sing-box start (port ready ≠ outbound ready).
- `sub update` replaces ALL links in a group (by design — subscription is source of truth for that group).
- geosite .srs only available for `ir` and `cn` from Chocolate4U; other countries have geoip only.
- **sing-box 1.13 on ARM64 gets HTTP 403 from Cloudflare Workers** — VLESS+WS CDN Workers on aarch64. Workaround: `preferred: "xray"`.

## 🧪 Next session (founder request 2026-08-12)

Canonical priorities live in **`.knowledge/00_Product_Bible/99_CURRENT_STATE.md`**.

- [ ] Full code pass: dead code / bugs
- [ ] Clean test environment install + multi-sub smoke test (WS sub + XHTTP panel + import path)
- [ ] Optional: tag/push `v2.6.6` GitHub release from current tree
