# Changelog

## v2.5.3 (2026-06-01)

### Bug Fixes
- **Active link matching** — Fixed trailing whitespace in subscription link remarks causing `GetActiveLink()` to fail silently, falling back to wrong servers
- **xray stop cleanup** — `bypath stop` now kills xray processes (previously only killed sing-box)
- **sing-box 1.13 TUN** — Fixed `inet4_address` → `address` field for sing-box 1.10+ compatibility

### Features
- **xray routing** — xray config now includes `geoip:ir` direct routing and bypass_domains support with sniffing
- **xray DNS** — Added DNS section and sniffing to xray config for proper domain resolution
- **Update download choice** — TUI self-update now asks "Direct / Over Bypath" before downloading
- **Status IP fix** — Live status now uses `icanhazip.com` for IP detection (not affected by bypass_domains)
- **bypass_domains configurable** — Removed hardcoded bypass_domains defaults; users configure in config.yaml

### Improvements
- **Build output** — Cross-compile output goes to `.tmp/` (gitignored)

## v2.5.1 (2026-06-01)

### Bug Fixes
- **Updater variant match** — lite build now downloads lite asset, full downloads full (was always downloading full)
- **Updater proxy retry** — if direct download fails, automatically retries via local SOCKS proxy (gateway connection)
- **TUI server selection** — uses `systemctl restart` when running under systemd, prevents stale engine processes
- **TUI gateway status** — properly detects running state via systemd + pgrep fallback

## v2.5.0 (2026-06-01)

### Features
- **TUI paste support** — Fixed text input to accept pasted content (bracket paste / multi-character input). URIs and subscription URLs can now be pasted directly in TUI.
- **TUI engine selector** — Toggle between sing-box and xray engines from Home tab. Shows current engine status.
- **TUI auto start toggle** — Shows systemd enabled/disabled status, toggle with one click.
- **TUI self-update** — Real-time progress bar download, confirm dialog (Yes/No with arrow keys), auto-restart into new version after update.
- **TUI exit button** — Added Exit item to Home tab.
- **TUI group delete** — Press `x` in Servers tab to delete a group (with confirmation).
- **TUI bench sort** — Press `f` to toggle sort order (fastest first / slowest first). Failed links always at bottom.
- **TUI update notification** — Yellow highlight on "Update Bypath" when update available, changelog link in footer.
- **Subscription proxy support** — `FetchSubscription` now respects `ALL_PROXY`/`HTTPS_PROXY` environment variables with socks5 support.
- **Self-update with download** — `bypath update` now downloads and installs the new binary with progress bar. Supports proxy via environment variables.

### Bug Fixes
- **install.sh pipe fix** — `read` prompts now use `</dev/tty` so `curl | bash` one-liner works interactively.
- **sing-box 1.13 compatibility** — Fixed DNS server format (new `type`/`server`/`server_port` format), removed deprecated `independent_cache` and `dns.listen`, added `route.default_domain_resolver`, DNS inbound as separate listener.
- **Geosite file check** — Rule sets only referenced when `.srs` file actually exists on disk, preventing sing-box crash.
- **xray Reality config** — Fixed vless Reality generation for xray (`security: "reality"` + `realitySettings` with publicKey/shortId/fingerprint).
- **xray socks5 outbound** — Added socks5/http protocol support to xray config generation.
- **xray xhttp transport** — Added xhttp/splithttp transport support for xray bench and config.
- **TUI status detection** — Gateway status now checks multiple PID file paths + `pgrep` fallback for systemd-started processes.
- **TUI bench selection** — Fixed: selecting a link from sorted bench results now picks the correct server (not wrong index).
- **Bench DNS config** — Added proper DNS section and `default_domain_resolver` to bench sing-box configs for 1.13 compatibility.
- **Bench reality fields** — Bench now reads `reality_pbk`, `reality_sid`, `fingerprint` from profile for proper relay testing.

### Improvements
- **Bench always uses sing-box** — Speed test uses sing-box regardless of engine preference (better protocol compatibility).
- **Bench timeout increased** — 20s total, 6s port wait, 8s curl connect for slow reality links.

## v2.4.3 (2026-06-01)

### Improvements
- **Expanded test coverage** — Added comprehensive tests for `internal/config` (YAML parsing, defaults, edge cases) and `internal/tunnel/configgen` (all protocols, Reality, chains, SNI spoofing).
- **Documentation migrated to wiki** — Moved `docs/` content (API, architecture, configuration, deployment) to `.wiki/` for GitHub Wiki publishing. Removed stale markdown docs from repo.
- **README cleanup** — Streamlined README with links to wiki instead of inline docs.
- **Gitignore updates** — Added `.kiro/` and cleaned up patterns.

## v2.4.2 (2026-05-31)

### Features
- **Reality support** — Full VLESS Reality parsing with `public_key`, `short_id`, and `fingerprint` (uTLS). Both `buildOutbound()` and `singboxOutbounds()` now generate correct Reality TLS config.
- **SSH tunnel protocol** — Native SSH dynamic port forwarding as a proxy protocol. Parse `ssh://` URIs, bench via `ssh -D`, no sing-box needed.
- **Multi-hop chains** — `bypath chain add/remove/list` CLI commands. Chain config stored in YAML, tunnel orchestration via `internal/tunnel/chain.go`.
- **CDN/HTTPS detection** — Bench now tests HTTPS connectivity per link. Links marked `[CDN]` or `[HTTPS✗]` in list output. `SelectBest()` prefers HTTPS-capable links.
- **SNI spoofing config** — `sni_spoof` section in config for DPI bypass with fake Iranian SNI.
- **Geosite domain whitelist** — Download and validate geosite `.srs` files per country. Integrated into gateway startup.
- **Chain CLI** — `bypath chain add <name> <hop1> [hop2...] [--auto-start]`, `chain remove`, `chain list`.

### Improvements
- Bench results now show HTTPS column (✓/✗/—)
- `select` command warns if chosen link is CDN-based
- `buildOutbound()` handles SSH protocol gracefully (returns direct outbound)
- Bench timeout increased to 20s, SSH bench uses `sshpass` for password auth
- Profile `HTTPSCapable` field persisted after bench

### Housekeeping
- Removed `.kiro/` from git tracking (added to `.gitignore`)
- Removed dead kiro spec files from repository

## v2.3.0 (2026-05-29)

### Features — TUI Redesign
- **Tab-based UI** — Three tabs: Home, Servers, Subscriptions. Navigate with `tab`/`shift+tab`.
- **Servers tab** — Browse all groups, switch with `0-9`, select server with `enter`, ping with `t`, bench group with `b`, create new group with `n`.
- **Subscriptions tab** — View all subs, `enter` to update single sub, `r` to rename group, `d` to delete, `u` to update all.
- **Speed Test improvements** — No longer auto-starts. Press `s` to start. Switch groups with `tab`. Press `r` to retest.
- **Active link display** — Header shows current active server and connection status (running/stopped).
- **Group management** — Create groups from TUI, rename groups, groups shown with numbered shortcuts.

### Features — Proxy & Protocol
- **SOCKS5 as outbound** — Add upstream SOCKS5 proxies: `bypath add 'socks5://host:port#name'`
- **HTTP proxy as outbound** — Add upstream HTTP proxies: `bypath add 'http://user:pass@host:port#name'`
- **HTTP proxy inbound** — Separate HTTP proxy port (default 8888) in addition to SOCKS5 on 2801. Configurable via `server.http_proxy_port` in config.
- **Default group protection** — `sub add` without `-g` auto-creates a named group from URL domain. Default group reserved for manual links only.
- **Engine selection** — Choose between sing-box and xray via `engines.preferred` in config.
- **SNI Spoofing** — Replace real SNI with a fake Iranian domain to bypass DPI. Configure via `sni_spoof` in config.

### Features — Security & Reliability
- **API authentication** — Token-based auth via `Authorization: Bearer <token>` or `X-API-Key` header. Configure with `server.api_token` in config. Empty = no auth (backward compatible).
- **PID file management** — Gateway writes PID to `bypath.pid`. `stop` command uses PID file instead of `pkill`. Prevents duplicate instances.
- **Subscription removal** — `bypath sub remove <index>` CLI command + TUI support.

### Fixes
- **Race condition in TUI** — Update check now uses `tea.Cmd` instead of raw goroutine (was writing to model without synchronization).
- **Gateway fallback group** — Fallback now searches the active link's group, not hardcoded "default".
- **Skip info links** — Links with port<10 or address 0.0.0.0 are skipped in bench, fallback, and list.
- **SNI comma-separated fix** — `configgen.go` now takes first SNI from comma-separated lists (matches bench behavior).
- **TLS insecure for vless** — Added `insecure: true` to vless TLS config (required for CDN-based links with mismatched certificates).
- **DNS circular dependency** — Removed `detour: direct` from DNS config that caused sing-box 1.13 startup failure. DNS now resolves without detour.
- **Whitelist with proxy mode** — Route section with sniff+resolve via direct DNS enables geoip matching for SOCKS5 clients. IR sites go direct.
- **Verify connection** — Changed from `ip-api.com` to `cp.cloudflare.com` with `socks5h://` (DNS through proxy). Added 2s delay after engine start.
- **`sub update` without `-g`** — Now updates ALL groups with subscriptions, not just default.
- **`list` without `-g`** — Shows all groups with their links, info links filtered out.
- **`select -g <group>`** — Select by number within a specific group.

### Config Changes
```yaml
server:
  api_token: ""           # NEW: API authentication token
  http_proxy_port: 8888   # NEW: Separate HTTP proxy port

engines:
  preferred: ""           # NEW: "sing-box" or "xray" (empty = auto)

sni_spoof:                # NEW: SNI spoofing for DPI bypass
  enabled: false
  sni: "digikala.com"
```

## v2.2.0 (2026-05-29)

### Features
- **Proxy mode whitelist** — Iranian sites now go direct even when using SOCKS5 proxy (not just gateway mode). Uses sing-box sniff + resolve via clean DNS + geoip-ir rule_set.
- **TUI update notification** — Main menu shows update banner when a new version is available.
- **Docker support** — Full Dockerfile with sing-box + tun2socks pre-installed. `docker compose up` and go.
- **Docker integration test** — E2E test that builds both lite and full from scratch, installs deps, adds subscription, fetches links, selects server, starts gateway.
- **Auto-release on main** — Every push to main creates a dev release with binaries for all platforms.
- **Full build for all platforms** — linux (amd64/arm64/arm/mipsle), windows, darwin (amd64/arm64).

### Fixes
- **sing-box 1.13 compatibility** — Removed deprecated inbound sniff fields, use route actions instead. Added env vars for deprecated DNS format. Fixed geoip rule_set to use local .srs files (avoids GitHub download at startup which fails in Iran).
- **IPv6 vet warning** — Fixed `fmt.Sprintf("%s:%d")` to use `net.JoinHostPort` in bench.
- **CI Go version** — Use `go-version-file: go.mod` instead of hardcoded version.
- **`.gitignore` fix** — `build/` pattern was ignoring `internal/build/` package.
- **tun2socks download URL** — Updated to v2.5.2 zip format.
- **Version comparison** — Proper semver comparison instead of string compare.

### Removed (dead code cleanup)
- `internal/whitelist/fetcher.go` — Legacy CIDR fetcher, replaced by sing-box geoip rule_set.
- `whitelist.Manager.Load()` — No longer needed with sing-box routing.
- `gateway.getNextLink()` — Unused helper, fallback logic is inline.
- `configgen.dnsRuleSetTags()` — Duplicate of inline logic.
- `sortByDownload` constant — Bench download test not yet implemented.
- Custom `contains()`/`containsHelper()` in tests — Replaced with `strings.Contains`.

## v2.1.0 (2026-05-28)

### Initial public release
- Network gateway that transparently routes LAN traffic through encrypted tunnels.
- Zero-config for clients (just set DNS/GW).
- Country whitelist (IR traffic bypasses tunnel via sing-box geoip).
- Multi-protocol support: VMess, VLESS, Trojan, Shadowsocks, WireGuard.
- Subscription support (add URL, auto-fetch links).
- Parallel speed test with auto-select best server.
- Interactive TUI (bubbletea).
- Auto-fallback if a link fails.
- REST API on :8080.
- CLI: run, stop, add, list, select, bench, sub, test, engines, update.
