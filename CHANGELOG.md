# Changelog

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
