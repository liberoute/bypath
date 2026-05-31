# Bypath — Project Context

## Overview
Bypath is a network gateway written in Go that transparently routes LAN traffic through encrypted tunnels. Clients set their DNS and Gateway to the Bypath machine — traffic is either tunneled or sent direct based on country whitelist (geoip).

Target platforms: Linux (ARM/ARM64/AMD64), partial Windows support (proxy-only mode).

## Tech Stack
- Language: Go 1.24+
- TUI: charmbracelet/bubbletea + lipgloss
- HTTP Router: gorilla/mux
- DNS: miekg/dns
- Config: gopkg.in/yaml.v3
- External engines (runtime): sing-box ≥1.10, tun2socks, dns2socks
- Build: Makefile with ldflags version injection

## Project Structure
- `cmd/bypath/` — Entry point (main.go, ~1300 lines, contains all CLI commands + bench logic)
- `internal/api/` — REST API server (gorilla/mux, token auth, port 8080)
- `internal/build/` — Version/commit/date info (injected via ldflags)
- `internal/config/` — YAML config loading + defaults
- `internal/dns/` — SOCKS DNS proxy
- `internal/engine/` — Engine manager (detect on PATH, download, embed via build tags)
- `internal/gateway/` — Main orchestrator (iptables, tun, routing, sing-box, tun2socks, dns2socks)
- `internal/health/` — Health checks
- `internal/isolation/` — Network namespace isolation (netns)
- `internal/paths/` — Path detection (local vs installed mode, auto-detect)
- `internal/pidfile/` — PID file management
- `internal/profile/` — Profile/link/subscription CRUD (JSON persistence, Group/Link structs)
- `internal/tui/` — Interactive terminal UI (bubbletea, tab-based: Home/Servers/Subscriptions)
- `internal/tunnel/` — Tunnel config generation (sing-box JSON from Link struct)
- `internal/updater/` — Self-update logic (GitHub releases)
- `internal/whitelist/` — Country whitelist (legacy, actual whitelist is in sing-box geoip rule_set)

## Key Data Structures
- `config.Config` — Root YAML config (Server, Gateway, Engines, Whitelist, Isolation, Chains, DHCP, SNISpoof)
- `profile.Link` — Single proxy link (protocol, address, port, UUID, TLS, SNI, transport params)
- `profile.Group` — Collection of links + subscription URLs
- `profile.Manager` — CRUD for groups/links, persists as JSON in data/profiles/

## Supported Protocols
VMess, VLESS (with Reality), Trojan, Shadowsocks, WireGuard, SOCKS5, HTTP Proxy

## Build & Test
- Build: `make lite` (external engines) or `make full` (embedded, `-tags full`)
- Test: `go test -v -race ./...`
- Lint: `go vet ./...`
- Cross-compile targets: linux/amd64, linux/arm64, linux/mipsle, windows/amd64

## Conventions
- Standard Go project layout (`cmd/`, `internal/`)
- All internal packages are unexported (internal/)
- Config via YAML (`yaml` struct tags), profiles via JSON (`json` struct tags)
- Build variants controlled by build tags (`-tags full`)
- Version info injected via ldflags at build time (`internal/build` package)
- Error handling: return errors up with `fmt.Errorf("context: %w", err)`, don't panic
- Logging: `log.Printf` with emoji prefixes (✅ ⚠️ ❌ 🚀 🔧 🌍)
- Platform-specific code uses `_linux.go` / `_other.go` suffixes
- Concurrency: `sync.RWMutex` + `context.Context`
- TUI: bubbletea with `tea.Cmd` for async operations

## Known Technical Debt
- `main.go` is ~1300 lines (all CLI commands + bench + outbound builder in one file)
- `buildOutbound()` in main.go duplicates `singboxOutbounds()` in configgen.go
- `internal/whitelist/` is legacy (whitelist now handled by sing-box rule_set)
- Gateway accessor methods lack proper locking
- API token stored plaintext in config
- Test coverage is low (only config, parser, profile, configgen, socksproxy have tests)

## API
REST API on port 8080 with optional token auth.
Endpoints: /status, /profiles/*, /tunnels/*, /chains, /whitelist/*, /subscriptions/*, /engines

## File Paths (Runtime)
- Local mode: `configs/default.yaml`, `data/profiles/`, `data/tmp/`, `engines/`
- Installed mode: `/etc/bypath/config.yaml`, `/var/lib/bypath/profiles/`, `/opt/bypath/engines/`
- Detection: binary in `/opt/bypath/` or `/usr/local/bin/` or `/etc/bypath/config.yaml` exists → installed mode
