# AI Context Document

> For AI assistants working on this project.

## Identity

- **Name**: Bypath
- **Org**: Liberoute (`github.com/liberoute/bypath`)
- **Language**: Go 1.24+
- **License**: MIT

## What It Does

Network gateway for Linux (ARM/x86). Clients set DNS/GW to this machine → traffic transparently routed through encrypted tunnels. Country-based whitelist (IR) bypasses tunnel via sing-box geoip rules.

## Current Architecture

```
LAN clients → iptables (fwmark) → tun0 → tun2socks → SOCKS5:2801 → sing-box → tunnel
                                                                      ↓
                                                              geoip IR → direct
                                                              * → proxy outbound
```

**Key point:** Whitelist is inside sing-box (rule_set with local geoip-ir.srs). No ipset, no iptables -m set.

**Proxy ports:**
- SOCKS5 (mixed): 0.0.0.0:2801
- HTTP proxy: 0.0.0.0:8888 (configurable)
- API: 0.0.0.0:8080

## Directory Map

```
cmd/bypath/main.go              Entry point + CLI commands
internal/
├── api/
│   ├── server.go               REST API (gorilla/mux) :8080
│   ├── handlers.go             API endpoint handlers
│   └── auth.go                 Token-based auth middleware
├── config/config.go            YAML config + defaults
├── dns/socksproxy.go           Native Go DNS-over-SOCKS5
├── engine/
│   ├── manager.go              Detect/download engines
│   ├── downloader.go           HTTP download + extract
│   ├── process.go              Run processes
│   ├── embedded.go             Full build: in-process
│   └── embedded_stub.go        Lite build: no-op
├── gateway/
│   ├── gateway.go              Main orchestrator (start/stop)
│   ├── dns.go                  DNS forwarding
│   ├── router.go               iptables/NAT
│   └── dhcp.go                 DHCP (placeholder)
├── health/health.go            Connectivity check
├── isolation/netns.go          Network namespace
├── pidfile/pidfile.go          PID file management
├── profile/
│   ├── profile.go              Link/Group CRUD (JSON)
│   ├── parser.go               URI parser (vmess/vless/trojan/ss/wg/socks5/http)
│   └── subscription.go         Subscription fetch + parse + remove
├── tunnel/
│   ├── tunnel.go               Tunnel lifecycle
│   ├── chain.go                Multi-hop chains
│   └── configgen.go            Generate sing-box/xray configs
├── tui/
│   ├── tui.go                  Main TUI (tab-based: Home/Servers/Subs)
│   ├── bench.go                Speed test page (parallel ping/relay)
│   ├── proc_linux.go           Linux-specific (Setpgid)
│   └── proc_other.go           Non-Linux stub
├── updater/                    Self-update check
└── whitelist/
    └── whitelist.go            IP list manager (legacy, routing via sing-box)
```

## How Whitelist Works (Current)

1. `configgen.go` adds `route.rules` + `route.rule_set` to sing-box config
2. DNS section: udp server `1.1.1.1` (no detour, resolves directly)
3. Route rules: `sniff` → `resolve` → `ip_is_private → direct` → `geoip-ir → direct` → `final → proxy`
4. Rule set: local `geoip-ir.srs` file at `/opt/bypath/data/geo/geoip-ir.srs`
5. No iptables/ipset involved in whitelist decision

## How Gateway Works (Current)

`gateway.go` Start():
1. Check PID file (prevent duplicate instances)
2. Detect network (interface, IP, real gateway)
3. Get active link from `.active` file (searches all groups)
4. Start sing-box (generated config with mixed inbound + HTTP inbound + geoip route)
5. Verify connection via `curl -x socks5h:// cp.cloudflare.com`
6. If fails → fallback to other links in same group (skip info links)
7. Start dns2socks (DNS through SOCKS5 tunnel)
8. Start tun2socks (TUN device → SOCKS5)
9. iptables: mark LAN traffic → policy route through tun0

## How Groups Work

- **default** — Reserved for manual links (user adds with `bypath add <uri>`)
- **Subscription groups** — Auto-created from URL domain when `sub add` is used without `-g`
- `sub update` without `-g` updates ALL groups
- Active link stored in `data/profiles/.active` as `group\nremark`

## Supported Protocols (outbound)

| Protocol | sing-box type | Auth fields |
|----------|--------------|-------------|
| vmess | vmess | uuid, alter_id, security |
| vless | vless | uuid, flow (+ insecure TLS) |
| trojan | trojan | password (in uuid field) |
| shadowsocks | shadowsocks | method (security), password (uuid) |
| wireguard | wireguard | private_key, public_key |
| socks5 | socks | username (uuid), password (security) |
| http | http | username (uuid), password (security) |

## Config Generation (configgen.go)

Key fixes applied:
- **SNI comma-separated**: Takes first entry from comma-separated SNI/Host lists
- **TLS insecure**: Added `insecure: true` for vless (CDN links have mismatched certs)
- **No `auto_detect_interface`**: Not needed for SOCKS inbound mode
- **DNS without detour**: sing-box 1.13 rejects `detour: direct` on DNS servers
- **HTTP proxy inbound**: Optional second inbound on configurable port

## Build

```bash
# Lite (ARM)
GOOS=linux GOARCH=arm GOARM=7 go build -o bypath ./cmd/bypath/

# Lite (ARM64)
GOOS=linux GOARCH=arm64 go build -o bypath ./cmd/bypath/

# Lite (x86_64)
GOOS=linux GOARCH=amd64 go build -o bypath ./cmd/bypath/
```

## Conventions

- Error wrapping: `fmt.Errorf("context: %w", err)`
- Logging: `log.Printf` with emoji (✅ ⚠️ ❌ 🚀 🔧 🌍)
- Concurrency: `sync.RWMutex` + `context.Context`
- JSON tags on API/profile structs, YAML tags on config structs
- No global state
- Platform-specific code in `_linux.go` / `_other.go` files
- TUI: bubbletea with tab-based navigation, tea.Cmd for async (no raw goroutines)

## Dependencies

| Package | Purpose |
|---------|---------|
| `github.com/charmbracelet/bubbletea` | TUI framework |
| `github.com/charmbracelet/lipgloss` | TUI styling |
| `github.com/mattn/go-runewidth` | Unicode column alignment |
| `github.com/miekg/dns` | DNS server |
| `github.com/gorilla/mux` | HTTP router |
| `gopkg.in/yaml.v3` | Config parsing |

## External Runtime Dependencies (Lite)

| Binary | Purpose | Required |
|--------|---------|----------|
| `sing-box` ≥1.10 | Tunnel engine | ✅ |
| `tun2socks` | TUN → SOCKS5 | ✅ (gateway mode) |
| `dns2socks` | DNS through tunnel | recommended |
| `curl` | Bench + health check | recommended |
| `iptables` | Routing | ✅ (gateway mode) |
| `iproute2` | ip commands | ✅ (gateway mode) |

## TUI Structure

Tab-based (Home / Servers / Subscriptions):
- **Home**: Start/Stop, Speed Test, Add Sub, Add Server, Version
- **Servers**: Group tabs (0=default, 1-9=others), server list, select/ping/bench/new group
- **Subscriptions**: List subs, update single/all, rename group, delete
- **Speed Test** (sub-page): Group tabs, press `s` to start, sort 1/2/3, enter to select

## Known Issues / Gotchas

- CDN-based vless links (Cloudflare Workers) only relay HTTP, not HTTPS
- `VLDR` links with comma-separated SNI need the first-entry fix (applied in both configgen and bench)
- sing-box 1.13 rejects `detour: "direct"` on DNS servers (use no detour)
- Gateway verify needs `socks5h://` (DNS through proxy) and 2s delay after start
- `sub update` replaces ALL links in a group (by design — subscription is source of truth)
- Some sub URLs only accessible via proxy — TUI has `o`/`p` keys for proxy-based update
- Port 8118 may conflict with privoxy if installed — use different http_proxy_port
- `engines.preferred: "xray"` only works for vmess/vless/trojan/ss — wireguard/openvpn always use their native engine
- SNI spoof replaces SNI on ALL outbound TLS connections — don't use with Reality links
- Default group is protected: `sub add` without `-g` auto-creates named group from URL domain
