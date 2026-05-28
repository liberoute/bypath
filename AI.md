# AI Context Document

> For AI assistants working on this project.

## Identity

- **Name**: Bypath
- **Org**: Liberoute (`github.com/liberoute/bypath`)
- **Language**: Go 1.22+
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

**Key point:** Whitelist is inside sing-box (rule_set with remote geoip-ir.srs). No ipset, no iptables -m set.

## Directory Map

```
cmd/bypath/main.go              Entry point + CLI commands
internal/
├── api/                        REST API (gorilla/mux) :8080
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
│   ├── router.go               iptables/NAT (unused now, gateway.go does it)
│   └── dhcp.go                 DHCP (placeholder)
├── health/health.go            Connectivity check
├── isolation/netns.go          Network namespace
├── profile/
│   ├── profile.go              Link/Group CRUD (JSON)
│   ├── parser.go               URI parser (vmess/vless/trojan/ss/wg)
│   └── subscription.go         Subscription fetch + parse
├── tunnel/
│   ├── tunnel.go               Tunnel lifecycle
│   ├── chain.go                Multi-hop chains
│   └── configgen.go            Generate sing-box/xray configs
├── tui/
│   ├── tui.go                  Main TUI menu (bubbletea)
│   ├── bench.go                Bench page (parallel ping/relay, sort, select)
│   ├── proc_linux.go           Linux-specific (Setpgid)
│   └── proc_other.go           Non-Linux stub
├── updater/                    Self-update check
└── whitelist/
    ├── whitelist.go            IP list manager (legacy, not used for routing)
    └── fetcher.go              Download country CIDRs (legacy)
```

## How Whitelist Works (Current)

1. `configgen.go` adds `route.rule_set` to sing-box config
2. Rule set: remote `geoip-ir.srs` from `SagerNet/sing-geoip` (binary format)
3. Route rules: `ip_is_private → direct`, `rule_set geoip-ir → direct`, `final → proxy`
4. sing-box downloads and caches the .srs file, updates every 7 days
5. No iptables/ipset involved in whitelist decision

## How Gateway Works (Current)

`gateway.go` Start():
1. Detect network (interface, IP, real gateway)
2. Start sing-box (generated config with SOCKS5 inbound + geoip route)
3. Start dns2socks (DNS through SOCKS5 tunnel)
4. Start tun2socks (TUN device → SOCKS5)
5. iptables: mark LAN traffic → policy route through tun0
6. NAT + forwarding rules

## Build

```bash
# Lite (ARM)
GOOS=linux GOARCH=arm GOARM=7 go build -o bypath ./cmd/bypath/

# Lite (ARM64)
GOOS=linux GOARCH=arm64 go build -o bypath ./cmd/bypath/

# Lite (x86_64)
GOOS=linux GOARCH=amd64 go build -o bypath ./cmd/bypath/

# Full (embedded engines — not yet implemented)
go build -tags full -o bypath-full ./cmd/bypath/
```

## Conventions

- Error wrapping: `fmt.Errorf("context: %w", err)`
- Logging: `log.Printf` with emoji (✅ ⚠️ ❌ 🚀 🔧 🌍)
- Concurrency: `sync.RWMutex` + `context.Context`
- JSON tags on API/profile structs, YAML tags on config structs
- No global state
- Platform-specific code in `_linux.go` / `_other.go` files

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
