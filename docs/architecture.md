# Bypath — Architecture

## Overview

Bypath is a network gateway that transparently routes LAN traffic through encrypted tunnels. Clients set their DNS and Gateway to the Bypath machine — all traffic is then either tunneled or sent direct based on country whitelist (geoip).

```
┌──────────────────────────────────────────────────────────┐
│                        Bypath                             │
│                                                           │
│  ┌─────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐ │
│  │   API   │  │   DNS    │  │  Router  │  │ Whitelist│ │
│  │  :8080  │  │ dns2socks│  │ iptables │  │ sing-box │ │
│  │         │  │   :53    │  │ fwmark   │  │  geoip   │ │
│  └────┬────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘ │
│       │             │             │              │        │
│       └─────────────┴──────┬──────┴──────────────┘        │
│                            │                              │
│                    ┌───────┴────────┐                     │
│                    │   sing-box     │                     │
│                    │  SOCKS5 :2801  │                     │
│                    │  + geoip route │                     │
│                    │  IR → direct   │                     │
│                    │  * → proxy     │                     │
│                    └───────┬────────┘                     │
│                            │                              │
│                    ┌───────┴────────┐                     │
│                    │   tun2socks    │                     │
│                    │  tun0 device   │                     │
│                    └───────┬────────┘                     │
│                            │                              │
│                        Internet                           │
└──────────────────────────────────────────────────────────┘
```

## Traffic Flow

```
Client (192.168.1.x)
    │ DNS = Bypath IP, GW = Bypath IP
    ▼
Bypath (iptables PREROUTING)
    │ fwmark 0x1 on LAN traffic not destined to LAN
    ▼
ip rule: fwmark 0x1 → table 100
    │ table 100: default via tun0
    ▼
tun0 (TUN device)
    │
    ▼
tun2socks → socks5://127.0.0.1:2801
    │
    ▼
sing-box (route rules)
    ├─ geoip IR → direct (outbound "direct")
    ├─ ip_is_private → direct
    └─ everything else → proxy (outbound "proxy" → remote server)
         │
         ▼
     Internet (exit IP = remote server)
```

## Components

### Gateway (`internal/gateway/`)
Main orchestrator. On `Start()`:
1. Detects network (interface, IP, gateway)
2. Starts sing-box with generated config (SOCKS5 + geoip routing)
3. Starts dns2socks (DNS through tunnel)
4. Starts tun2socks (TUN → SOCKS5)
5. Configures iptables (fwmark + policy routing)

### Engine Manager (`internal/engine/`)
Detects engines on PATH or downloads them.
- **sing-box** — primary engine, handles all protocols
- **xray** — fallback for edge cases
- **wireguard-go**, **openvpn** — protocol-specific

### Config Generator (`internal/tunnel/configgen.go`)
Converts a `Link` struct into sing-box JSON config:
- Inbound: `mixed` on port 2801
- Outbound: protocol-specific (vmess/vless/trojan/ss/wireguard)
- Route: `geoip IR → direct`, `ip_is_private → direct`, `final → proxy`
- Rule Set: remote `geoip-ir.srs` from SagerNet/sing-geoip (auto-downloaded)

### Profile Manager (`internal/profile/`)
- CRUD for links, groups, subscriptions
- Persists as JSON files in `data/profiles/`
- Subscription fetch (base64 decode, parse URIs)
- Active link selection

### TUI (`internal/tui/`)
Interactive terminal menu (bubbletea):
- Main menu: start/stop/status/sub/bench
- Bench page: parallel ping+relay test, live progress, sort, select
- All actions run inside alt-screen (no flash)

### DNS Proxy
External `dns2socks` binary. Routes DNS queries through the SOCKS5 tunnel.
Fallback: `dnsmasq` (DNS not through tunnel).

### Whitelist
Handled inside sing-box via `rule_set`:
- Downloads `geoip-ir.srs` from GitHub (cached, updated every 7 days)
- No ipset, no iptables `-m set`, no nf_tables compatibility issues

### REST API (`internal/api/`)
HTTP API on :8080 for management (profiles, status, subscriptions).

## Build Variants

| Variant | Build | Engines | Size | External Deps |
|---------|-------|---------|------|---------------|
| Lite | `go build ./cmd/bypath/` | External binaries | ~12 MB | sing-box, tun2socks, dns2socks |
| Full | `go build -tags full ./cmd/bypath/` | Embedded | ~50 MB | none (planned) |

## Directory Structure

```
/opt/bypath/
├── bypath              # binary
├── configs/
│   └── default.yaml    # main config
├── data/
│   ├── profiles/
│   │   ├── default.json    # links + subscriptions
│   │   └── .active         # current active link
│   └── tmp/
│       └── singbox-config.json  # generated at runtime
├── engines/            # downloaded engine binaries (if any)
└── bypath.log          # runtime log
```
