# Bypath

Network gateway that transparently routes LAN traffic through encrypted tunnels. Set your device's DNS and Gateway to the Bypath machine — done.

Iranian IPs go direct (no tunnel). Everything else goes through your proxy server.

## Features

- **Zero-config for clients** — just change DNS/Gateway
- **Country whitelist** — IR traffic bypasses tunnel automatically (sing-box geoip)
- **Multi-protocol** — VMess, VLESS, Trojan, Shadowsocks, WireGuard, SSH, SOCKS5, HTTP proxy
- **Subscription support** — add URL, auto-fetch links, auto-group by domain
- **Parallel speed test** — test all servers simultaneously, auto-select best
- **Interactive TUI** — tab-based terminal UI (Home / Servers / Subscriptions)
- **Dual engine** — sing-box (default, embedded in full build) + xray as automatic fallback; configurable per-deployment
- **Rule-based routing** — geoip/geosite/domain rules map traffic to direct or proxy outbounds
- **Home DNS / private TLD support** — route `.home`, `.lan`, `.internal` (or any private TLD) to your local DNS server via `gateway.local_dns`
- **Auto-fallback** — if a link or engine fails, tries the next one automatically
- **Mixed proxy** — SOCKS5 + HTTP on configurable port (default: 2801)
- **API authentication** — token-based auth for REST API
- **PID management** — clean start/stop without orphan processes
- **Auto-install** — installer handles all dependencies automatically

## Installation

One-liner install (recommended):

```bash
curl -fsSL https://raw.githubusercontent.com/liberoute/bypath/main/install.sh | sudo bash
```

Or with a specific version and variant:

```bash
curl -fsSL https://raw.githubusercontent.com/liberoute/bypath/main/install.sh | sudo bash -s -- v2.6.2 full
```

Or download and run manually (no `sudo` needed — the installer escalates automatically):

```bash
curl -fsSL -o install.sh https://raw.githubusercontent.com/liberoute/bypath/main/install.sh
chmod +x install.sh
./install.sh
```

The installer will:
- **Auto-escalate to root** via sudo if needed (v2.6.3+) — no manual `sudo` required
- Detect your OS and architecture automatically
- Download the correct binary from GitHub releases (or use `BYPATH_LOCAL_BINARY` for a local binary)
- **Auto-install dependencies** (sing-box, iptables, iproute2, curl — tun2socks only needed in legacy mode)
- **Free port 53** — stops `systemd-resolved` (Debian/Ubuntu) and `dnsmasq` (Armbian/Raspbian) if active
- Install to `/opt/bypath/` with proper directory structure
- Download geo rule sets (`geoip-ir.srs`, `geosite-ir.srs`) for Iran IP/domain whitelist
- **`bypath run` auto-downloads** any missing geoip files at startup (clean-machine safe)
- **Prompt for a server link** to add right after install (in interactive mode)
- Create a systemd service with `Conflicts=dnsmasq.service` (port 53 freed automatically on every boot)

### Installer options

| Usage | Description |
|-------|-------------|
| `./install.sh` | Interactive — latest version, asks for variant |
| `./install.sh v2.3.0` | Specific version, lite |
| `./install.sh v2.3.0 full` | Specific version, full variant |
| `./install.sh latest full` | Latest version, full variant |

Environment variables:

| Variable | Description |
|----------|-------------|
| `BYPATH_INSTALL_DIR` | Override install path (default: `/opt/bypath`) |
| `BYPATH_NO_SYSTEMD=1` | Skip systemd service creation |
| `BYPATH_INIT_LINK=<uri>` | Server link to add during install (vmess/vless/ss/trojan) |
| `BYPATH_LOCAL_BINARY=<path>` | Use a local binary instead of downloading from GitHub |

In interactive mode (TTY), the installer will prompt for a server link even without `BYPATH_INIT_LINK`.

## Quick Start

```bash
# After installation:
bypath sub add "https://your-subscription-url"
bypath bench --auto
bypath run
```

Then on your phone/laptop: set Gateway and DNS to the Bypath machine's IP.

## Usage

### Interactive TUI
```bash
bypath
```

Tab-based interface:
- **Home** — Start/Stop gateway, speed test, add subscription, change port, status
- **Servers** — Browse groups (0-9), select server, ping, bench
- **Subscriptions** — Update, rename, delete subscriptions

### CLI
```bash
# Gateway
bypath run                        # Start gateway
bypath run -c /path/to/config     # Custom config path
bypath stop                       # Stop gateway

# Servers
bypath add <uri>                  # Add link (vmess/vless/ss/trojan/ssh/socks5/http)
bypath list                       # Show all groups and servers
bypath list -g <group>            # Show specific group
bypath select <name|number>       # Select active server
bypath select <number> -g <group> # Select from specific group

# Speed test
bypath bench                      # Test all groups, show per-group results
bypath bench -g <group> --auto    # Test specific group + auto-select best

# Subscriptions
bypath sub add <url>              # Add subscription (auto-creates group)
bypath sub add -g <name> <url>    # Add to specific group
bypath sub update                 # Update ALL subscriptions
bypath sub update -g <group>      # Update specific group
bypath sub list                   # Show subscription URLs
bypath sub remove <index>         # Remove subscription by index

# Other
bypath engines                    # Show available engines
bypath update                     # Check for updates
bypath version                    # Show version info
```

### Supported Protocols

| Protocol | URI Format | Example |
|----------|-----------|---------|
| VMess | `vmess://base64...` | Standard v2ray format |
| VLESS | `vless://uuid@host:port?params#name` | With Reality/TLS support |
| Trojan | `trojan://pass@host:port?params#name` | Always TLS |
| Shadowsocks | `ss://base64@host:port#name` | All methods |
| WireGuard | `wireguard://key@host:port?publickey=x#name` | Native support |
| SSH | `ssh://[user[:pass]]@host[:port][?key=path]#name` | Dynamic SOCKS5 forwarding |
| SOCKS5 | `socks5://[user:pass@]host:port#name` | Upstream SOCKS5 proxy |
| HTTP | `http://[user:pass@]host:port#name` | Upstream HTTP proxy |

## How It Works

```
Your Phone/Laptop
    │ Gateway = Bypath IP
    │ DNS = Bypath IP
    ▼
Bypath (iptables → tun0 → sing-box native TUN)
    │
    ├── geoip:ir  → DIRECT (Iran IPs)
    ├── geosite:ir → DIRECT (Iran domains)
    ├── domain_suffix:.ir → DIRECT
    └── default   → tunnel → exit IP of your proxy server
```

Proxy port available for manual configuration:
- **SOCKS5 + HTTP (mixed)**: `<bypath-ip>:2801` (configurable)

## File Paths

Bypath auto-detects its installation mode:

| | Local (./bypath) | Installed (system) |
|---|---|---|
| Config | `configs/default.yaml` | `/etc/bypath/config.yaml` |
| Profiles | `./data/profiles/` | `/etc/bypath/profiles/` |
| Temp | `./data/tmp/` | `/tmp/bypath-<pid>/` |
| Geo data | `./data/geo/` | `/etc/bypath/geo/` |
| Engines | `./engines/` | `/opt/bypath/engines/` |
| Logs | stdout | `/var/log/bypath/` |

Detection: if binary is in `/opt/bypath/`, `/usr/local/bin/`, or `/usr/bin/`, or `/etc/bypath/config.yaml` exists → installed mode.

## Configuration

Config file (auto-created on first run if missing):

```yaml
server:
  api_port: 8080
  dns_port: 53
  socks_port: 2801        # SOCKS5/HTTP mixed proxy port
  api_token: ""           # API auth token (empty = no auth)

gateway:
  enabled: true
  native_tun: true        # sing-box native TUN (no tun2socks needed)
  interface: ""           # auto-detect
  local_dns:              # optional: home DNS for private TLDs
    - server: "192.168.1.1"
      domains: ["home", "lan"]

engines:
  prefer_system: true
  preferred: ""           # "sing-box" or "xray" (empty = auto)
  fallback:
    enabled: true         # try xray if sing-box fails (and vice versa)
    timeout: "10s"
    order: [sing-box, xray]

routing:
  rules:
    - match: domain_suffix:cloudflare.com
      outbound: direct
    - match: geoip:ir
      outbound: direct
    - match: geosite:ir
      outbound: direct
    - match: default
      outbound: proxy

isolation:
  enabled: true

sni_spoof:
  enabled: false
  sni: "digikala.com"
```

See [Configuration](https://github.com/liberoute/bypath/wiki/Configuration) for full reference.

## Build from Source

```bash
git clone https://github.com/liberoute/bypath.git
cd bypath

# For Orange Pi / RPi (32-bit ARM)
GOOS=linux GOARCH=arm GOARM=7 go build -o bypath ./cmd/bypath/

# For RPi 4 / modern ARM (64-bit)
GOOS=linux GOARCH=arm64 go build -o bypath ./cmd/bypath/

# For x86_64 server
GOOS=linux GOARCH=amd64 go build -o bypath ./cmd/bypath/
```

## Docs

- [Architecture](https://github.com/liberoute/bypath/wiki/Architecture)
- [Configuration](https://github.com/liberoute/bypath/wiki/Configuration)
- [Deployment Guide](https://github.com/liberoute/bypath/wiki/Deployment)
- [API Reference](https://github.com/liberoute/bypath/wiki/API-Reference)
- [Supported Protocols](https://github.com/liberoute/bypath/wiki/Supported-Protocols)
- [Troubleshooting](https://github.com/liberoute/bypath/wiki/Troubleshooting)
- [Build from Source](https://github.com/liberoute/bypath/wiki/Build-from-Source)

## Requirements

All dependencies are auto-installed by `install.sh`. For manual setup:

### Lite build

| | Required | Why |
|---|---|---|
| Linux (arm/arm64/amd64) | ✅ | OS |
| Root | ✅ | iptables, TUN, port 53 |
| sing-box ≥1.12 | ✅ | Primary tunnel engine |
| iptables + iproute2 | ✅ | Routing (gateway mode) |
| curl | recommended | Bench + health check |
| xray | optional | Fallback engine |
| tun2socks | legacy mode only | Not needed with `native_tun: true` (default) |

### Full build (embedded engines)

| | Required | Why |
|---|---|---|
| Linux (arm/arm64/amd64) | ✅ | OS |
| Root | ✅ | iptables, TUN, port 53 |
| iptables + iproute2 | ✅ | Routing (gateway mode) |

sing-box runs in-process — no external binary needed. xray embedded requires `geoip.dat`/`geosite.dat` (download separately if using xray engine).

## License

MIT
