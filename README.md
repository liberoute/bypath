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
- **Auto-fallback** — if a link fails, tries the next one
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
curl -fsSL https://raw.githubusercontent.com/liberoute/bypath/main/install.sh | sudo bash -s -- v2.3.0 full
```

Or download and run manually:

```bash
curl -fsSL -o install.sh https://raw.githubusercontent.com/liberoute/bypath/main/install.sh
chmod +x install.sh
sudo ./install.sh
```

The installer will:
- Detect your OS and architecture automatically
- Download the correct binary from GitHub releases
- **Auto-install dependencies** (sing-box, tun2socks, iptables, iproute2, curl)
- Install to `/opt/bypath/` with proper directory structure
- Download `geoip-ir.srs` for Iran IP whitelist
- Optionally create a systemd service

### Installer options

| Usage | Description |
|-------|-------------|
| `./install.sh` | Interactive — latest version, asks for variant |
| `./install.sh v2.3.0` | Specific version, lite |
| `./install.sh v2.3.0 full` | Specific version, full variant |
| `./install.sh latest full` | Latest version, full variant |

Environment variables:
- `BYPATH_INSTALL_DIR` — Override install path (default: `/opt/bypath`)
- `BYPATH_NO_SYSTEMD=1` — Skip systemd service creation

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
bypath bench                      # Test first group
bypath bench -g <group> --auto    # Test + auto-select best

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
Bypath (iptables → tun0 → tun2socks → sing-box)
    │
    ├── digikala.com (IR) → DIRECT (geoip whitelist)
    └── google.com → tunnel → exit in Germany/Netherlands/etc
```

Proxy port available for manual configuration:
- **SOCKS5 + HTTP (mixed)**: `<bypath-ip>:2801` (configurable)

## File Paths

Bypath auto-detects its installation mode:

| | Local (./bypath) | Installed (system) |
|---|---|---|
| Config | `configs/default.yaml` | `/etc/bypath/config.yaml` |
| Profiles | `./data/profiles/` | `/var/lib/bypath/profiles/` |
| Temp | `./data/tmp/` | `/var/lib/bypath/tmp/` |
| Geo data | `./data/geo/` | `/var/lib/bypath/geo/` |
| Engines | `./engines/` | `/opt/bypath/engines/` |
| Logs | stdout | `/var/log/bypath/error.log` |

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
  interface: ""           # auto-detect

whitelist:
  countries: ["ir"]       # bypass tunnel for these countries
  update_interval: "24h"

isolation:
  enabled: true

sni_spoof:
  enabled: false
  sni: "digikala.com"
```

See [docs/configuration.md](docs/configuration.md) for full reference.

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

- [Architecture](docs/architecture.md)
- [Configuration](docs/configuration.md)
- [Deployment Guide](docs/deployment.md)
- [API Reference](docs/api.md)

## Requirements (Lite build)

All dependencies are auto-installed by `install.sh`. For manual setup:

| | Required | Why |
|---|---|---|
| Linux (arm/arm64/amd64) | ✅ | OS |
| Root | ✅ | iptables, TUN, port 53 |
| sing-box ≥1.10 | ✅ | Tunnel engine |
| tun2socks | ✅ | TUN → SOCKS5 (gateway mode) |
| iptables + iproute2 | ✅ | Routing (gateway mode) |
| curl | recommended | Bench + health check |

## License

MIT
