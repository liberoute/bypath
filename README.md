# Bypath

Network gateway that transparently routes LAN traffic through encrypted tunnels. Set your device's DNS and Gateway to the Bypath machine — done.

Iranian IPs go direct (no tunnel). Everything else goes through your proxy server.

## Features

- **Zero-config for clients** — just change DNS/Gateway
- **Country whitelist** — IR traffic bypasses tunnel automatically (sing-box geoip)
- **Multi-protocol** — VMess, VLESS, Trojan, Shadowsocks, WireGuard, SOCKS5, HTTP proxy
- **Subscription support** — add URL, auto-fetch links, auto-group by domain
- **Parallel speed test** — test all servers simultaneously, auto-select best
- **Interactive TUI** — tab-based terminal UI (Home / Servers / Subscriptions)
- **Auto-fallback** — if a link fails, tries the next one
- **Dual proxy** — SOCKS5 (:2801) + HTTP proxy (:8888) for clients
- **API authentication** — token-based auth for REST API
- **PID management** — clean start/stop without orphan processes

## Quick Start

```bash
# On your Linux box (Orange Pi, Raspberry Pi, any server):

# Install dependencies
apt install -y iptables iproute2 curl
# Install sing-box: https://sing-box.sagernet.org/installation/package-manager/
# Install tun2socks:
wget https://github.com/xjasonlyu/tun2socks/releases/latest/download/tun2socks-linux-armv7 -O /usr/local/bin/tun2socks
chmod +x /usr/local/bin/tun2socks

# Download geoip for Iran whitelist
mkdir -p /opt/bypath/data/geo
wget -O /opt/bypath/data/geo/geoip-ir.srs https://github.com/SagerNet/sing-geoip/releases/latest/download/geoip-ir.srs

# Setup bypath
mkdir -p /opt/bypath && cd /opt/bypath
wget https://github.com/liberoute/bypath/releases/latest/download/bypath-lite-linux-arm -O bypath
chmod +x bypath

# Add your subscription and go
./bypath sub add "https://your-subscription-url"
./bypath bench --auto
./bypath run
```

Then on your phone/laptop: set Gateway and DNS to the Bypath machine's IP.

## Usage

### Interactive TUI
```bash
./bypath
```

Tab-based interface:
- **Home** — Start/Stop gateway, speed test, add subscription, status
- **Servers** — Browse groups (0-9), select server, ping, bench
- **Subscriptions** — Update, rename, delete subscriptions

### CLI
```bash
# Gateway
bypath run                        # Start gateway
bypath stop                       # Stop gateway

# Servers
bypath add <uri>                  # Add link (vmess/vless/ss/trojan/socks5/http)
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

Proxy ports available for manual configuration:
- **SOCKS5**: `<bypath-ip>:2801`
- **HTTP**: `<bypath-ip>:8888`

## Configuration

`configs/default.yaml`:
```yaml
server:
  api_port: 8080
  dns_port: 53
  api_token: ""           # API auth token (empty = no auth)
  http_proxy_port: 8888   # HTTP proxy port (0 = disabled)

gateway:
  enabled: true
  interface: ""           # auto-detect

whitelist:
  countries: ["ir"]       # bypass tunnel for these countries
  update_interval: "24h"

isolation:
  enabled: true
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

| | Required | Why |
|---|---|---|
| Linux (arm/arm64/amd64) | ✅ | OS |
| Root | ✅ | iptables, TUN, port 53 |
| sing-box ≥1.10 | ✅ | Tunnel engine |
| tun2socks | ✅ | TUN → SOCKS5 (gateway mode) |
| iptables + iproute2 | ✅ | Routing (gateway mode) |
| dns2socks | recommended | DNS through tunnel |
| curl | recommended | Bench + health check |

## License

MIT
