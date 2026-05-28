# Bypath

Network gateway that transparently routes LAN traffic through encrypted tunnels. Set your device's DNS and Gateway to the Bypath machine — done.

Iranian IPs go direct (no tunnel). Everything else goes through your proxy server.

## Features

- **Zero-config for clients** — just change DNS/Gateway
- **Country whitelist** — IR traffic bypasses tunnel automatically (sing-box geoip)
- **Multi-protocol** — VMess, VLESS, Trojan, Shadowsocks, WireGuard, Hysteria2
- **Subscription support** — add URL, auto-fetch links
- **Parallel speed test** — test all servers simultaneously, auto-select best
- **Interactive TUI** — terminal menu for everything
- **Auto-fallback** — if a link fails, tries the next one

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
mkdir -p /usr/share/sing-box
wget -O /usr/share/sing-box/geoip.db https://github.com/SagerNet/sing-geoip/releases/latest/download/geoip.db

# Setup bypath
mkdir -p /opt/bypath && cd /opt/bypath
# Download binary (or build from source)
wget https://github.com/liberoute/bypath/releases/latest/download/bypath-linux-armv7 -O bypath
chmod +x bypath

# Add your subscription and go
./bypath sub add "https://your-subscription-url"
./bypath sub update
./bypath bench --auto
./bypath run
```

Then on your phone/laptop: set Gateway and DNS to the Bypath machine's IP.

## Usage

### Interactive Menu
```bash
./bypath
```

### CLI
```bash
bypath sub add <url>      # Add subscription
bypath sub update         # Fetch latest links
bypath list               # Show all servers
bypath bench --auto       # Speed test + auto-select best
bypath select <number>    # Manual select
bypath run                # Start gateway
bypath stop               # Stop gateway
bypath version            # Show info
```

## How It Works

```
Your Phone/Laptop
    │ Gateway = Bypath IP
    │ DNS = Bypath IP
    ▼
Bypath (iptables → tun0 → tun2socks → sing-box)
    │
    ├── digikala.com (IR) → DIRECT (no tunnel)
    └── google.com → tunnel → exit in Germany/Netherlands/etc
```

## Build from Source

```bash
git clone https://github.com/liberoute/bypath.git
cd bypath/v2

# For Orange Pi / RPi (32-bit ARM)
GOOS=linux GOARCH=arm GOARM=7 go build -o bypath ./cmd/bypath/

# For RPi 4 / modern ARM (64-bit)
GOOS=linux GOARCH=arm64 go build -o bypath ./cmd/bypath/

# For x86_64 server
GOOS=linux GOARCH=amd64 go build -o bypath ./cmd/bypath/
```

## Configuration

`configs/default.yaml`:
```yaml
server:
  api_port: 8080
  dns_port: 53

gateway:
  enabled: true
  interface: ""

whitelist:
  countries: ["ir"]
```

See [docs/configuration.md](docs/configuration.md) for full reference.

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
| tun2socks | ✅ | TUN → SOCKS5 |
| iptables + iproute2 | ✅ | Routing |
| dns2socks | recommended | DNS through tunnel |
| curl | recommended | Bench + health check |

## License

MIT
