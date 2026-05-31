# Bypath — Configuration Reference

Config file: `configs/default.yaml`

## Minimal Config

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

That's it. Everything else has sane defaults.

## Full Example

```yaml
server:
  listen: "0.0.0.0"
  api_port: 8080
  dns_port: 53

gateway:
  enabled: true
  interface: ""           # auto-detect (end0, eth0, etc.)
  dns_upstream:
    - "1.1.1.1"
    - "8.8.8.8"

engines:
  directory: "./engines"
  prefer_system: true     # use sing-box from PATH first

whitelist:
  countries: ["ir"]       # country codes to bypass tunnel
  update_interval: "24h"

isolation:
  enabled: false          # network namespace isolation (advanced)

health_check:
  enabled: true
  interval: "60s"
  url: "http://ip-api.com/json"

profiles:
  active_group: "default"
  directory: "./data/profiles"
```

## Sections

### `server`

| Key | Default | Description |
|-----|---------|-------------|
| `listen` | `0.0.0.0` | Bind address |
| `api_port` | `8080` | REST API port |
| `dns_port` | `53` | DNS proxy port |

### `gateway`

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `true` | Gateway mode (TUN + routing). `false` = proxy-only mode |
| `interface` | `""` | Network interface. Empty = auto-detect |
| `dns_upstream` | `["1.1.1.1","8.8.8.8"]` | Upstream DNS (used by dns2socks) |

### `engines`

| Key | Default | Description |
|-----|---------|-------------|
| `directory` | `./engines` | Where to store downloaded binaries |
| `prefer_system` | `true` | Prefer system PATH over local directory |

### `whitelist`

| Key | Default | Description |
|-----|---------|-------------|
| `countries` | `["ir"]` | ISO country codes. Traffic to these countries goes direct |
| `update_interval` | `24h` | How often sing-box refreshes the geoip rule_set |

Whitelist is implemented inside sing-box using remote `rule_set` (geoip-ir.srs). No ipset or iptables match-set needed.

### `isolation`

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `false` | Run engine in separate network namespace |

### `health_check`

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `true` | Periodic connectivity check |
| `interval` | `60s` | Check interval |
| `url` | `http://ip-api.com/json` | URL to test |

### `profiles`

| Key | Default | Description |
|-----|---------|-------------|
| `active_group` | `default` | Which profile group to use |
| `directory` | `./data/profiles` | Profile storage path |

## Profile JSON Format

`data/profiles/default.json`:
```json
{
  "name": "default",
  "type": "subscription",
  "links": [
    {
      "remark": "my-server",
      "protocol": "shadowsocks",
      "address": "1.2.3.4",
      "port": 8585,
      "uuid": "password-here",
      "security": "aes-128-gcm"
    }
  ],
  "subscriptions": [
    "https://example.com/sub/abc123"
  ]
}
```

## SSH Tunnel

SSH tunnel uses OpenSSH's dynamic port forwarding (`ssh -D`) to create a local SOCKS5 proxy through any SSH server. No specialized proxy software is needed on the remote end.

### URI Format

```
ssh://[user[:password]]@host[:port][?key=<path>]#remark
```

| Component | Required | Default | Description |
|-----------|----------|---------|-------------|
| `user` | No | `root` | SSH username |
| `password` | No | — | Password for auth (requires `sshpass`) |
| `host` | Yes | — | SSH server address |
| `port` | No | `22` | SSH port |
| `key` | No | — | Path to private key file |
| `#remark` | No | — | Display name for the link |

### Examples

Key-based authentication:
```
ssh://root@myserver.com:22?key=/etc/bypath/keys/id_rsa#my-ssh-server
```

Password-based authentication:
```
ssh://user:password123@10.0.0.1:2222#office-relay
```

Minimal (defaults to port 22, user root):
```
ssh://admin@192.168.1.1#home-router
```

### Prerequisites

- `ssh` binary must be available on PATH (OpenSSH client)
- `sshpass` is required for password-based authentication (install via `apt install sshpass`)
- Key-based authentication is preferred and does not require extra tools

### SSH in Chains

SSH tunnels can be used as hops in multi-hop chains. When SSH is part of a chain, Bypath uses multi-process strategy (SSH runs as a separate process providing a SOCKS5 proxy for the next hop).

```yaml
chains:
  - name: "ssh-chain"
    hops:
      - profile: "my-ssh-server"    # SSH tunnel as first hop
      - profile: "vless-exit"       # VLESS as exit through SSH
    auto_start: true
```

## Supported Protocols

| Protocol | Engine | Notes |
|----------|--------|-------|
| VMess | sing-box | ws/tcp/grpc transport, TLS |
| VLESS | sing-box | ws/tcp/grpc, TLS, Reality, XTLS |
| Trojan | sing-box | TLS, ws transport |
| Shadowsocks | sing-box | All methods |
| WireGuard | sing-box | Built-in |
| Hysteria2 | sing-box | QUIC-based |
| TUIC | sing-box | QUIC-based |
| SSH | ssh (native) | Dynamic port forwarding, key or password auth |

## Environment

Bypath must run as root (needs iptables, TUN device, port 53).

Working directory should be the install directory (`/opt/bypath/`) so relative paths work.
