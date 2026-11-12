# Configuration reference

Bypath reads a single YAML file. The location depends on how it was started:

| Context | Path |
|---|---|
| Installed service | `/etc/bypath/config.yaml` |
| `bypath run -c FILE` | The file you pass |
| Local development binary | `configs/default.yaml` |

Paths for profiles, geo data, engines and logs also follow the installation
mode; `bypath doctor` prints the configuration file it used.

The first-run wizard is the supported way to create a configuration. Editing
the file by hand is possible, but `bypath setup --dry-run` and
`bypath doctor` are the safe ways to check the result before restarting.

The default configuration on this branch contains no connection, no
subscription, no credential, no provider and no geographic assumption.

## server

```yaml
server:
  listen: "127.0.0.1"        # management API bind address
  api_port: 8080
  dns_port: 53               # gateway DNS listener
  socks_port: 2801           # SOCKS5/HTTP mixed proxy
  api_token: ""              # TCP API credential; a root daemon refuses tokenless TCP
  socks_listen: "127.0.0.1"  # proxy bind address
  socks_allow_lan: false     # explicit opt-in for a non-loopback proxy bind
  socks_trusted_cidrs: []    # explicit source allow-list for that bind
  ssh_host_key: "accept-new" # accept-new | strict | off
  web:
    enabled: false
    listen: "127.0.0.1"
    port: 8081               # defaults to api_port + 1
    allow_lan: false
    allowed_origins: []      # e.g. ["https://panel.example.net"]
    socket: ""               # optional Unix socket for a reverse proxy
```

- **`api_token`** authenticates TCP access to the management API. Without it, a
  root daemon refuses tokenless TCP and only the control socket (CLI/TUI) is
  usable. The browser panel uses an administrator session instead.
- **`socks_listen`** defaults to loopback because the proxy has no client
  authentication. Setting a LAN address requires `socks_allow_lan: true` and at
  least one `socks_trusted_cidrs` entry; every entry must be a private IPv4
  subnet of an up, non-loopback interface. Bypath installs firewall rules that
  reject all other sources on that port.
- **`socks_username` / `socks_password`** are rejected at load time. Bypath's
  own probe and internal clients cannot authenticate, so an "authenticated"
  listener would either be unusable or silently open.
- **`ssh_host_key`**: `accept-new` pins an SSH link's host key on first use,
  `strict` rejects unknown hosts, `off` disables verification explicitly.
- **`server.web`** is a separate listener. Enabling the panel does not expose
  the proxy, and exposing the proxy does not expose the panel.

## gateway

```yaml
gateway:
  enabled: false
  native_tun: true
  interface: ""              # auto-detect; set explicitly on multi-LAN hosts
  dns_upstream:
    - "1.1.1.1"
    - "8.8.8.8"
  dns_mode: "strict"         # strict | local
  local_dns:                 # optional; route private TLDs to your own resolver
    - server: "192.0.2.53"
      domains: ["lan", "home.arpa"]
```

- **`enabled`** must stay `false` until a connection has been imported,
  selected and verified. The wizard always stages gateway mode this way.
- **`native_tun`** uses sing-box's TUN inbound. When the selected engine cannot
  provide it, Bypath uses tun2socks; it never downgrades silently after a
  native-TUN failure.
- **`interface`** is never assumed. On a host with more than one private
  network, set it explicitly.
- **`dns_mode: strict`** resolves through the tunnel and returns failure rather
  than falling back to a direct resolver. `local` explicitly permits direct
  upstream queries.
- **`local_dns`** forwards the listed suffixes to a resolver on your own
  network. The example address is from the RFC 5737 documentation range.

## engines

```yaml
engines:
  directory: "./engines"
  prefer_system: true
  preferred: ""              # "sing-box", "xray", or empty for auto
  fallback:
    enabled: true
    timeout: "10s"
    endpoint_timeout: "90s"
    total_timeout: "5m"
    order: ["sing-box", "xray"]
```

Fallback tries the next engine only when the current one fails to start or
fails its readiness probe. Timeouts bound one link attempt and the whole chain,
so an unreachable group cannot hold the gateway in a connecting state
indefinitely.

## routing

```yaml
routing:
  rules:
    - match: geoip:<cc>
      outbound: direct
    - match: domain_suffix:example.com
      outbound: direct
    - match: default
      outbound: proxy
  external_outbounds:
    office-proxy: "socks5://proxy.example:1080"
```

Matchers:

| Matcher | Meaning |
|---|---|
| `geoip:<cc>` | Destination IP in a country database, two-letter ISO code. |
| `geosite:<tag>` | Domain in a domain-list category. |
| `domain:<name>` | Exact domain. |
| `domain_suffix:<suffix>` | Domain and its subdomains. |
| `ip_cidr:<cidr>` | Destination IP range. |
| `default` | Everything not matched above. |

Outbounds: `direct`, `proxy`, or a name declared in `external_outbounds`.
Rules are evaluated in order; the first match wins. Private IP ranges always go
direct. When `routing.rules` is non-empty it replaces the legacy `whitelist`
block entirely.

Country rules require geo data. For the embedded Xray engine, `geoip.dat` and
`geosite.dat` are fetched from the v2fly release feeds when needed; they are not
hash-pinned in this pre-release. A missing geo file fails its rule; it does not
silently match everything.

Editing rules from the panel or API previews the resulting configuration before
writing it. An edit that sends a domain direct while another rule tunnels an
overlapping domain is reported as a warning, because it changes where that
traffic exits.

## Legacy whitelist (deprecated)

```yaml
whitelist:
  countries: ["<cc>"]
  geosite_countries: ["<cc>"]
  bypass_domains: ["example.com"]
  force_proxy_domains: ["must-tunnel.example"]
  update_interval: "24h"
```

Legacy whitelist configuration still loads with a deprecation notice. If both a
whitelist block and `routing.rules` are present, the rules win and Bypath prints
an explicit notice, because the whitelist fields then have no effect.

## chains

```yaml
chains:
  - name: "multi-hop"
    auto_start: false
    hops:
      - profile: "relay"
        engine: "sing-box"
        isolate: true
      - profile: "exit"
```

A chain is an ordered sequence of stored profiles. `isolate` runs the hop in a
network namespace when isolation is available on the host.

## isolation

```yaml
isolation:
  enabled: true
```

Isolates tunnel processes in a network namespace so a helper process cannot use
the host's direct route. If the host cannot provide the required primitives, the
gateway reports that the isolation is unavailable rather than pretending it is
active.

## health_check

```yaml
health_check:
  enabled: true
  interval: "30s"
  url: "https://example.com"
```

A tunnel is only reported healthy after an HTTPS round trip succeeds. A UDP/443
timeout is reported as failed; a blocked result is only used when a controlled
probe shows direct egress is also unavailable, and it never counts as a pass.

## sni_spoof

```yaml
sni_spoof:
  enabled: false
  mode: "replace"    # replace | fragment
  sni: "example.com"
```

Presents a different TLS server name on the wire. Disabled by default; use only
where you understand the consequences for certificate checks end to end.

## update

```yaml
update:
  url: "https://releases.example.net/bypath/latest.json"
```

Self-update is disabled unless this points at a feed publishing the GitHub
releases JSON shape (`tag_name`, `body`, `assets[].digest`). The feed must be
HTTPS; plain HTTP is accepted only for a loopback test feed. This pre-release
does not ship a default update feed.

## tests

```yaml
tests:
  isolation_verified: false
  parallel: 2
  speed_per_link_mb: 10
  speed_per_batch_mb: 40
  monthly_budget_mb: 0
```

Host capability flags and limits for relay and speed testing. When
`isolation_verified` is false, isolated results are reported as inconclusive.
These values are deliberately not writable from the panel: they describe the
host, not a user preference.

## profiles

```yaml
profiles:
  active_group: ""
  directory: ""
```

Empty values mean "use the installation defaults". Imported connections,
credentials and saved profiles live under the profiles directory with
owner-only permissions.
