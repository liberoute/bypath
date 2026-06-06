# Bypath — Project Context

## Overview
Bypath is a network gateway written in Go that transparently routes LAN traffic through encrypted tunnels. Clients set their DNS and Gateway to the Bypath machine — traffic is either tunneled or sent direct based on rule-based routing (geoip + geosite + domain rules).

Target platforms: Linux (ARM/ARMv7/ARM64/AMD64), partial Windows support (proxy-only mode).
Current version: v2.5.11+

## Tech Stack
- Language: Go 1.24+
- TUI: charmbracelet/bubbletea v1.3+ (KeyMsg.Type/Runes API, tea.ExecProcess for shell-out)
- TUI styling: charmbracelet/lipgloss v1.1+
- HTTP Router: gorilla/mux
- DNS: miekg/dns
- Config: gopkg.in/yaml.v3
- Property-based testing: pgregory.net/rapid v1.1+
- External engines (runtime): sing-box ≥1.12 (tested with 1.13.12), xray, tun2socks (legacy mode only), dns2socks (legacy mode only)
- Build: Makefile with ldflags version injection
- Module path: `github.com/liberoute/bypath`

## Project Structure
- `cmd/bypath/` — Entry point; split into focused files (all package main):
  - `main.go` — dispatch switch + printUsage (~105 lines)
  - `cmd_run.go` — cmdRun (daemon startup, pidfile, retry loop, API server)
  - `cmd_profile.go` — cmdAdd, cmdRemove, cmdList, helpers
  - `cmd_select.go` — cmdSelect, warnIfCDN
  - `cmd_probe.go` — cmdTest (dry-run link/config validation)
  - `cmd_bench.go` — cmdBench, benchLinkOnPort, buildOutbound, parseMs
  - `cmd_sub.go` — cmdSub and subcommands
  - `cmd_chain.go` — cmdChain and subcommands
  - `cmd_system.go` — cmdStop, cmdEngines, cmdUpdate
  - `helpers.go` — detectEngine, createDefaultConfig, setupLogging, path helpers
- `internal/api/` — REST API server (gorilla/mux, token auth, port 8080)
  - Routes prefix: `/api/v1/`
  - Chain CRUD endpoints partially implemented (POST/DELETE/start/stop missing, only GET /chains exists)
  - GET /status returns: version, active_engine, tunnels, chains, whitelist
- `internal/build/` — Version/commit/date info (injected via ldflags); also has `UpdateURL`, `Variant` ("lite"/"full"), `UserAgent()`
- `internal/config/` — YAML config loading + defaults
- `internal/dns/` — SOCKS DNS proxy
- `internal/engine/` — Engine manager (detect on PATH, download, embed via build tags)
  - `manager.go` — detect sing-box, xray, wireguard-go, openvpn, ssh, sshpass on init
  - `process.go` — `StartProcess()`, `Process` struct with `IsRunning()`/`Stop()`, `FirejailOptions`
  - `fallback.go` — `FallbackController`, `StartWithFallback()`, `ConfigGeneratorIface`
  - `downloader.go`, `embedded.go`/`embedded_stub.go` — download + build-tag embedding
- `internal/gateway/` — Main orchestrator (iptables, tun, routing, sing-box/xray, tun2socks, dns2socks)
- `internal/geo/` — Geoip/geosite file downloader
- `internal/health/` — Health checks
- `internal/isolation/` — Network namespace isolation (netns)
- `internal/paths/` — Path detection (local vs installed mode, auto-detect)
- `internal/pidfile/` — PID file management
- `internal/profile/` — Profile/link/subscription CRUD (JSON persistence, Group/Link structs)
  - `cdn.go` — `IsCDNPattern()`, `MarkCDNDetected()` (called in `loadAll()`)
  - `httpscheck.go` — `TestHTTPS(ctx, proxyPort)` using curl
  - `autoselect.go` — `SelectBest()` preferring HTTPS-capable links
- `internal/tui/` — Interactive terminal UI (bubbletea, tab-based: Home/Servers/Subscriptions)
  - `tui.go` — Main TUI model, views, input handling, confirm dialogs
  - `bench.go` — Parallel speed test (ping/relay/download), always uses sing-box
- `internal/tunnel/` — Tunnel config generation (sing-box + xray JSON from Link struct)
  - `configgen.go` — `ConfigGenerator`, `GenerateChainConfig()`, `BuildSingboxOutbound()` (public, used by bench + chain)
  - `chain.go` — `StartChain()`, `StartChainSingleProcess()`, `resolveChainStrategy()`
- `internal/updater/` — Self-update logic (GitHub releases); `Check()`, `CheckAndLog()`, `findAsset()` (variant-aware)
- `internal/whitelist/` — Country whitelist (legacy, actual whitelist is in sing-box geoip rule_set)

## Key Data Structures
- `config.Config` — Root YAML config (Server, Gateway, Engines, Routing, Whitelist, Isolation, Chains, DHCP, SNISpoof)
  - `Engines.PreferredEngine` — "sing-box" or "xray" (empty = auto/sing-box)
  - `Engines.Fallback` — `FallbackConfig{Enabled bool, Timeout string, Order []string}` (default: enabled, 10s, [sing-box,xray])
  - `Gateway.NativeTUN` — bool, default true; enables sing-box native TUN inbound (no tun2socks/dns2socks)
  - `Routing.Rules` — `[]RoutingRule{Match, Outbound}` — new rule-based system; when non-empty overrides whitelist
  - `Routing.ExternalOutbounds` — map[name]url for proxy servers not managed by bypath
  - `SNISpoofConfig` — `Enabled bool`, `SNI string`, `Mode string` ("replace" or "fragment")
- `profile.Link` — Single proxy link (protocol, address, port, UUID, TLS, SNI, transport params, Reality fields)
  - Runtime-only fields (json:"-"): `ChainProxy string`, `ListenPort int`, `CDNDetected bool`
  - Persisted HTTPS test result: `HTTPSCapable int` (0=untested, 1=ok, -1=failed)
- `profile.Group` — Collection of links + subscription URLs
- `profile.Manager` — CRUD for groups/links, persists as JSON in data/profiles/
- `engine.Engine` — Engine binary info (Name, Path, Version, Source)
- `engine.FallbackController` — Orchestrates multi-engine startup with fallback; implements `ConfigGeneratorIface` dependency injection
- `engine.FallbackResult` — `{Engine, Process, ConfigFile, EngineName, WasFallback, Attempts}`
- `tunnel.ConfigGenerator` — Generates sing-box/xray/wireguard JSON configs from Link
  - Fields: `RoutingRules []RoutingRule`, `ExternalOutbounds map[string]string`, `WhitelistCountries`, `GeositeCountries`, `BypassDomains`, `PinnedHosts map[string]string`, `DNSUpstream`, `SOCKSPort`, `SNISpoof`, `GatewayMode`, `DNSPort`

## Routing System (v2.5.10+)

Rule-based routing replaces the legacy whitelist config:

```yaml
routing:
  rules:
    - match: geoip:ir         # matchers: geoip:<cc>, geosite:<tag>,
      outbound: direct        # domain:<exact>, domain_suffix:<suffix>,
    - match: geosite:ir       # ip_cidr:<cidr>, default
      outbound: direct        # outbounds: direct, proxy, or external name
    - match: default
      outbound: proxy
  # External proxy servers not managed by bypath profiles:
  external_outbounds:
    lray-proxy: socks5://172.20.100.12:8088
```

When `routing.rules` is non-empty it overrides `whitelist` entirely. Legacy whitelist config still works but shows a deprecation warning at startup.

## Supported Protocols
VMess, VLESS (with Reality + xhttp), Trojan, Shadowsocks, WireGuard, SSH, SOCKS5, HTTP Proxy

## Engines
- **sing-box** — Default engine. Best compatibility (Reality, xhttp, all protocols). Used for bench/speed test always.
- **xray** — Alternative engine. Supports Reality (with publicKey/shortId/fingerprint), socks5, vmess, vless, trojan. Some Reality links may not work with xray (server-dependent).
- Engine preference only affects gateway connection, not speed test.

## Engine Fallback (FallbackController)
`internal/engine/fallback.go` — `FallbackController` tries engines in order for a given link:
- Calls `configGen.Generate(eng, link)` for each engine attempt
- Starts process, polls SOCKS port until ready or timeout
- Logs ❌ failure / 🔄 fallback / ✅ success
- `StartWithFallback(ctx, link, preferredEngine)` returns `*FallbackResult` with `EngineName`, `WasFallback`
- `ConfigGeneratorIface` interface avoids import cycle (engine ← tunnel ← engine forbidden)
- `gateway.startEngine()` creates FallbackController + delegates; sets `gw.activeEngine`
- `GetActiveEngine() string` exposed on Gateway; wired into `/api/v1/status` as `active_engine`

## Gateway Modes
- **Native TUN mode** (default, `gateway.native_tun: true`): sing-box handles TUN device and DNS natively.
  - Inbounds: TUN inbound (`tun-in`) + DNS inbound (`dns-in`) + Mixed inbound
  - No tun2socks or dns2socks processes needed
  - sing-box auto_route handles policy routing; iptables only does NAT masquerade + FORWARD
  - Falls back to legacy mode if TUN device doesn't appear within 10s
- **Legacy mode** (`gateway.native_tun: false`): tun2socks + DNS proxy
  - sing-box or xray runs Mixed inbound only (SOCKS5/HTTP on port 2801)
  - tun2socks creates tun0 device → connects to SOCKS5 port
  - iptables fwmark 0x1 + policy routing table 100
  - DNS: tries dns2socks (DNS through tunnel) → dnsmasq (DNS direct) → built-in DoH forwarder via SOCKS5 (no external tool needed, avoids ISP DNS poisoning)

## sing-box 1.12+ Compatibility (IMPORTANT)
sing-box 1.12+ deprecated several config fields. Current code handles:
- DNS servers: use `{"type": "udp", "server": "1.1.1.1", "server_port": 53}` format (NOT `"address": "udp://..."`)
- DNS direct server: NO `detour: "direct"` (causes "detour to empty direct outbound" error)
- No `independent_cache` in DNS section
- No `dns.listen` / `dns.listen_port` — use separate DNS inbound instead
- Route must have `default_domain_resolver: "dns-direct"`
- Rule sets: only reference geosite/geoip files that actually exist on disk (`os.Stat` check)
- TUN inbound: use `address` (not `inet4_address`), no `sniff` field
- DNS inbound type: `"direct"` with `override_address`/`override_port`
- Route rules: use `"action": "route"` + `"outbound"` (not `"outboundTag"`)
- Route rules sniff/resolve: `{"action": "sniff", "timeout": "300ms"}` and `{"action": "resolve", "server": "dns-direct"}`

## xray DNS & Routing
- xray DNS uses DoH (`https://1.1.1.1/dns-query`) via the proxy outbound — plain UDP DNS fails silently through TCP-only VLESS WebSocket transports (xray 25.x). DoH goes over TCP/HTTPS and survives any transport.
- Bootstrap domains (proxy server hostname, SNI, bypass domains) are resolved via direct DoH (no proxy) to avoid chicken-and-egg startup issues.
- Routing: `domainStrategy: "IPIfNonMatch"` — if no domain rule matches, resolve to IP and check IP rules. Required for `geoip:ir` to fire.
- Direct (freedom) outbound: `domainStrategy: "UseIPv4"` — resolves via xray's DoH DNS, NOT system DNS. Prevents `SSL_ERROR_SYSCALL` for Iranian sites.
- `geosite:ir` is NOT used in xray routing — standard geosite.dat doesn't include IR. Only `geoip:ir` is used.
- xray routing: RFC1918 explicit ranges direct routing (NOT `geoip:private` — unavailable in standalone xray) + bypass_domains support.
- xray VLESS/WS outbound: must include `wsSettings` with `host` header, `allowInsecure: true` in tlsSettings.

## TUI Architecture
- bubbletea model with tabs (Home/Servers/Subscriptions)
- Input modes: normal navigation, text input (paste-aware via KeyRunes), confirm dialog (Yes/No with arrows)
- Async operations via `tea.Cmd` returning `actionDoneMsg`
- Shell-out for self-update: `tea.ExecProcess` (pauses TUI, runs command with full terminal access)
- Status detection: checks PID files + `pgrep` fallback for systemd processes
- Bench results: sorted display (fastest first by default), `f` to toggle, selection uses sorted index
- Self-update: asks "Direct / Over Bypath" before downloading
- Status IP detection: uses `icanhazip.com` (not affected by bypass_domains)

## Chain Strategy
Two strategies auto-resolved at startup:
- **Single-process** (`StrategySingleProcess`): all hops are sing-box-compatible protocols. One sing-box instance with `detour`-linked outbounds. Uses `GenerateChainConfig()` → chain listens on port 10800.
- **Multi-process** (`StrategyMultiProcess`): any hop uses SSH or a non-sing-box engine. Each hop runs as a separate process, each on `10800+i`. Previous hop's listen port is set as `ChainProxy` for the next hop.
- `resolveChainStrategy()` checks hop engine + protocol to decide. Falls back to multi-process if profile not found.
- XTLS flow (`xtls-rprx-vision`) is stripped from non-first hops (incompatible with detour).

## Build & Test
- Build: `make lite` (external engines) or `make full` (embedded, `-tags full`)
- Cross-compile for Orange Pi: `$env:GOOS="linux"; $env:GOARCH="arm"; $env:GOARM="7"; go build -o .tmp/bypath ./cmd/bypath`
- Build output goes to `.tmp/` directory (gitignored). NEVER put build artifacts, test configs, or debug scripts in project root.
- Deploy: `scp .tmp/bypath root@172.16.11.15:/tmp/bypath-fix` then copy on device
- Test: `go test -v -race ./...`
- Lint: `go vet ./...`
- Cross-compile targets: linux/amd64, linux/arm64, linux/arm (ARMv7), linux/mipsle, windows/amd64

## Test Environment
- **Active server:** `root@172.16.11.196` — Debian 12 x86_64, full build (embedded sing-box working)
- **Previous server:** Orange Pi Zero (ARMv7, Armbian): `root@172.16.11.15`
- sing-box 1.13.12 installed on system (also embedded in full build)
- See `deploy_env.md` in memory for current deploy workflow

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
- TUI: bubbletea with `tea.Cmd` for async, `tea.ExecProcess` for shell-out, `msg.Type`/`msg.Runes` for input
- Active link persistence: group+remark stored in `.active` file, TrimSpace on both sides when loading
- Temp files: `.tmp/` directory (gitignored). NEVER in project root.

## Known Technical Debt
- **Embedded xray broken** — needs `geoip.dat`/`geosite.dat` (xray format) but only `.srs` files exist; xray embedded will fail on startup when selected as engine
- **Metrics HTTP endpoint missing** — `internal/metrics/metrics.go` defines Prometheus counters/gauges but there is no `/metrics` HTTP endpoint wired up anywhere; the counters are incremented but never exposed
- **Config hot-reload not implemented** — `ConfigReloads` counter defined but no SIGHUP handler or `fsnotify` watcher; `[x] Config hot-reload` in TODO.md was incorrect
- `internal/whitelist/` is legacy (whitelist now handled by sing-box rule_set; routing.rules is the new system)
- Gateway accessor methods lack proper locking
- API token stored plaintext in config
- xray bench code (`testRelayXray`) is unused (bench always uses sing-box) but kept for future use
- Some reality links work with sing-box but not xray (server-dependent, not a code bug)
- TUN inbound `dns-in` uses `"direct"` type with `override_address`/`override_port` (DNS redirect hack)
- Chain API endpoints (POST/DELETE/start/stop) not yet implemented in `internal/api/handlers.go`
- `handleStartTunnel` in API has a TODO — not fully implemented
- `handleListEngines` in API returns "not yet implemented"
- `singboxDNS()` falls back to `WhitelistCountries` when `GeositeCountries` is empty (implicit coupling)

## API
REST API on port 8080 with optional token auth.
Routes prefix: `/api/v1/`
Endpoints: GET /status, GET|POST|DELETE /profiles/groups/*, POST /profiles/links, DELETE /profiles/links/{group}/{remark}, GET /tunnels, POST /tunnels/start, POST /tunnels/{name}/stop, GET /chains, GET|POST /whitelist/*, POST /subscriptions/update/{group}, GET /engines
Auth header: `Authorization: Bearer <token>` or `X-API-Key: <token>`
**Note:** Chain write endpoints (POST /chains, DELETE /chains/{name}, POST /chains/{name}/start/stop) are NOT yet registered.

`GET /status` response includes: `version`, `active_engine` (name of running engine), `tunnels`, `chains`, `whitelist`

## File Paths (Runtime)
- Local mode: `configs/default.yaml`, `data/profiles/`, `data/tmp/`, `engines/`
- Installed mode: `/etc/bypath/config.yaml`, `/etc/bypath/profiles/`, `/opt/bypath/engines/`, `/etc/bypath/geo/`
- Detection: binary in `/opt/bypath/` or `/usr/local/bin/` or `/etc/bypath/config.yaml` exists → installed mode
- Active link: `data/profiles/.active` (format: `group\nremark`)
- Generated config: `data/tmp/singbox-config.json` or `data/tmp/xray-config.json`

## Implemented Features (Spec-Driven)
Do not re-implement or revert these:

- **`singbox-tun-inbound`** — Native TUN mode for sing-box: TUN inbound + DNS inbound + Mixed inbound. Falls back to legacy mode if TUN device doesn't appear within 10s.

- **`reality-support`** — Full Reality protocol support for both sing-box and xray. Parses `publicKey`, `shortId`, `fingerprint` from VLESS+Reality URIs. XTLS flow supported on first hop only.

- **`multi-hop-chain`** — Proxy chain support with StrategySingleProcess / StrategyMultiProcess auto-selected at startup. XTLS flow stripped from non-first hops.

- **`ssh-tunnel`** — SSH protocol as a hop in proxy chains via StrategyMultiProcess.

- **`domain-whitelist`** — `bypass_domains` config: per-domain direct routing. Default list includes `"ir"` (all `.ir` TLD → direct). Empty entries filtered.

- **`cdn-https-detection`** — Automatic CDN-fronted HTTPS proxy detection. Results influence auto-select. Post-start async check logs warning if CDN link can't relay HTTPS.

- **`xray-fallback`** — FallbackController in `internal/engine/fallback.go`. Iterates engine order (sing-box → xray by default), tries each engine for the same link. `engines.fallback` config section. Active engine exposed in `/status`. Config: `engines.fallback.enabled/timeout/order`.

- **`rule-based-routing`** — `routing.rules` config replaces legacy whitelist. Matchers: `geoip:<cc>`, `geosite:<tag>`, `domain:<exact>`, `domain_suffix:<suffix>`, `ip_cidr:<cidr>`, `default`. Outbounds: `direct`, `proxy`, or named external outbound. When rules non-empty, whitelist config is ignored.

- **`vpn-detection-bypass`** — Reality protocol, xhttp transport, TLS fingerprinting via utls/chrome.

## Important Bugs Fixed (v2.5.11 — Don't Reintroduce)

- **Embedded sing-box DNS crash** — `encoding/json.Unmarshal` leaves `DNSServerOptions.Options` nil (it has `json:"-"`). Fix: use `singJSON.UnmarshalContext(ctx, data, &opts)` with `ctx = include.Context(ctx)` set up BEFORE the call. See `internal/engine/embedded.go`.
- **Self-update crash loop** — `cmdUpdate()` replaced binary but left old process running → stale PID file → new binary saw "already running" → systemd restart loop. Fix: after successful binary replacement, kill old process + restart systemd service.
- **TUI "No server selected" despite connected** — `getActiveLink()` fallback path returned a link without calling `SetActiveLink()` → `.active` file never written → TUI showed "No server selected". Fix: fallback now calls `gw.profileMgr.SetActiveLink(l)` before returning.
- **install.sh `bypath add` ordering** — server link was added before default profile JSON was created → `bypath add` failed silently. Fix: profile file creation happens before server link addition.

## Important Bugs Fixed (v2.5.x — Don't Reintroduce)
- Active link matching: always `strings.TrimSpace` on remark when comparing
- xray stop cleanup: `bypath stop` must kill both xray and sing-box processes
- sing-box 1.13 TUN: `address` (not `inet4_address`), no `sniff` in TUN inbound
- verifyConnection: use `gstatic.com`, `msftconnecttest.com`, `captive.apple.com` (NOT `cp.cloudflare.com` — CDN VLESS proxies answer that check from their own edge, giving a false positive). Use `--interface localIP` in native TUN mode to bypass sing-box auto_route
- bypass_domains: default list includes `"ir"` (all `.ir` TLD → direct, avoids 403 from foreign IPs); empty entries filtered out
- Updater variant: lite build downloads lite asset, full downloads full
- TUI server selection: use `systemctl restart` when running under systemd
- xray domainStrategy: MUST be `"IPIfNonMatch"` — dns2socks resolves via tunnel (real IPs); geoip:ir then correctly identifies Iranian sites. `xrayGeositeAvailable()` must guard geosite:ir rule (xray crashes with "code not found" if geosite.dat is missing or lacks IR category)
- Legacy mode DNS: `setupRouting()` must set `/etc/resolv.conf` to `127.0.0.1` (dns2socks) after pinning server hostname to `/etc/hosts`
- geosite rule_set consistency: DNS rules must only reference rule_set tags that are defined in route section
- xray downloader: must extract binary from .zip archive, not store the .zip directly and try to exec it
- geo file validation: `fileExists()` checks file size > 16 bytes to detect empty/stub files from failed downloads
- Self-healing: `cleanupPreviousRun()` must run at the top of `Start()` — kills tracked children (PIDs from `/var/run/bypath.children`), flushes iptables+routing, restores resolv.conf
- DNS intercept: `setupDNSIntercept()` must add iptables PREROUTING REDIRECT :53 → dns_port in BOTH native TUN and legacy modes
- resolv.conf lifecycle: always back up original before overwriting; restore from backup on stop
- pinHostToEtcHosts: must be called BEFORE engine start; use custom resolver bypassing resolv.conf; reject private/bogon IPs
- FallbackController.tryEngine: do NOT call proc.Wait() in startup code — causes double-Wait race with gateway cleanup. Poll port until timeout instead; kill+Wait only on failure.
