# Requirements Document

## Introduction

This feature consolidates the Bypath gateway mode from a 3-process architecture (sing-box + tun2socks + dns2socks) into a single sing-box process by leveraging sing-box's native TUN inbound and DNS handling capabilities. This reduces latency, removes external dependencies, and simplifies process orchestration.

## Glossary

- **Config_Generator**: The component (`internal/tunnel/configgen.go`) that produces sing-box JSON configuration from a Link struct
- **Gateway_Orchestrator**: The component (`internal/gateway/gateway.go`) that starts/stops processes and configures system routing
- **TUN_Inbound**: A sing-box inbound type that creates and manages a TUN network device directly
- **Mixed_Inbound**: A sing-box inbound type that accepts both SOCKS5 and HTTP proxy connections on a single port
- **DNS_Module**: The sing-box DNS configuration section that handles DNS resolution with rule-based routing
- **Whitelist**: The set of country codes whose traffic is routed directly (bypassing the tunnel) via geoip rule_set
- **Gateway_Mode**: Operation mode where Bypath acts as a network gateway for LAN clients (`gateway.enabled=true`)
- **Proxy_Mode**: Operation mode where Bypath only provides a SOCKS5/HTTP proxy (`gateway.enabled=false`)
- **Fallback_Mode**: A degraded operation mode using the legacy 3-process architecture when sing-box TUN is unavailable

## Requirements

### Requirement 1: TUN Inbound Configuration Generation

**User Story:** As a gateway operator, I want sing-box to create and manage the TUN device directly, so that I don't need the tun2socks external process.

#### Acceptance Criteria

1. WHEN gateway mode is enabled, THE Config_Generator SHALL produce a sing-box configuration with a TUN inbound containing `type: "tun"`, `inet4_address`, `auto_route`, and `stack` fields
2. WHEN gateway mode is disabled, THE Config_Generator SHALL produce a sing-box configuration with a Mixed_Inbound (SOCKS5/HTTP) as before
3. WHEN gateway mode is enabled, THE Config_Generator SHALL include both a TUN inbound and a Mixed_Inbound so that local SOCKS5 proxy remains available
4. THE Config_Generator SHALL set the TUN inbound `inet4_address` to `"10.0.0.1/30"`
5. THE Config_Generator SHALL set the TUN inbound `stack` to `"system"`
6. THE Config_Generator SHALL set the TUN inbound `auto_route` to `true`

### Requirement 2: DNS Configuration Generation

**User Story:** As a gateway operator, I want sing-box to handle DNS resolution with rule-based routing, so that I don't need the dns2socks external process.

#### Acceptance Criteria

1. WHEN gateway mode is enabled, THE Config_Generator SHALL produce a DNS section with at least two server entries: one tunnel DNS server and one direct DNS server
2. THE Config_Generator SHALL configure the tunnel DNS server to resolve queries through the proxy outbound
3. THE Config_Generator SHALL configure the direct DNS server to resolve queries without the tunnel for whitelisted domains
4. WHEN whitelist countries are configured, THE DNS_Module SHALL use DNS rules to route resolution for whitelisted domains through the direct server
5. THE Config_Generator SHALL set the DNS listen address to `0.0.0.0` on the configured DNS port so LAN clients can use it
6. WHEN gateway mode is disabled, THE Config_Generator SHALL omit the DNS listen configuration

### Requirement 3: Gateway Orchestrator Simplification

**User Story:** As a developer, I want the gateway orchestrator to skip starting tun2socks and dns2socks when sing-box handles TUN and DNS natively, so that the architecture is simpler and has fewer failure points.

#### Acceptance Criteria

1. WHEN sing-box TUN mode is active, THE Gateway_Orchestrator SHALL not start the tun2socks process
2. WHEN sing-box TUN mode is active, THE Gateway_Orchestrator SHALL not start the dns2socks process
3. WHEN sing-box TUN mode is active, THE Gateway_Orchestrator SHALL not manually create or configure the TUN device via `ip tuntap` commands
4. WHEN sing-box TUN mode is active, THE Gateway_Orchestrator SHALL wait for the TUN device to appear (created by sing-box) before configuring routing
5. WHEN sing-box TUN mode is active, THE Gateway_Orchestrator SHALL log that it is using native TUN mode

### Requirement 4: Routing Rules Adaptation

**User Story:** As a gateway operator, I want iptables and routing rules to work correctly with sing-box's native TUN device, so that LAN traffic is properly routed through the tunnel.

#### Acceptance Criteria

1. WHEN sing-box TUN mode is active with `auto_route` enabled, THE Gateway_Orchestrator SHALL skip manual policy routing setup (fwmark, ip rule, route table 100)
2. WHEN sing-box TUN mode is active, THE Gateway_Orchestrator SHALL still configure IP forwarding and NAT masquerade for LAN traffic
3. WHEN sing-box TUN mode is active, THE Gateway_Orchestrator SHALL still configure iptables FORWARD rules to allow traffic between LAN interface and TUN device
4. WHEN the gateway stops, THE Gateway_Orchestrator SHALL clean up iptables rules regardless of which TUN mode was used

### Requirement 5: Backward Compatibility and Fallback

**User Story:** As a user with an older sing-box version that doesn't support TUN inbound, I want the system to fall back to the legacy 3-process method, so that my gateway continues to work.

#### Acceptance Criteria

1. WHEN the sing-box version does not support TUN inbound, THE Gateway_Orchestrator SHALL fall back to the legacy method (tun2socks + dns2socks)
2. WHEN falling back to legacy mode, THE Gateway_Orchestrator SHALL log a warning explaining why fallback occurred
3. WHEN sing-box fails to start with TUN configuration, THE Gateway_Orchestrator SHALL retry with a Mixed_Inbound configuration and start tun2socks and dns2socks
4. THE Gateway_Orchestrator SHALL detect TUN support by attempting to start sing-box with the TUN config and checking for startup failure within a timeout period

### Requirement 6: Configuration Options

**User Story:** As a system administrator, I want to control whether sing-box native TUN is used or the legacy method, so that I can choose the approach that works best for my environment.

#### Acceptance Criteria

1. THE Config SHALL include a `gateway.native_tun` boolean field that defaults to `true`
2. WHEN `gateway.native_tun` is set to `false`, THE Gateway_Orchestrator SHALL use the legacy 3-process method regardless of sing-box capabilities
3. WHEN `gateway.native_tun` is set to `true`, THE Gateway_Orchestrator SHALL attempt native TUN mode with fallback to legacy on failure
