# Requirements Document

## Introduction

Mobile carrier apps (Irancell, Hamrah-e-Aval) detect VPN usage by calling IP geolocation endpoints such as `cloudflare.com/cdn-cgi/trace` and checking the `loc` field. If the response shows a non-Iranian location, the carrier app restricts functionality. This feature adds domain-based direct routing rules to the sing-box configuration so that traffic to known VPN-detection endpoints always bypasses the tunnel and returns `loc=IR`.

## Glossary

- **ConfigGenerator**: The component in `internal/tunnel/configgen.go` that produces sing-box JSON configuration from a Link struct
- **Bypass_Domains**: A list of domain names whose traffic must be routed directly (not through the tunnel) to avoid VPN detection
- **Direct_Route**: A sing-box routing rule that sends matching traffic to the "direct" outbound instead of the "proxy" outbound
- **Gateway_Mode**: Operating mode where the Bypath machine acts as the network gateway for LAN clients (iptables + tun)
- **Proxy_Mode**: Operating mode where Bypath exposes a SOCKS5/HTTP mixed proxy on a local port
- **Config**: The root YAML configuration structure in `internal/config/config.go`

## Requirements

### Requirement 1: Configurable Bypass Domain List

**User Story:** As a user, I want to configure which domains bypass the tunnel, so that I can control which VPN-detection endpoints are routed directly.

#### Acceptance Criteria

1. THE Config SHALL include a `bypass_domains` field under the `whitelist` section that accepts a list of domain strings
2. WHEN the `bypass_domains` field is empty or omitted, THE Config SHALL apply a default list containing `cloudflare.com`, `ip-api.com`, `ipinfo.io`, and `api.myip.com`
3. WHEN the `bypass_domains` field is explicitly set, THE Config SHALL use only the user-provided list without merging with defaults
4. THE Config SHALL validate that each entry in `bypass_domains` is a non-empty string

### Requirement 2: Domain-Based Direct Routing in sing-box Config

**User Story:** As a user, I want traffic to VPN-detection domains to bypass the tunnel automatically, so that carrier apps always see my real Iranian IP.

#### Acceptance Criteria

1. WHEN bypass domains are configured, THE ConfigGenerator SHALL produce a sing-box route rule that matches those domains and routes them to the "direct" outbound
2. THE ConfigGenerator SHALL place the domain bypass rule before the geoip whitelist rules in the route rule list so that domain matching takes priority
3. WHEN a bypass domain is specified (e.g. `cloudflare.com`), THE ConfigGenerator SHALL match both the domain itself and all subdomains (e.g. `www.cloudflare.com`, `cdn-cgi.cloudflare.com`)
4. THE ConfigGenerator SHALL include the domain bypass rule in the generated config regardless of whether geoip whitelist countries are configured

### Requirement 3: Bypass Rules in Both Operating Modes

**User Story:** As a user, I want VPN-detection bypass to work whether I use Bypath as a gateway or as a local proxy, so that carrier apps cannot detect VPN in either mode.

#### Acceptance Criteria

1. WHEN operating in Gateway_Mode, THE ConfigGenerator SHALL include domain bypass rules in the generated sing-box configuration
2. WHEN operating in Proxy_Mode, THE ConfigGenerator SHALL include domain bypass rules in the generated sing-box configuration
3. THE ConfigGenerator SHALL produce identical domain bypass routing rules for both Gateway_Mode and Proxy_Mode

### Requirement 4: Serialization Round-Trip for Bypass Configuration

**User Story:** As a developer, I want the bypass domain configuration to survive serialization and deserialization, so that config loading is reliable.

#### Acceptance Criteria

1. FOR ALL valid Config objects containing bypass_domains, serializing to YAML then deserializing SHALL produce an equivalent bypass_domains list
2. WHEN a Config with bypass_domains is loaded from a YAML file, THE Config SHALL preserve the exact order and content of the domain list
