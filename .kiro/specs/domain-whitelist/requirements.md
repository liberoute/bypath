# Requirements Document

## Introduction

Iranian websites like digikala.com time out when DNS resolves through the tunnel because CDN domains return non-Iranian IPs. The existing geoip whitelist only matches destination IPs after resolution, which fails when DNS itself goes through the tunnel. This feature adds domain-based whitelist rules (geosite) so that DNS for Iranian domains resolves directly and traffic routes directly, complementing the existing geoip-based IP whitelist.

## Glossary

- **Config_Generator**: The component (`internal/tunnel/configgen.go`) that produces sing-box JSON configuration from link and whitelist settings.
- **Geosite_Rule_Set**: A sing-box binary rule set file (`.srs` format) containing domain lists for a specific country, sourced from the SagerNet/sing-geosite repository.
- **Geoip_Rule_Set**: The existing binary rule set file containing IP ranges for a country, used for IP-based direct routing.
- **Direct_DNS_Server**: A DNS server entry in the sing-box config that resolves domains without going through the tunnel.
- **Tunnel_DNS_Server**: A DNS server entry that resolves domains through the proxy outbound.
- **Whitelist_Config**: The YAML configuration section (`whitelist:`) that controls which countries and domains bypass the tunnel.
- **Sing_Box**: The proxy engine used by Bypath for traffic routing, supporting geoip and geosite rule sets.

## Requirements

### Requirement 1: Geosite Rule Set Configuration

**User Story:** As a user, I want to configure geosite-based domain whitelisting, so that Iranian domain traffic bypasses the tunnel entirely including DNS resolution.

#### Acceptance Criteria

1. THE Whitelist_Config SHALL include a `geosite_countries` field accepting a list of country codes (e.g., `["ir"]`)
2. THE Whitelist_Config SHALL include a `geosite_url` field for specifying the download URL template for geosite rule set files
3. WHEN `geosite_countries` is omitted from the configuration, THE Config_Generator SHALL default to an empty list (geosite disabled)
4. WHEN `geosite_url` is omitted from the configuration, THE Config_Generator SHALL use the default SagerNet/sing-geosite GitHub release URL
5. THE Whitelist_Config SHALL store geosite rule set files in the same `GeoDir` directory used by geoip rule sets

### Requirement 2: DNS Rule Generation

**User Story:** As a user, I want DNS queries for Iranian domains to resolve directly (not through the tunnel), so that CDN domains return Iranian IP addresses.

#### Acceptance Criteria

1. WHEN `geosite_countries` contains entries, THE Config_Generator SHALL produce a DNS configuration with both a direct DNS server and a tunnel DNS server
2. WHEN a domain matches the Geosite_Rule_Set, THE Config_Generator SHALL generate a DNS rule directing resolution to the Direct_DNS_Server
3. WHEN a domain does not match the Geosite_Rule_Set, THE Config_Generator SHALL generate a DNS rule directing resolution to the Tunnel_DNS_Server
4. THE Config_Generator SHALL reference the geosite rule set by tag in DNS rules using the format `geosite-{country}`

### Requirement 3: Route Rule Generation

**User Story:** As a user, I want traffic to Iranian domains to route directly after DNS resolves to Iranian IPs, so that the full connection bypasses the tunnel.

#### Acceptance Criteria

1. WHEN `geosite_countries` contains entries, THE Config_Generator SHALL generate a route rule matching domains against the Geosite_Rule_Set and routing to the direct outbound
2. THE Config_Generator SHALL place the geosite route rule before the geoip route rule in the rule list
3. THE Config_Generator SHALL include the geosite rule set definition in the route `rule_set` array with type `local`, format `binary`, and the correct file path

### Requirement 4: Coexistence with Geoip Whitelist

**User Story:** As a user, I want geosite and geoip whitelists to work together (belt and suspenders), so that Iranian traffic is caught by either domain match or IP match.

#### Acceptance Criteria

1. WHEN both `geosite_countries` and `countries` (geoip) are configured, THE Config_Generator SHALL include both geosite and geoip rule sets in the generated configuration
2. WHEN only `geosite_countries` is configured (no geoip), THE Config_Generator SHALL generate a valid configuration with only domain-based routing
3. WHEN only `countries` (geoip) is configured (no geosite), THE Config_Generator SHALL generate a valid configuration identical to the current behavior
4. THE Config_Generator SHALL maintain the existing resolve-then-geoip-match flow alongside the new domain-match flow

### Requirement 5: Geosite Rule Set File Management

**User Story:** As a user, I want geosite rule set files to be downloaded and updated automatically, so that the domain list stays current without manual intervention.

#### Acceptance Criteria

1. WHEN the geosite rule set file does not exist in GeoDir, THE system SHALL download it from the configured `geosite_url`
2. WHEN the `update_interval` elapses, THE system SHALL re-download the geosite rule set file
3. IF the download fails, THEN THE system SHALL log a warning and continue operating with the existing file if available
4. IF the download fails and no existing file is available, THEN THE system SHALL log an error and skip geosite rules in the generated configuration
