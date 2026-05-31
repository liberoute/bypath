# Implementation Plan: VPN Detection Bypass

## Overview

Add domain-based direct routing to bypass VPN detection endpoints. Implementation touches `internal/config/config.go` (new field + defaults) and `internal/tunnel/configgen.go` (new routing rule generation). The project uses Go, so all code is in Go.

## Tasks

- [x] 1. Add BypassDomains field to config
  - [x] 1.1 Add `BypassDomains []string` field to `WhitelistConfig` struct in `internal/config/config.go` with yaml tag `bypass_domains,omitempty`
    - _Requirements: 1.1_
  - [x] 1.2 Add default bypass domains in `applyDefaults()` — when `cfg.Whitelist.BypassDomains` is empty, set it to `["cloudflare.com", "ip-api.com", "ipinfo.io", "api.myip.com"]`
    - _Requirements: 1.2_
  - [x] 1.3 Add validation that filters out empty strings from `BypassDomains` (log warning for each removed entry)
    - _Requirements: 1.4_
  - [ ]* 1.4 Write unit tests for config defaults and validation
    - Test that omitted bypass_domains gets defaults applied
    - Test that explicitly set bypass_domains is preserved
    - Test that empty strings are filtered out
    - _Requirements: 1.2, 1.3, 1.4_

- [x] 2. Add BypassDomains to ConfigGenerator and generate domain bypass rule
  - [x] 2.1 Add `BypassDomains []string` field to `ConfigGenerator` struct in `internal/tunnel/configgen.go`
    - _Requirements: 2.1_
  - [x] 2.2 Implement `singboxBypassDomainRule()` method that returns a `domain_suffix` rule routing to "direct" outbound
    - _Requirements: 2.1, 2.3_
  - [x] 2.3 Modify `singboxRoute()` to insert the domain bypass rule after sniff/resolve but before private IP and geoip rules
    - _Requirements: 2.2_
  - [x] 2.4 Modify `generateSingBox()` to include route/dns sections when `BypassDomains` is non-empty (even if `WhitelistCountries` is empty)
    - _Requirements: 2.4_
  - [ ]* 2.5 Write property test: generated config contains correct domain bypass rule
    - **Property 3: Generated config contains correct domain bypass rule**
    - **Validates: Requirements 2.1, 2.3, 2.4**
  - [ ]* 2.6 Write property test: domain bypass rule precedes geoip rules
    - **Property 4: Domain bypass rule precedes geoip rules**
    - **Validates: Requirements 2.2**

- [x] 3. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 4. Wire bypass domains from config to ConfigGenerator
  - [x] 4.1 Update the code that creates `ConfigGenerator` instances (in `internal/gateway/gateway.go` and `cmd/bypath/main.go`) to pass `cfg.Whitelist.BypassDomains` to the `BypassDomains` field
    - This ensures bypass rules work in both gateway mode and proxy-only mode
    - _Requirements: 3.1, 3.2, 3.3_
  - [x] 4.2 Update `configs/default.yaml` to include a commented `bypass_domains` example under the `whitelist` section
    - _Requirements: 1.1_

- [ ] 5. Serialization round-trip and integration
  - [ ]* 5.1 Write property test: config serialization round-trip preserves bypass_domains
    - **Property 5: Config serialization round-trip**
    - **Validates: Requirements 4.1, 4.2**
  - [ ]* 5.2 Write unit test: end-to-end config load → generate sing-box config with bypass domains
    - Load a YAML config with bypass_domains, create ConfigGenerator, generate sing-box config, verify domain rule is present
    - _Requirements: 2.1, 3.1, 3.2_

- [x] 6. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- The `domain_suffix` field in sing-box matches the domain and all subdomains automatically
- Property-based tests use `pgregory.net/rapid` library
- The ConfigGenerator is mode-agnostic — it produces the same config for gateway and proxy modes, so wiring the bypass domains in both call sites is sufficient to satisfy Requirement 3
