# Implementation Plan: Domain Whitelist (Geosite)

## Overview

Add geosite-based domain whitelisting to complement the existing geoip IP whitelist. Implementation touches config (new fields), config generation (DNS split + route rules), and geo file downloading (geosite files). The project uses Go, so all code is in Go.

## Tasks

- [ ] 1. Add geosite fields to WhitelistConfig
  - [ ] 1.1 Add `GeositeCountries []string` and `GeositeURL string` fields to `WhitelistConfig` in `internal/config/config.go` with yaml tags `geosite_countries,omitempty` and `geosite_url,omitempty`
    - _Requirements: 1.1, 1.2_
  - [ ] 1.2 Add default for `GeositeURL` in `applyDefaults()` — when empty, set to `https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite-{country}.srs`
    - `GeositeCountries` defaults to empty (feature disabled by default)
    - _Requirements: 1.3, 1.4_
  - [ ]* 1.3 Write property test: config serialization round-trip preserves geosite fields
    - **Property 1: Config serialization round-trip preserves geosite fields**
    - **Validates: Requirements 1.1, 1.2**
  - [ ]* 1.4 Write unit tests for config defaults
    - Test that omitted geosite_countries stays empty
    - Test that omitted geosite_url gets default applied
    - Test that explicitly set values are preserved
    - _Requirements: 1.3, 1.4_

- [ ] 2. Implement geosite DNS rule generation
  - [ ] 2.1 Add `GeositeCountries []string` field to `ConfigGenerator` struct in `internal/tunnel/configgen.go`
    - _Requirements: 2.1_
  - [ ] 2.2 Implement `singboxDNS(link)` method that generates split DNS config: `dns-direct` (no detour), `dns-tunnel` (detour through proxy), DNS rules referencing geosite rule_sets pointing to `dns-direct`, and final server `dns-tunnel`
    - When `GeositeCountries` is empty, fall back to current simple DNS (direct only, no split)
    - _Requirements: 2.1, 2.2, 2.3, 2.4_
  - [ ] 2.3 Update `generateSingBox()` to call `singboxDNS()` instead of the inline DNS map, using split DNS when geosite is configured
    - _Requirements: 2.1_
  - [ ]* 2.4 Write property test: DNS rules reference geosite rule sets for direct resolution
    - **Property 2: DNS rules reference geosite rule sets for direct resolution**
    - **Validates: Requirements 2.1, 2.2, 2.3, 2.4**

- [ ] 3. Implement geosite route rule generation
  - [ ] 3.1 Implement `singboxGeositeRuleSets()` method returning rule_set definitions (type local, format binary, path from GeoDir)
    - _Requirements: 3.3, 1.5_
  - [ ] 3.2 Modify `singboxRoute()` to insert a geosite domain route rule (rule_set → direct) after private IP rule but before geoip rule
    - _Requirements: 3.1, 3.2_
  - [ ] 3.3 Modify `singboxRoute()` to append geosite rule_set definitions to the route `rule_set` array alongside existing geoip definitions
    - _Requirements: 3.3_
  - [ ]* 3.4 Write property test: route rules contain geosite rule with correct ordering and definition
    - **Property 3: Route rules contain geosite rule with correct ordering and definition**
    - **Validates: Requirements 3.1, 3.2, 3.3, 1.5**

- [ ] 4. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 5. Handle geosite/geoip coexistence and edge cases
  - [ ] 5.1 Update `generateSingBox()` to handle all combinations: both geosite+geoip, geosite-only, geoip-only, neither — ensuring valid config in each case
    - When geosite is configured but geoip is not, still include route section with geosite rules
    - When neither is configured, omit route/dns sections (current behavior for no whitelist)
    - _Requirements: 4.1, 4.2, 4.3, 4.4_
  - [ ]* 5.2 Write property test: geosite and geoip coexistence produces correct combined config
    - **Property 4: Geosite and geoip coexistence produces correct combined config**
    - **Validates: Requirements 4.1, 4.2, 4.3, 4.4**

- [ ] 6. Implement geosite file download
  - [ ] 6.1 Extend geo file download logic in `internal/engine/downloader.go` (or create `internal/geo/downloader.go` if cleaner) to download geosite `.srs` files using the configured URL template
    - Replace `{country}` placeholder in URL with actual country code
    - Save to `GeoDir/geosite-{country}.srs`
    - Reuse existing update_interval logic
    - _Requirements: 5.1, 5.2_
  - [ ] 6.2 Add error handling: log warning on update failure with existing file, log error and skip geosite rules when no file exists
    - _Requirements: 5.3, 5.4_
  - [ ]* 6.3 Write unit tests for download logic
    - Mock HTTP responses for success/failure scenarios
    - Test URL template expansion
    - Test graceful degradation
    - _Requirements: 5.1, 5.2, 5.3, 5.4_

- [ ] 7. Wire geosite config to ConfigGenerator and update default config
  - [ ] 7.1 Update code that creates `ConfigGenerator` instances (in `internal/gateway/gateway.go` and `cmd/bypath/main.go`) to pass `cfg.Whitelist.GeositeCountries` to the new field
    - _Requirements: 1.1, 2.1_
  - [ ] 7.2 Update `configs/default.yaml` to include `geosite_countries` field (commented out with example) under the `whitelist` section
    - _Requirements: 1.1_
  - [ ] 7.3 Trigger geosite file download during startup (alongside existing geoip download) when `GeositeCountries` is non-empty
    - _Requirements: 5.1_

- [ ] 8. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Property-based tests use `pgregory.net/rapid` library (same as vpn-detection-bypass spec)
- The geosite rule_set uses the same `local` type as geoip — files are pre-downloaded, not fetched by sing-box at runtime
- The `{country}` placeholder in `geosite_url` follows the same pattern as SagerNet's release naming: `geosite-ir.srs`
- DNS split is the key insight: without it, all DNS goes through tunnel and CDN domains resolve to non-IR IPs, making geoip useless for those domains
