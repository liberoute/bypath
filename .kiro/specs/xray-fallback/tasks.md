# Implementation Plan: Xray Fallback

## Overview

Implement automatic engine fallback so that when sing-box fails to start, Bypath tries xray automatically. The implementation extends config, config generation, and gateway orchestration in that order, wiring everything together at the end.

## Tasks

- [ ] 1. Extend configuration with fallback settings
  - [ ] 1.1 Add FallbackConfig struct to `internal/config/config.go`
    - Add `FallbackConfig` struct with `Enabled bool`, `Timeout string`, `Order []string`
    - Add `Fallback FallbackConfig` field to `EnginesConfig`
    - Set defaults in `applyDefaults`: enabled=true, timeout="10s", order=["sing-box", "xray"]
    - _Requirements: 6.1, 6.2, 6.4_

  - [ ]* 1.2 Write unit tests for fallback config defaults
    - Test parsing config without fallback section yields correct defaults
    - Test parsing config with explicit fallback values preserves them
    - _Requirements: 6.1, 6.2, 6.4_

- [ ] 2. Extend xray config generation in `internal/tunnel/configgen.go`
  - [ ] 2.1 Implement full xray outbound generation for trojan and shadowsocks
    - Add trojan case to `xrayOutbounds` with servers/password settings
    - Add shadowsocks case to `xrayOutbounds` with servers/method/password
    - _Requirements: 3.2_

  - [ ] 2.2 Implement xray streamSettings builder
    - Create `xrayStreamSettings(link *profile.Link) map[string]interface{}` method
    - Support network types: tcp, ws, grpc, http/h2
    - Map wsSettings (path, headers), grpcSettings (serviceName), httpSettings (path, host)
    - Map TLS: tlsSettings with serverName, alpn, fingerprint
    - Map Reality: realitySettings with serverName, fingerprint, publicKey, shortId
    - Refactor existing vmess/vless cases to use the new streamSettings builder
    - _Requirements: 3.4, 3.5_

  - [ ] 2.3 Add unsupported protocol error for xray
    - Return clear error for hysteria2, tuic, wireguard, openvpn protocols in `generateXray`
    - _Requirements: 3.3_

  - [ ]* 2.4 Write property tests for xray config generation
    - **Property 3: Xray config generation produces valid config for supported protocols**
    - **Property 4: Unsupported protocols produce errors**
    - **Property 5: Stream settings mapping preserves transport and TLS configuration**
    - **Property 6: Port consistency across engines**
    - **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 4.3**

- [ ] 3. Checkpoint - Ensure config generation tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 4. Implement FallbackController in `internal/engine/fallback.go`
  - [ ] 4.1 Create FallbackController struct and StartWithFallback method
    - Define `FallbackConfig`, `FallbackResult`, `AttemptRecord` types
    - Implement `StartWithFallback(ctx, link, configGen, socksPort)` that iterates through engine order
    - For each engine: get binary, generate config, start process, wait for port
    - On failure: kill process, record attempt, try next engine
    - Respect `Enabled` flag — if false, only try first engine
    - Handle preferred engine: reorder so preferred is first
    - _Requirements: 1.1, 1.2, 1.3, 2.1, 2.2, 2.3, 2.4, 6.3_

  - [ ] 4.2 Implement failure detection logic
    - Detect early exit: goroutine monitors process, signals failure if exits within timeout
    - Detect port timeout: use existing `waitForPort` with configurable timeout
    - Combine both signals: whichever fires first determines failure
    - _Requirements: 1.1, 1.2_

  - [ ] 4.3 Implement fallback logging
    - Log sing-box failure reason with ❌ prefix
    - Log fallback attempt with 🔄 prefix
    - Log success with ✅ prefix including engine name and elapsed time
    - Log all-failed with ❌ prefix listing all attempts
    - _Requirements: 5.1, 5.2, 5.4_

  - [ ]* 4.4 Write property tests for FallbackController
    - **Property 1: Failure classification by timing threshold**
    - **Property 2: Fallback initiation when alternative engine is available**
    - **Property 7: Fallback order respects preferred engine**
    - **Validates: Requirements 1.1, 1.2, 2.1, 6.3**

- [ ] 5. Integrate fallback into Gateway (`internal/gateway/gateway.go`)
  - [ ] 5.1 Refactor `startEngine` to use FallbackController
    - Create FallbackController in `New()` using config
    - Replace direct engine start in `startEngine` with `fc.StartWithFallback`
    - Store active engine name from FallbackResult
    - Keep existing `startEngineWithFallback` link-rotation logic (it tries different links; the new fallback tries different engines for the same link)
    - _Requirements: 2.1, 4.1, 4.2, 4.3_

  - [ ] 5.2 Add active engine name to Gateway status
    - Add `activeEngine string` field to Gateway struct
    - Expose via existing status accessor or new `GetActiveEngine() string` method
    - Wire into API `/status` response
    - _Requirements: 5.3_

  - [ ]* 5.3 Write unit tests for gateway fallback integration
    - Test that gateway uses FallbackController
    - Test that activeEngine is set correctly after fallback
    - Test proxy-only mode with xray (no tun2socks dependency on engine name)
    - _Requirements: 4.1, 4.2, 5.3_

- [ ] 6. Update default config and documentation
  - [ ] 6.1 Add fallback section to `configs/default.yaml`
    - Add commented `fallback` block under `engines` with defaults
    - _Requirements: 6.1, 6.2, 6.4_

- [ ] 7. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- The existing link-rotation fallback in `startEngineWithFallback` (tries different links) is orthogonal to this feature (tries different engines for the same link). Both can coexist.
- Property tests use `github.com/leanovate/gopter` with minimum 100 iterations
- The xray config generation already has a partial implementation — tasks extend it rather than rewrite
