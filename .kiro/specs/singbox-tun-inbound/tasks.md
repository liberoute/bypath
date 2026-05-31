# Implementation Plan: sing-box Native TUN Inbound

## Overview

Replace the 3-process gateway architecture with sing-box's native TUN inbound and DNS handling. Implementation proceeds bottom-up: config generation first, then orchestrator changes, then routing adaptation.

## Tasks

- [ ] 1. Add `NativeTUN` config field
  - Add `NativeTUN bool` field to `GatewayConfig` in `internal/config/config.go` with yaml tag `native_tun`
  - Set default to `true` in `applyDefaults()`
  - _Requirements: 6.1_

- [ ] 2. Extend ConfigGenerator for gateway mode
  - [ ] 2.1 Add gateway mode fields to ConfigGenerator
    - Add `GatewayMode bool` and `DNSPort int` fields to the `ConfigGenerator` struct in `internal/tunnel/configgen.go`
    - _Requirements: 1.1, 2.5_

  - [ ] 2.2 Implement TUN inbound generation
    - Create `singboxInboundsGateway(link *profile.Link) []map[string]interface{}` method
    - Return array with TUN inbound (`type: "tun"`, `inet4_address: "10.0.0.1/30"`, `auto_route: true`, `stack: "system"`, `sniff: true`) and Mixed inbound (existing logic)
    - _Requirements: 1.1, 1.3, 1.4, 1.5, 1.6_

  - [ ] 2.3 Implement DNS configuration generation
    - Create `singboxDNS() map[string]interface{}` method
    - Generate `servers` array with `dns-tunnel` (detour: proxy) and `dns-direct` (detour: direct)
    - Generate `rules` array with geosite rule_set entries for each whitelist country routing to dns-direct
    - Include `listen` address (`0.0.0.0`) and port when in gateway mode
    - Set `final: "dns-tunnel"` and `independent_cache: true`
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5_

  - [ ] 2.4 Update generateSingBox to use gateway mode
    - Modify `generateSingBox()` to check `cg.GatewayMode`
    - When true: call `singboxInboundsGateway()` instead of `singboxInbounds()`, call `singboxDNS()` for DNS section
    - When false: use existing `singboxInbounds()` logic, omit DNS listen config
    - Update route section to include geosite rule_set definitions alongside geoip ones when in gateway mode
    - _Requirements: 1.2, 2.6_

  - [ ]* 2.5 Write property tests for config generation
    - **Property 1: Gateway mode produces both TUN and Mixed inbounds**
    - **Property 2: TUN inbound has correct constant fields**
    - **Property 3: Proxy-only mode produces only Mixed inbound**
    - **Property 4: Gateway DNS has tunnel and direct servers with correct routing**
    - **Property 5: DNS rules reference whitelist countries**
    - **Property 6: DNS listen is present only in gateway mode**
    - Use `pgregory.net/rapid` library with minimum 100 iterations per property
    - Create generators for random Link structs (varying protocol, port, address, TLS, etc.)
    - **Validates: Requirements 1.1-1.6, 2.1-2.6**

- [ ] 3. Checkpoint - Verify config generation
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 4. Update Gateway Orchestrator for native TUN mode
  - [ ] 4.1 Add native TUN detection and startup logic
    - Add `nativeTUN bool` field to `Gateway` struct
    - In `startEngine()`, set `configGen.GatewayMode = true` and `configGen.DNSPort = gw.dnsPort` when `gw.config.Gateway.Enabled && gw.config.Gateway.NativeTUN`
    - After engine starts successfully with TUN config, set `gw.nativeTUN = true`
    - _Requirements: 3.5, 6.3_

  - [ ] 4.2 Implement TUN device wait logic
    - Create `waitForTUNDevice(name string, timeout time.Duration) error` helper
    - Poll for network interface existence using `net.InterfaceByName()`
    - Use 10-second timeout with 500ms polling interval
    - _Requirements: 3.4_

  - [ ] 4.3 Modify Start() to skip tun2socks and dns2socks in native TUN mode
    - After successful engine start with TUN config, skip `startDNS()` and `startTun()` calls
    - Instead call `waitForTUNDevice("tun0", 10*time.Second)`
    - Log "🚀 Using sing-box native TUN mode (no tun2socks/dns2socks needed)"
    - _Requirements: 3.1, 3.2, 3.3_

  - [ ] 4.4 Implement fallback to legacy mode
    - If sing-box fails to start with TUN config OR TUN device doesn't appear:
      - Log warning: "⚠️ sing-box native TUN failed, falling back to legacy mode"
      - Kill failed sing-box process
      - Regenerate config with `GatewayMode = false`
      - Restart sing-box with mixed-inbound config
      - Call `startDNS()` and `startTun()` as before
      - Set `gw.nativeTUN = false`
    - If `config.Gateway.NativeTUN == false`, skip native TUN attempt entirely
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 6.2_

  - [ ]* 4.5 Write integration tests for gateway orchestrator
    - Test native TUN path: verify tun2socks/dns2socks not started
    - Test fallback path: verify legacy processes started after TUN failure
    - Test config-driven disable: verify legacy mode when native_tun=false
    - _Requirements: 3.1-3.5, 5.1-5.4_

- [ ] 5. Adapt routing rules for native TUN mode
  - [ ] 5.1 Simplify setupRouting for native TUN
    - When `gw.nativeTUN == true`:
      - Skip fwmark marking (`iptables -t mangle` rules)
      - Skip policy routing (`ip rule add fwmark`, `ip route add table 100`)
      - Still enable IP forwarding (`sysctl net.ipv4.ip_forward=1`)
      - Still configure NAT masquerade on LAN interface
      - Still configure FORWARD rules (LAN ↔ tun0)
    - When `gw.nativeTUN == false`: use existing full routing setup
    - _Requirements: 4.1, 4.2, 4.3_

  - [ ] 5.2 Update cleanupRouting for both modes
    - Clean up iptables rules regardless of mode (mangle, nat, forward)
    - Skip `ip link del tun0` in native TUN mode (sing-box cleans up its own device)
    - Skip `ip rule del fwmark` in native TUN mode
    - _Requirements: 4.4_

  - [ ] 5.3 Update Stop() method
    - When `gw.nativeTUN == true`: don't kill tunProc/dnsProc (they don't exist)
    - Killing engineProc is sufficient — sing-box removes its TUN device on exit
    - _Requirements: 4.4_

- [ ] 6. Checkpoint - Full integration verification
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 7. Wire everything together and final cleanup
  - [ ] 7.1 Update gateway.go startEngine to pass gateway config to ConfigGenerator
    - Ensure `configGen.GatewayMode` and `configGen.DNSPort` are set from gateway config in `startEngine()`
    - Ensure fallback path resets `configGen.GatewayMode = false` before regenerating
    - _Requirements: 1.1, 1.2, 6.2, 6.3_

  - [ ] 7.2 Update default.yaml with native_tun field
    - Add `native_tun: true` under `gateway:` section in `configs/default.yaml`
    - _Requirements: 6.1_

  - [ ]* 7.3 Write end-to-end unit test for config generation round trip
    - Generate config with gateway mode → parse JSON → verify structure
    - Generate config with proxy mode → parse JSON → verify no TUN
    - Test with various protocol types (vmess, vless, trojan, shadowsocks)
    - _Requirements: 1.1-1.6, 2.1-2.6_

- [ ] 8. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- The config generation changes (tasks 2.x) are pure functions and fully testable without system dependencies
- The orchestrator changes (tasks 4.x) require Linux for full integration testing but logic can be unit tested with mocks
- Property tests validate universal correctness of config generation across all protocol types
- Fallback ensures zero downtime for users upgrading — old sing-box versions continue to work
