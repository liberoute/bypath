# Requirements Document

## Introduction

When sing-box fails to start with a given link configuration (process exits quickly or the SOCKS port never becomes ready), Bypath should automatically attempt to use xray as a fallback engine. Currently, users must manually switch engines via the `engines.preferred` config field. This feature automates that fallback, generates an xray-compatible config, starts xray with tun2socks (since xray lacks native TUN), and logs the fallback clearly so the user knows which engine is active.

## Glossary

- **Engine_Manager**: The component (`internal/engine/manager.go`) that detects, downloads, and provides access to tunnel engine binaries (sing-box, xray, etc.)
- **Config_Generator**: The component (`internal/tunnel/configgen.go`) that produces engine-specific JSON configuration files from a `Link` struct
- **Gateway**: The orchestrator (`internal/gateway/gateway.go`) that starts the engine process, DNS proxy, tun2socks, and configures routing
- **Fallback_Controller**: The new component responsible for detecting engine startup failure and coordinating the switch to an alternative engine
- **Link**: A proxy configuration containing protocol, address, port, credentials, and transport settings
- **Engine_Failure**: A condition where the engine process exits within a short time window after launch, or the expected SOCKS port does not become ready within a timeout period
- **Xray_Config**: A JSON configuration file in xray-core format, distinct from sing-box format

## Requirements

### Requirement 1: Detect Engine Startup Failure

**User Story:** As a user, I want Bypath to detect when sing-box fails to start, so that it can automatically try an alternative engine without manual intervention.

#### Acceptance Criteria

1. WHEN the sing-box process exits within 5 seconds of launch, THE Fallback_Controller SHALL classify this as an Engine_Failure
2. WHEN the SOCKS port does not become ready within the configured timeout (default 10 seconds), THE Fallback_Controller SHALL classify this as an Engine_Failure
3. WHEN an Engine_Failure is detected, THE Fallback_Controller SHALL terminate the failed engine process and release its resources

### Requirement 2: Automatic Xray Fallback

**User Story:** As a user, I want Bypath to automatically try xray when sing-box fails, so that my connection works without manual engine switching.

#### Acceptance Criteria

1. WHEN an Engine_Failure occurs for sing-box AND xray is available on the system, THE Fallback_Controller SHALL initiate a fallback to xray
2. WHEN xray is not available on the system, THE Fallback_Controller SHALL log a clear error message indicating no fallback engine is available
3. WHEN the fallback to xray also fails, THE Fallback_Controller SHALL report both failures and stop attempting further engines
4. IF the `engines.fallback.enabled` configuration is set to false, THEN THE Fallback_Controller SHALL skip the fallback attempt and report the original failure

### Requirement 3: Xray Configuration Generation

**User Story:** As a user, I want Bypath to generate a valid xray configuration from my link, so that xray can connect using the same server details.

#### Acceptance Criteria

1. WHEN a fallback to xray is initiated, THE Config_Generator SHALL produce a valid Xray_Config from the same Link struct
2. THE Config_Generator SHALL support vmess, vless, trojan, and shadowsocks protocols in Xray_Config format
3. WHEN a Link uses a protocol not supported by xray (e.g., hysteria2, tuic), THE Config_Generator SHALL return an error indicating the protocol is unsupported for xray
4. THE Config_Generator SHALL map transport settings (websocket path, gRPC service name, HTTP headers) from the Link to the equivalent xray streamSettings
5. THE Config_Generator SHALL map TLS settings (SNI, ALPN, Reality public key, fingerprint) from the Link to the equivalent xray tlsSettings or realitySettings

### Requirement 4: Xray with Tun2socks Integration

**User Story:** As a user, I want xray to work in gateway mode via tun2socks, so that LAN clients are routed through the tunnel even when xray is the active engine.

#### Acceptance Criteria

1. WHEN xray is started as the active engine in gateway mode, THE Gateway SHALL start tun2socks pointing to xray's SOCKS port
2. WHEN xray is started as the active engine in proxy-only mode, THE Gateway SHALL expose the SOCKS port directly without tun2socks
3. THE Gateway SHALL configure xray to listen on the same SOCKS port as sing-box would have used

### Requirement 5: Fallback Logging and Status

**User Story:** As a user, I want clear logs showing which engine is active and whether a fallback occurred, so that I can understand and troubleshoot my connection.

#### Acceptance Criteria

1. WHEN a fallback from sing-box to xray occurs, THE Fallback_Controller SHALL log the reason for the sing-box failure
2. WHEN a fallback from sing-box to xray occurs, THE Fallback_Controller SHALL log that xray is now the active engine
3. WHEN the Gateway is running, THE Gateway SHALL expose the currently active engine name via the status API endpoint
4. WHEN a fallback succeeds, THE Fallback_Controller SHALL log the total time taken for the fallback process

### Requirement 6: Fallback Configuration

**User Story:** As a user, I want to control whether automatic fallback is enabled, so that I can disable it if I prefer manual engine selection.

#### Acceptance Criteria

1. THE Config SHALL include an `engines.fallback.enabled` field (default: true)
2. THE Config SHALL include an `engines.fallback.timeout` field specifying the failure detection timeout (default: 10 seconds)
3. WHERE the `engines.preferred` field is set to "xray", THE Fallback_Controller SHALL use sing-box as the fallback engine instead
4. THE Config SHALL include an `engines.fallback.order` field to specify the engine fallback sequence (default: ["sing-box", "xray"])
