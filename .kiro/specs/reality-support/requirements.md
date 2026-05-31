# Requirements Document

## Introduction

VLESS Reality is a censorship-resistant protocol that uses TLS with Reality handshake parameters (public key, short ID) and UTLS fingerprinting to disguise traffic. Currently, Bypath's link parser and config generator silently ignore Reality-specific URI parameters (`pbk`, `sid`, `fp`), causing Reality links to produce invalid sing-box configurations that fail at runtime. This feature adds full Reality parameter support across the parsing, storage, and config generation pipeline.

## Glossary

- **Parser**: The `parseVless()` function in `internal/profile/parser.go` that extracts fields from VLESS URIs
- **Link_Struct**: The `profile.Link` struct in `internal/profile/profile.go` that stores parsed proxy link data
- **Config_Generator**: The `singboxOutbounds()` method in `internal/tunnel/configgen.go` that produces sing-box JSON outbound configuration
- **Bench_Builder**: The `buildOutbound()` function in `cmd/bypath/main.go` that produces sing-box JSON for benchmarking
- **Reality_Link**: A VLESS URI with `security=reality` and parameters `pbk` (public key), `sid` (short ID), and `fp` (fingerprint)
- **UTLS_Fingerprint**: The `fp` parameter specifying which browser TLS fingerprint to emulate (e.g., `chrome`, `firefox`, `safari`)
- **Public_Key**: The `pbk` parameter containing the server's Reality public key (base64-encoded x25519 key)
- **Short_ID**: The `sid` parameter containing a hex-encoded short identifier for the Reality handshake

## Requirements

### Requirement 1: Store Reality Parameters in Link Struct

**User Story:** As a developer, I want the Link struct to have dedicated fields for Reality parameters, so that parsed Reality data can be carried through the system without loss.

#### Acceptance Criteria

1. THE Link_Struct SHALL include a `RealityPublicKey` field of type string for storing the `pbk` value
2. THE Link_Struct SHALL include a `RealityShortID` field of type string for storing the `sid` value
3. THE Link_Struct SHALL include a `Fingerprint` field of type string for storing the `fp` (UTLS fingerprint) value
4. THE Link_Struct SHALL serialize the new fields to JSON with tags `reality_pbk`, `reality_sid`, and `fingerprint` respectively
5. WHEN a Link_Struct has empty Reality fields, THE JSON serialization SHALL omit those fields using the `omitempty` option

### Requirement 2: Parse Reality Parameters from VLESS URIs

**User Story:** As a user, I want to add VLESS Reality links via URI, so that the system correctly extracts all Reality-specific parameters for later config generation.

#### Acceptance Criteria

1. WHEN a VLESS URI contains `security=reality` and a `pbk` query parameter, THE Parser SHALL store the `pbk` value in the Link's `RealityPublicKey` field
2. WHEN a VLESS URI contains `security=reality` and a `sid` query parameter, THE Parser SHALL store the `sid` value in the Link's `RealityShortID` field
3. WHEN a VLESS URI contains an `fp` query parameter, THE Parser SHALL store the `fp` value in the Link's `Fingerprint` field
4. WHEN a VLESS URI has `security=reality` but is missing `pbk`, THE Parser SHALL still parse the link without error and leave `RealityPublicKey` empty
5. WHEN a VLESS URI has `security=reality` but is missing `sid`, THE Parser SHALL still parse the link without error and leave `RealityShortID` empty
6. FOR ALL valid VLESS Reality URIs, parsing the URI and then re-reading the stored fields SHALL produce values identical to the original URI query parameters (round-trip preservation)

### Requirement 3: Generate sing-box Reality TLS Configuration

**User Story:** As a user, I want Reality links to produce valid sing-box configurations, so that my VLESS Reality connections work correctly.

#### Acceptance Criteria

1. WHEN a Link has `Security` equal to `reality` and `RealityPublicKey` is non-empty, THE Config_Generator SHALL produce a TLS object with `reality.enabled` set to `true` and `reality.public_key` set to the `RealityPublicKey` value
2. WHEN a Link has `Security` equal to `reality` and `RealityShortID` is non-empty, THE Config_Generator SHALL include `reality.short_id` set to the `RealityShortID` value in the TLS object
3. WHEN a Link has a non-empty `Fingerprint` field, THE Config_Generator SHALL include `utls.enabled` set to `true` and `utls.fingerprint` set to the `Fingerprint` value in the TLS object
4. WHEN a Link has `Security` equal to `reality`, THE Config_Generator SHALL set `tls.enabled` to `true` and `tls.server_name` to the Link's SNI value
5. WHEN a Link has `Security` equal to `reality`, THE Config_Generator SHALL NOT include `tls.insecure` in the output

### Requirement 4: Generate sing-box Reality Configuration in Bench Builder

**User Story:** As a user, I want the bench command to correctly test Reality links, so that benchmarking produces accurate latency results for Reality servers.

#### Acceptance Criteria

1. WHEN a Link has `Security` equal to `reality`, THE Bench_Builder SHALL produce a TLS object with `reality.enabled` set to `true`, `reality.public_key`, and `reality.short_id` matching the Link's stored values
2. WHEN a Link has a non-empty `Fingerprint` field, THE Bench_Builder SHALL include `utls.enabled` set to `true` and `utls.fingerprint` in the TLS object
3. THE Bench_Builder output for Reality links SHALL be structurally equivalent to the Config_Generator output for the same Link input

### Requirement 5: Backward Compatibility

**User Story:** As a user with existing saved profiles, I want my non-Reality links to continue working unchanged after this update.

#### Acceptance Criteria

1. WHEN a Link has `Security` equal to `tls` (not `reality`), THE Config_Generator SHALL produce the same TLS output as before this change
2. WHEN loading a previously-saved JSON profile that lacks Reality fields, THE Link_Struct SHALL deserialize without error and leave Reality fields empty
3. WHEN a VLESS URI has no `pbk`, `sid`, or `fp` parameters, THE Parser SHALL produce a Link identical to the current behavior
