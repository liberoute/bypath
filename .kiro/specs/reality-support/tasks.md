# Implementation Plan: VLESS Reality Support

## Overview

This plan implements VLESS Reality protocol support across the parsing, storage, and config generation pipeline. The implementation is additive and backward-compatible. Tasks are ordered to build incrementally: struct fields first, then parser, then config generators, with tests alongside each step.

## Tasks

- [ ] 1. Add Reality fields to the Link struct
  - [ ] 1.1 Add `RealityPublicKey`, `RealityShortID`, and `Fingerprint` fields to the `Link` struct in `internal/profile/profile.go`
    - Add fields after `Flow` with JSON tags `reality_pbk,omitempty`, `reality_sid,omitempty`, `fingerprint,omitempty`
    - Add a comment grouping them as "Reality/UTLS fields"
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5_

- [ ] 2. Update the VLESS parser to extract Reality parameters
  - [ ] 2.1 Modify `parseVless()` in `internal/profile/parser.go` to extract `pbk`, `sid`, and `fp` query parameters
    - Add `link.RealityPublicKey = params.Get("pbk")` after existing param extraction
    - Add `link.RealityShortID = params.Get("sid")`
    - Add `link.Fingerprint = params.Get("fp")`
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5_
  - [ ]* 2.2 Write property test for Reality URI parsing round-trip
    - **Property 1: Reality parameter round-trip preservation**
    - **Validates: Requirements 2.1, 2.2, 2.3, 2.6**
  - [ ]* 2.3 Write unit tests for Reality URI parsing
    - Test parsing a complete Reality URI with all params
    - Test parsing a Reality URI with missing `sid`
    - Test parsing a non-Reality VLESS URI produces empty Reality fields
    - _Requirements: 2.4, 2.5, 5.3_

- [ ] 3. Update sing-box config generator for Reality TLS
  - [ ] 3.1 Modify the VLESS case in `singboxOutbounds()` in `internal/tunnel/configgen.go`
    - Restructure the TLS block: if `Security == "reality"`, include `reality` sub-object with `enabled`, `public_key`, `short_id`; omit `insecure`
    - If `Fingerprint` is non-empty, add `utls` sub-object with `enabled` and `fingerprint`
    - For non-Reality TLS, keep existing behavior (`insecure: true`, no `reality` key)
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 5.1_
  - [ ]* 3.2 Write property test for Reality config structure validity
    - **Property 2: Reality config structure validity**
    - **Validates: Requirements 3.1, 3.4, 3.5**
  - [ ]* 3.3 Write property test for UTLS fingerprint inclusion
    - **Property 3: UTLS fingerprint inclusion**
    - **Validates: Requirements 3.3**
  - [ ]* 3.4 Write property test for non-Reality TLS backward compatibility
    - **Property 4: Non-Reality TLS backward compatibility**
    - **Validates: Requirements 5.1**
  - [ ]* 3.5 Write unit test for Reality sing-box config generation
    - Generate config for a Reality link, validate full JSON structure matches expected output
    - Generate config for a standard TLS VLESS link, verify no Reality keys present
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 5.1_

- [ ] 4. Checkpoint - Verify parser and config generator
  - Ensure all tests pass with `go test ./internal/profile/ ./internal/tunnel/`
  - Ask the user if questions arise.

- [ ] 5. Update bench builder for Reality TLS
  - [ ] 5.1 Modify `buildOutbound()` in `cmd/bypath/main.go` to include `reality.public_key`, `reality.short_id`, and `utls` in the Reality branch
    - Update the existing `if link.Security == "reality"` branch to add `public_key` and `short_id` from Link fields
    - Add `utls` block when `Fingerprint` is non-empty
    - _Requirements: 4.1, 4.2_
  - [ ]* 5.2 Write property test for config generator and bench builder equivalence
    - **Property 5: Config generator and bench builder equivalence**
    - **Validates: Requirements 4.3**

- [ ] 6. Backward compatibility verification
  - [ ]* 6.1 Write unit test for legacy JSON deserialization
    - Deserialize a JSON object without Reality fields, verify Link loads without error and Reality fields are empty
    - _Requirements: 5.2_

- [ ] 7. Final checkpoint - Ensure all tests pass
  - Run `go test -v -race ./...` and ensure all tests pass.
  - Ask the user if questions arise.

## Task Dependency Graph

```json
{
  "waves": [
    { "tasks": ["1"] },
    { "tasks": ["2", "3"] },
    { "tasks": ["4"] },
    { "tasks": ["5", "6"] },
    { "tasks": ["7"] }
  ]
}
```

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- The project uses `pgregory.net/rapid` for property-based tests (needs to be added to go.mod)
- Each property test runs minimum 100 iterations
- The existing `buildOutbound()` in main.go already has a partial Reality check — this task completes it
- No deduplication of `buildOutbound()` is done in this spec (that's separate tech debt)
