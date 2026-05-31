# Implementation Plan: CDN HTTPS Detection

## Overview

Implement CDN-pattern link detection and HTTPS connectivity testing for Bypath. The implementation adds a detection heuristic, extends the bench flow with an HTTPS test, adds capability fields to the Link struct, and integrates warnings into CLI/TUI output.

## Tasks

- [ ] 1. Add CDN detection function and Link struct extension
  - [ ] 1.1 Add `HTTPSCapable` field to the Link struct in `internal/profile/profile.go`
    - Add `HTTPSCapable int` field with `json:"https_capable,omitempty"` tag
    - Add `CDNDetected bool` field with `json:"-"` tag (not persisted)
    - _Requirements: 3.1, 3.2_

  - [ ] 1.2 Create `internal/profile/cdn.go` with `IsCDNPattern` function
    - Implement the detection heuristic: port 443 AND network "ws" AND TLS true AND host != "" AND host != address AND security != "reality"
    - Add `MarkCDNDetected(link *Link)` helper that sets `CDNDetected` based on `IsCDNPattern`
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5_

  - [ ]* 1.3 Write property tests for `IsCDNPattern` in `internal/profile/cdn_test.go`
    - **Property 4: CDN classification requires all four conditions**
    - **Property 2: Reality links are never classified as CDN**
    - **Property 3: Non-WebSocket links are never classified as CDN**
    - Use `pgregory.net/rapid` for Link struct generation
    - Minimum 100 iterations per property
    - **Validates: Requirements 1.1, 1.2, 1.3, 1.4**

- [ ] 2. Implement HTTPS connectivity test function
  - [ ] 2.1 Create `internal/profile/httpscheck.go` with `TestHTTPS` function
    - Accept `context.Context` and `proxyPort int` parameters
    - Use curl with `socks5h://127.0.0.1:<port>` to fetch `https://cp.cloudflare.com`
    - Use 8-second timeout via context
    - Return bool (true if HTTP status is 200 or 204)
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5_

- [ ] 3. Implement auto-select logic with HTTPS preference
  - [ ] 3.1 Create `internal/profile/autoselect.go` with `SelectBest` function
    - Accept a slice of bench results (link + latency + httpsOk)
    - Return the best link: prefer HTTPS-capable with lowest latency
    - Fall back to fastest overall if no HTTPS-capable links exist
    - Return a `skipped` list of links that were faster but lacked HTTPS
    - _Requirements: 5.1, 5.2, 5.3, 5.4_

  - [ ]* 3.2 Write property tests for `SelectBest` in `internal/profile/autoselect_test.go`
    - **Property 5: HTTPS-capable links are preferred in auto-select**
    - **Property 6: Auto-select falls back when no HTTPS links exist**
    - Generate random bench result sets with `rapid`
    - Minimum 100 iterations per property
    - **Validates: Requirements 5.1, 5.2, 5.3**

- [ ] 4. Checkpoint
  - Ensure all tests pass with `go test ./internal/profile/...`, ask the user if questions arise.

- [ ] 5. Integrate HTTPS test into CLI bench
  - [ ] 5.1 Modify `benchLinkOnPort` in `cmd/bypath/main.go` to return HTTPS result
    - After successful HTTP relay test, call `profile.TestHTTPS` on the same proxy port
    - Extend `benchResult` struct with `httpsOk bool` field
    - _Requirements: 2.1, 2.2, 2.3_

  - [ ] 5.2 Update CLI bench output to show HTTPS column
    - Add "HTTPS" column header to results table
    - Show ✓ for pass, ✗ for fail, — for untested
    - _Requirements: 4.1_

  - [ ] 5.3 Update CLI auto-select to use `SelectBest` function
    - Replace current "find best by latency" logic with `profile.SelectBest`
    - Print warning if no HTTPS-capable links found
    - Print info about skipped faster links
    - _Requirements: 5.1, 5.2, 5.3, 5.4_

- [ ] 6. Integrate HTTPS test into TUI bench
  - [ ] 6.1 Extend `benchEntry` in `internal/tui/bench.go` with HTTPS field
    - Add `https int` field (1=ok, 0=untested, -1=failed)
    - Call `profile.TestHTTPS` in `runParallelBench` after successful relay
    - _Requirements: 2.1, 2.2, 2.3_

  - [ ] 6.2 Update TUI bench view to display HTTPS status
    - Add "HTTPS" column to the header and entry rendering
    - Use green ✓ for pass, red ✗ for fail, dim — for untested
    - _Requirements: 4.2_

- [ ] 7. Add warnings on link selection and listing
  - [ ] 7.1 Update `cmdSelect` in `cmd/bypath/main.go` to warn on HTTPS-incapable links
    - After selecting a link, check `IsCDNPattern` and `HTTPSCapable`
    - Print warning: `⚠️  This link is CDN-based and may not support HTTPS browsing`
    - _Requirements: 4.3_

  - [ ] 7.2 Update `printGroupLinks` in `cmd/bypath/main.go` to show CDN/HTTPS status
    - Add a status indicator column: `[CDN]` for detected CDN links, `[HTTPS✗]` for tested-and-failed
    - _Requirements: 4.4_

  - [ ] 7.3 Mark CDN detection on profile load
    - In `Manager.loadAll()` or after loading, call `IsCDNPattern` on each link to set `CDNDetected`
    - _Requirements: 3.3_

- [ ] 8. Persist HTTPS test results
  - [ ] 8.1 Update `benchLinkOnPort` and TUI bench to persist `HTTPSCapable` to the Link
    - After bench completes, update the link's `HTTPSCapable` field in the profile JSON
    - Use `Manager.saveGroup` to persist
    - _Requirements: 3.4_

- [ ] 9. Final checkpoint
  - Ensure all tests pass with `go test -v -race ./...`, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- The project uses `pgregory.net/rapid` for property-based testing (add to go.mod)
- The HTTPS test reuses the same sing-box proxy instance that the HTTP relay test already starts — no extra process needed
- `CDNDetected` is a runtime-computed field (not persisted) to avoid stale data if link fields change
- The auto-select logic is extracted into its own function for testability
