# Requirements Document

## Introduction

CDN-based VLESS/VMess links that use Cloudflare Workers (port 443, TLS, WebSocket transport) can only relay HTTP traffic — they cannot forward HTTPS connections because the CDN terminates TLS and the worker only sees plaintext HTTP inside the tunnel. These links pass current bench tests (which use HTTP endpoints like `http://ip-api.com/json` and `http://cp.cloudflare.com`) but fail for real browsing where most sites require HTTPS. This feature adds detection of CDN-pattern links, HTTPS connectivity testing during bench, and user-facing warnings so users don't unknowingly select links that can't handle HTTPS traffic.

## Glossary

- **Link**: A `profile.Link` struct representing a single proxy/VPN connection configuration
- **CDN_Link**: A Link whose traffic is routed through a CDN (e.g., Cloudflare Workers) that terminates TLS, making it unable to relay HTTPS connections
- **Bench**: The speed/connectivity testing process that evaluates links by starting a local sing-box proxy and curling through it
- **HTTPS_Test**: A connectivity check that attempts to fetch an HTTPS URL through the proxy to verify end-to-end encrypted traffic works
- **Detection_Heuristic**: A set of conditions on Link fields used to identify CDN-pattern links without requiring a live test
- **Auto_Select**: The `bench --auto` mode that automatically picks the best-performing link

## Requirements

### Requirement 1: CDN Pattern Detection

**User Story:** As a user, I want the system to identify CDN-pattern links by their configuration, so that I can be warned before selecting a link that may not support HTTPS.

#### Acceptance Criteria

1. WHEN a Link has port 443 AND network is "ws" AND TLS is true AND host field differs from address field, THE Detection_Heuristic SHALL classify the Link as a CDN_Link
2. WHEN a Link has port 443 AND network is "ws" AND TLS is true AND host field is empty, THE Detection_Heuristic SHALL NOT classify the Link as a CDN_Link
3. WHEN a Link uses the "reality" security type, THE Detection_Heuristic SHALL NOT classify the Link as a CDN_Link regardless of other fields
4. WHEN a Link has network "grpc" or "tcp", THE Detection_Heuristic SHALL NOT classify the Link as a CDN_Link even if port is 443 and TLS is true
5. THE Detection_Heuristic SHALL return a boolean result indicating whether a given Link matches the CDN pattern

### Requirement 2: HTTPS Connectivity Test

**User Story:** As a user, I want the bench process to test HTTPS connectivity in addition to HTTP, so that I know which links actually work for real browsing.

#### Acceptance Criteria

1. WHEN a bench test runs for a Link, THE Bench SHALL perform an HTTPS_Test by attempting to fetch an HTTPS URL through the proxy
2. WHEN the HTTPS_Test succeeds (HTTP status 200 or 204), THE Bench SHALL record the Link as HTTPS-capable
3. WHEN the HTTPS_Test fails (timeout, connection error, or non-success status), THE Bench SHALL record the Link as HTTPS-incapable
4. THE HTTPS_Test SHALL use a timeout of 8 seconds to account for slower CDN links
5. THE HTTPS_Test SHALL target a reliable HTTPS endpoint such as `https://cp.cloudflare.com` or `https://www.gstatic.com/generate_204`

### Requirement 3: Link Capability Marking

**User Story:** As a user, I want links to carry an HTTPS capability flag, so that the system can make informed decisions about link selection.

#### Acceptance Criteria

1. THE Link struct SHALL include an `HTTPSCapable` field that indicates whether the link has passed an HTTPS_Test
2. WHEN a Link has not been tested for HTTPS, THE `HTTPSCapable` field SHALL default to a value indicating "untested"
3. WHEN the Detection_Heuristic identifies a Link as a CDN_Link AND no HTTPS_Test has been performed, THE system SHALL mark the Link as "cdn_suspected" 
4. WHEN an HTTPS_Test completes, THE system SHALL update the `HTTPSCapable` field to reflect the test result

### Requirement 4: User Warning Display

**User Story:** As a user, I want to see clear warnings when I select or view a CDN-only link, so that I understand its limitations before using it.

#### Acceptance Criteria

1. WHEN displaying bench results in CLI, THE system SHALL show an indicator next to links that failed the HTTPS_Test
2. WHEN displaying bench results in TUI, THE system SHALL show a visual indicator (color or icon) for links that failed the HTTPS_Test
3. WHEN a user selects a link that is marked as HTTPS-incapable, THE system SHALL display a warning message explaining that the link may not work for HTTPS browsing
4. WHEN listing links via `bypath list`, THE system SHALL show the HTTPS capability status for links that have been tested

### Requirement 5: Auto-Select HTTPS Preference

**User Story:** As a user running `bench --auto`, I want the system to prefer links that pass the HTTPS test, so that auto-selected links work for real browsing.

#### Acceptance Criteria

1. WHEN Auto_Select chooses the best link, THE system SHALL prefer links that passed the HTTPS_Test over links that failed it
2. WHEN multiple HTTPS-capable links exist, THE system SHALL select the one with the lowest latency among them
3. WHEN no HTTPS-capable links exist, THE system SHALL fall back to the fastest link overall and display a warning that no HTTPS-capable links were found
4. WHEN Auto_Select skips a faster link due to HTTPS failure, THE system SHALL log which link was skipped and why
