# Requirements Document

## Introduction

Multi-hop proxy chaining allows Bypath users to define a sequence of proxy hops so that traffic traverses multiple servers before reaching the internet. This is essential for bypassing censorship that blocks direct connections to foreign servers, adding layers of anonymity, and using local relay servers to reach foreign exit nodes. Example: Client → hop1 (vmess in Iran) → hop2 (vless in Germany) → internet.

## Glossary

- **Chain**: An ordered sequence of two or more proxy hops through which traffic flows sequentially before reaching the internet.
- **Hop**: A single proxy server in a chain, identified by a profile link and optional engine override.
- **Chain_Manager**: The component within the tunnel package responsible for starting, stopping, and monitoring chains.
- **Config_Generator**: The component that produces sing-box JSON configuration with chained outbounds using the "detour" field.
- **CLI**: The command-line interface provided by the `bypath` binary for user interaction.
- **TUI**: The interactive terminal user interface built with bubbletea.
- **API_Server**: The REST API server that exposes chain management endpoints.
- **Profile_Manager**: The component that manages proxy link profiles and groups.
- **Detour**: The sing-box configuration field that specifies which outbound a given outbound should use as its upstream transport.

## Requirements

### Requirement 1: Chain Definition in Configuration

**User Story:** As a network administrator, I want to define multi-hop chains in the YAML configuration file, so that traffic routes through multiple proxy servers on startup.

#### Acceptance Criteria

1. THE Config SHALL support a `chains` array where each entry contains a `name` field and a `hops` array with two or more hop entries.
2. WHEN a chain is defined with fewer than two hops, THE Config SHALL treat the chain as a single-hop tunnel and start it without chaining.
3. WHEN a chain is loaded from configuration, THE Chain_Manager SHALL validate that each hop references an existing profile link before starting.
4. IF a hop references a non-existent profile, THEN THE Chain_Manager SHALL return an error identifying the chain name, hop index, and missing profile name.
5. WHERE an `engine` field is specified on a hop, THE Chain_Manager SHALL use that engine for the hop instead of auto-detecting from protocol.

### Requirement 2: Chain Management via CLI

**User Story:** As a user, I want to manage chains from the command line, so that I can create, list, remove, and start chains without editing YAML files.

#### Acceptance Criteria

1. WHEN the user runs `bypath chain add <name> <hop1-profile> <hop2-profile> [hopN-profile...]`, THE CLI SHALL create a new chain entry in the configuration with the specified hops in order.
2. WHEN the user runs `bypath chain list`, THE CLI SHALL display all defined chains with their name, number of hops, and current status.
3. WHEN the user runs `bypath chain remove <name>`, THE CLI SHALL remove the named chain from the configuration.
4. WHEN the user runs `bypath chain start <name>`, THE CLI SHALL start the named chain by invoking the Chain_Manager.
5. WHEN the user runs `bypath chain stop <name>`, THE CLI SHALL stop the named chain by invoking the Chain_Manager.
6. IF the user attempts to add a chain with a name that already exists, THEN THE CLI SHALL return an error stating the chain name is already in use.
7. IF the user attempts to start a chain that is already running, THEN THE CLI SHALL return an error stating the chain is already active.

### Requirement 3: Sing-box Configuration Generation with Detour Chaining

**User Story:** As a developer, I want the config generator to produce sing-box JSON that chains outbounds via the "detour" field, so that traffic flows through each hop sequentially within a single sing-box instance.

#### Acceptance Criteria

1. WHEN a chain with N hops is provided, THE Config_Generator SHALL produce N outbound entries where each outbound (except the last) has a `detour` field pointing to the next hop's outbound tag.
2. THE Config_Generator SHALL assign unique tags to each outbound in the format `chain-<chain_name>-hop-<index>`.
3. WHEN generating chained outbounds, THE Config_Generator SHALL set the final hop's outbound as the one without a `detour` field (the exit node).
4. THE Config_Generator SHALL produce a single inbound entry (mixed type) that routes traffic to the first hop's outbound tag.
5. WHEN a chain contains mixed protocols, THE Config_Generator SHALL generate the correct outbound type for each hop's protocol (vmess, vless, trojan, shadowsocks, wireguard, socks5).
6. FOR ALL valid chain configurations, generating a config then parsing the resulting JSON SHALL produce a valid sing-box configuration object (round-trip property).

### Requirement 4: Mixed Protocol Support

**User Story:** As a user, I want to combine different proxy protocols in a single chain, so that I can use the best protocol for each hop based on network conditions.

#### Acceptance Criteria

1. THE Chain_Manager SHALL support chains combining any two or more of the following protocols: vmess, vless, trojan, shadowsocks, wireguard, socks5.
2. WHEN a chain mixes protocols that require different engines, THE Chain_Manager SHALL use the multi-process approach (one engine per hop with SOCKS chaining between them).
3. WHEN all hops in a chain use protocols supported by sing-box, THE Chain_Manager SHALL use the single-process approach (one sing-box instance with detour chaining).
4. THE Chain_Manager SHALL select the chaining strategy (single-process vs multi-process) automatically based on the protocols in the chain.

### Requirement 5: Chain Status Reporting

**User Story:** As a user, I want to see the status of each chain and its individual hops, so that I can monitor connectivity and diagnose issues.

#### Acceptance Criteria

1. THE API_Server SHALL expose a `GET /chains` endpoint that returns all chains with their name, overall status, and per-hop status.
2. WHEN a chain is running, THE API_Server SHALL report each hop's protocol, engine, and individual status (running, stopped, error).
3. THE TUI SHALL display active chains in the Home tab showing chain name, hop count, and overall status.
4. WHEN the user selects a chain in the TUI, THE TUI SHALL display detailed per-hop information including protocol, server address, and status.
5. THE CLI SHALL display chain status when the user runs `bypath chain status [name]`.

### Requirement 6: Chain Failure Handling

**User Story:** As a user, I want clear error reporting when a chain hop fails, so that I can identify and fix the problematic hop.

#### Acceptance Criteria

1. IF a hop fails to start during chain startup, THEN THE Chain_Manager SHALL stop all previously started hops in reverse order and report which hop failed with the error message.
2. IF a running hop process exits unexpectedly, THEN THE Chain_Manager SHALL mark that hop and the overall chain as "error" status.
3. WHEN a hop failure is detected, THE Chain_Manager SHALL log the failure with the chain name, hop index, hop profile name, and error details.
4. IF a hop fails during chain startup, THEN THE Chain_Manager SHALL include the hop index (zero-based) and profile name in the returned error.
5. THE API_Server SHALL include error details in the chain status response when a chain or hop is in error state.

### Requirement 7: Chain Benchmarking

**User Story:** As a user, I want to test the end-to-end latency of a chain, so that I can evaluate whether the multi-hop path is acceptable for my use case.

#### Acceptance Criteria

1. WHEN the user runs `bypath bench --chain <name>`, THE CLI SHALL start the named chain temporarily, measure round-trip latency through the full chain, and stop the chain.
2. THE CLI SHALL display the total chain latency and individual hop TCP ping times during a chain benchmark.
3. WHEN benchmarking a chain, THE CLI SHALL use a temporary listen port that does not conflict with the main gateway SOCKS port.
4. IF any hop in the chain fails during benchmarking, THEN THE CLI SHALL report which hop failed and clean up all temporary processes.
5. WHEN the chain benchmark completes successfully, THE CLI SHALL display the measured latency in milliseconds.

### Requirement 8: Chain Persistence

**User Story:** As a user, I want chains defined via CLI to persist across restarts, so that I do not need to re-create them each time.

#### Acceptance Criteria

1. WHEN a chain is added via CLI, THE CLI SHALL write the chain definition to the YAML configuration file.
2. WHEN a chain is removed via CLI, THE CLI SHALL remove the chain definition from the YAML configuration file.
3. WHEN the gateway starts, THE Chain_Manager SHALL read chain definitions from the configuration and start chains marked as auto-start.
4. THE Config SHALL support an optional `auto_start` boolean field on each chain definition (default: false).
