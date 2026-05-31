# Design Document: Multi-Hop Proxy Chaining

## Overview

This document describes the technical design for multi-hop proxy chaining in Bypath. The design builds on existing infrastructure — the `ChainConfig`/`HopConfig` structs, the `chain.go` tunnel logic, and the sing-box config generator — extending them to support full detour-based chaining within a single sing-box process, CLI management, status reporting, and benchmarking.

## Architecture

The multi-hop chain feature spans four layers:

1. **Configuration Layer** (`internal/config`) — Extended `ChainConfig` with `auto_start` field
2. **Tunnel Layer** (`internal/tunnel`) — Dual-strategy chain execution (single-process detour vs multi-process SOCKS relay)
3. **Interface Layer** (`cmd/bypath`, `internal/api`, `internal/tui`) — CLI commands, API endpoints, TUI display
4. **Benchmarking** (`cmd/bypath`) — Chain-aware bench command

```
┌─────────────────────────────────────────────────────────┐
│                    User Interfaces                        │
│  CLI (bypath chain ...)  │  TUI (Home tab)  │  REST API │
└──────────┬───────────────┴──────┬───────────┴─────┬─────┘
           │                      │                 │
           ▼                      ▼                 ▼
┌─────────────────────────────────────────────────────────┐
│              Chain Manager (internal/tunnel)              │
│  ┌─────────────────┐    ┌──────────────────────────┐    │
│  │ Single-Process   │    │ Multi-Process             │    │
│  │ (detour chain)   │    │ (SOCKS relay per hop)     │    │
│  └────────┬────────┘    └────────────┬─────────────┘    │
│           │                          │                   │
│           ▼                          ▼                   │
│  ┌─────────────────┐    ┌──────────────────────────┐    │
│  │ ConfigGenerator  │    │ Per-hop engine processes   │    │
│  │ (detour JSON)    │    │ (existing StartTunnel)     │    │
│  └─────────────────┘    └──────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

### Design Decisions

**Decision 1: Single-Process vs Multi-Process Chaining Strategy**

Automatic strategy selection based on protocol compatibility:
- **Single-process (preferred):** When all hops use protocols supported by sing-box (vmess, vless, trojan, shadowsocks, wireguard, socks5), generate one sing-box config with detour fields linking outbounds.
- **Multi-process (fallback):** When hops require different engines (e.g., wireguard-go + sing-box), use the existing SOCKS relay approach.

**Decision 2: Detour Configuration Structure**

For single-process chains, the sing-box config uses the `detour` field. Traffic flows: inbound → hop-0 (uses hop-1 as transport) → hop-1 (connects to internet). Tag naming: `chain-<chain_name>-hop-<index>`.

**Decision 3: Configuration Persistence**

CLI chain commands modify the YAML config file directly, keeping chains persistent and visible for manual editing.

**Decision 4: Chain Auto-Start**

Add `auto_start: true` field to `ChainConfig`. During gateway startup, chains with `auto_start: true` are started automatically.

**Decision 5: Port Allocation for Multi-Process Chains**

Each hop uses port `10800 + hopIndex` for local SOCKS relay, avoiding conflicts with the main SOCKS port (2801).

## Components and Interfaces

### ConfigGenerator (internal/tunnel/configgen.go)

```go
// GenerateChainConfig creates a sing-box config with detour-linked outbounds.
func (cg *ConfigGenerator) GenerateChainConfig(chainName string, links []*profile.Link) (string, error)
```

This method:
1. Creates outbound entries for each link with unique tags
2. Sets `detour` field on each outbound (except the last) pointing to the next hop's tag
3. Creates a single mixed inbound pointing to the first hop
4. Writes the JSON config to a temp file

### Chain Manager (internal/tunnel/chain.go)

```go
type ChainStrategy string

const (
    StrategySingleProcess ChainStrategy = "single-process"
    StrategyMultiProcess  ChainStrategy = "multi-process"
)

// resolveChainStrategy determines whether to use single or multi-process chaining.
func (m *Manager) resolveChainStrategy(hops []config.HopConfig, profiles *profile.Manager) ChainStrategy

// StartChainSingleProcess starts a chain using one sing-box instance with detour fields.
func (m *Manager) StartChainSingleProcess(ctx context.Context, chainCfg config.ChainConfig, profiles *profile.Manager) error
```

### API Endpoints (internal/api)

| Method | Path | Description |
|--------|------|-------------|
| GET | /chains | List all chains with status |
| POST | /chains | Create a new chain |
| DELETE | /chains/{name} | Remove a chain |
| POST | /chains/{name}/start | Start a chain |
| POST | /chains/{name}/stop | Stop a chain |

### CLI Commands (cmd/bypath)

```
bypath chain add <name> <hop1> <hop2> [hop3...] [--auto-start]
bypath chain remove <name>
bypath chain list
bypath chain start <name>
bypath chain stop <name>
bypath chain status [name]
bypath bench --chain <name>
```

## Data Models

### ChainConfig (YAML)

```go
type ChainConfig struct {
    Name      string      `yaml:"name"`
    Hops      []HopConfig `yaml:"hops"`
    AutoStart bool        `yaml:"auto_start,omitempty"`
}

type HopConfig struct {
    Profile string `yaml:"profile"`
    Engine  string `yaml:"engine,omitempty"`
    Isolate bool   `yaml:"isolate,omitempty"`
}
```

### Chain Status (JSON API response)

```go
type ChainStatus struct {
    Name     string      `json:"name"`
    Status   Status      `json:"status"`
    Strategy string      `json:"strategy"`
    Error    string      `json:"error,omitempty"`
    Hops     []HopStatus `json:"hops"`
}

type HopStatus struct {
    Name     string `json:"name"`
    Protocol string `json:"protocol"`
    Engine   string `json:"engine"`
    Status   Status `json:"status"`
    Error    string `json:"error,omitempty"`
}
```

### Sing-box Detour Config (generated JSON)

```json
{
  "inbounds": [
    {"type": "mixed", "tag": "mixed-in", "listen": "0.0.0.0", "listen_port": 2801}
  ],
  "outbounds": [
    {
      "type": "vmess", "tag": "chain-mychain-hop-0",
      "server": "iran-server.com", "server_port": 443,
      "detour": "chain-mychain-hop-1"
    },
    {
      "type": "vless", "tag": "chain-mychain-hop-1",
      "server": "germany-server.com", "server_port": 443
    },
    {"type": "direct", "tag": "direct"}
  ]
}
```

## Error Handling

### Chain Startup Failures

When a hop fails during startup:
1. Log the failure: `"chain %s hop %d (%s): %v"`
2. Stop all previously started hops in reverse order
3. Set chain status to `StatusError`
4. Return error with chain name, hop index, and profile name

### Runtime Hop Failures

A background goroutine monitors hop processes:
1. If a hop process exits, mark the hop as `StatusError`
2. Mark the overall chain as `StatusError`
3. Log with chain name, hop index, and exit reason

### Validation Errors

Before starting a chain:
1. Verify all hop profiles exist
2. Verify required engines are available
3. Return descriptive errors for any missing dependencies

## Testing Strategy

### Unit Tests

- `configgen_test.go`: Test chain config generation produces valid JSON with correct detour fields
- `chain_test.go`: Test strategy selection logic (single vs multi-process)
- Config validation: Test chain with missing profiles returns correct error

### Integration Tests

- Start a chain with mock profiles and verify sing-box config is valid
- Test CLI chain add/remove modifies YAML correctly
- Test API endpoints return correct chain status

## Correctness Properties

### Property 1: Detour Chain Linkage Integrity

For any chain with N hops, the generated sing-box config must have exactly N outbound entries (plus direct), where outbound at index i has `detour` pointing to outbound at index i+1's tag, and the last outbound has no `detour` field.

**Validates: Requirements 3.1, 3.3**

**Testable:** yes — property (verify for arbitrary N-hop chains that detour linkage forms a valid linear sequence)

### Property 2: Tag Uniqueness

All outbound tags in a generated chain config must be unique. No two outbounds share the same tag value.

**Validates: Requirements 3.2**

**Testable:** yes — property (generate configs for various chain sizes and verify tag uniqueness)

### Property 3: Strategy Selection Determinism

Given the same set of hop protocols, `resolveChainStrategy` must always return the same strategy. All-sing-box-compatible protocols → single-process; any non-sing-box protocol → multi-process.

**Validates: Requirements 4.4**

**Testable:** yes — property (for any combination of protocols, strategy is deterministic)

### Property 4: Reverse-Order Cleanup on Failure

When hop i fails during startup, all hops 0..i-1 must be stopped in reverse order (i-1, i-2, ..., 0). After cleanup, no hop processes remain running.

**Validates: Requirements 6.1**

**Testable:** yes — example (simulate failure at hop 2 of a 3-hop chain, verify hops 1 and 0 are stopped in order)

### Property 5: Chain Config Round-Trip

For any valid chain configuration, generating the sing-box JSON and parsing it back must produce a structurally valid sing-box config (all required fields present, valid JSON).

**Validates: Requirements 3.6**

**Testable:** yes — property (generate → parse → validate structure for arbitrary chains)

### Property 6: Port Allocation Non-Collision

For multi-process chains, each hop's listen port must be unique and must not equal the main SOCKS port (2801).

**Validates: Requirements 4.2**

**Testable:** yes — property (for any chain length, all allocated ports are distinct and ≠ 2801)
