# Implementation Plan: Multi-Hop Proxy Chaining

## Overview

This plan implements multi-hop proxy chaining for Bypath, enabling traffic to flow through multiple proxy servers sequentially. The implementation covers config changes, single-process detour generation, CLI commands, API endpoints, TUI display, failure handling, and benchmarking.

## Tasks

- [ ] 1. Extend ChainConfig with AutoStart field in `internal/config/config.go` — add `AutoStart bool` with `yaml:"auto_start,omitempty"` tag
  - [ ] 1.1 Add `AutoStart bool` field to `ChainConfig` struct
  - [ ] 1.2 Update `configs/default.yaml` with multi-hop chain example and `auto_start` field
  - [ ] 1.3 Run `go build ./...` to verify compilation

- [ ] 2. Implement single-process chain config generation in `internal/tunnel/configgen.go`
  - [ ] 2.1 Add `GenerateChainConfig(chainName string, links []*profile.Link) (string, error)` method
  - [ ] 2.2 Implement outbound generation loop with unique tags (`chain-<name>-hop-<i>`) and `detour` field linking to next hop
  - [ ] 2.3 Generate single mixed inbound routing to first hop's tag
  - [ ] 2.4 Include direct outbound and route/DNS sections
  - [ ] 2.5 Write unit tests: 2-hop detour linkage, 3-hop chain, mixed protocols, single hop no-detour
  - [ ] 2.6 Run `go test ./internal/tunnel/...` to verify

- [ ] 3. Implement chain strategy selection in `internal/tunnel/chain.go`
  - [ ] 3.1 Add `ChainStrategy` type and constants (`StrategySingleProcess`, `StrategyMultiProcess`)
  - [ ] 3.2 Add `resolveChainStrategy` method — returns single-process if all hops are sing-box compatible
  - [ ] 3.3 Add `StartChainSingleProcess` method using `GenerateChainConfig` and one sing-box process
  - [ ] 3.4 Modify `StartChain` to dispatch based on resolved strategy
  - [ ] 3.5 Add `Strategy` field to `Chain` struct
  - [ ] 3.6 Run `go build ./...` to verify

- [ ] 4. Implement CLI chain commands in `cmd/bypath/main.go`
  - [ ] 4.1 Add `"chain"` case to main switch dispatching to `cmdChain(args)`
  - [ ] 4.2 Implement `cmdChainAdd`: parse name + hop profiles, load config, append chain, write YAML
  - [ ] 4.3 Implement `cmdChainRemove`: load config, remove chain by name, write YAML
  - [ ] 4.4 Implement `cmdChainList`: load config, display chains table (name, hops, auto-start)
  - [ ] 4.5 Implement `cmdChainStart` and `cmdChainStop`: call API endpoints
  - [ ] 4.6 Implement `cmdChainStatus`: call GET /chains API, display per-hop status
  - [ ] 4.7 Update `printUsage()` with chain commands
  - [ ] 4.8 Run `go build ./cmd/bypath` to verify

- [ ] 5. Implement chain API endpoints in `internal/api/`
  - [ ] 5.1 Register routes: POST /chains, DELETE /chains/{name}, POST /chains/{name}/start, POST /chains/{name}/stop
  - [ ] 5.2 Implement `handleCreateChain`: parse body, validate, add to config
  - [ ] 5.3 Implement `handleDeleteChain`: remove chain, stop if running
  - [ ] 5.4 Implement `handleStartChain` and `handleStopChain`: invoke Chain_Manager
  - [ ] 5.5 Enhance `handleListChains` with error details and strategy field
  - [ ] 5.6 Run `go build ./...` to verify

- [ ] 6. Implement chain failure handling and monitoring in `internal/tunnel/chain.go`
  - [ ] 6.1 Add `monitorChainHops` goroutine to check hop process liveness
  - [ ] 6.2 Mark hop and chain as `StatusError` when a process exits unexpectedly
  - [ ] 6.3 Log failures with chain name, hop index, profile name, and error
  - [ ] 6.4 Ensure startup failure stops hops in reverse order with descriptive error
  - [ ] 6.5 Add `Error` field to `HopStatus` and `ChainStatus` structs
  - [ ] 6.6 Run `go build ./...` to verify

- [ ] 7. Implement chain benchmarking in `cmd/bypath/main.go`
  - [ ] 7.1 Add `--chain` flag parsing to `cmdBench`
  - [ ] 7.2 Implement `benchChain`: load config, resolve profiles, TCP ping each hop
  - [ ] 7.3 Generate temporary chain config on port 19800
  - [ ] 7.4 Start sing-box, measure latency via curl through chain SOCKS proxy
  - [ ] 7.5 Clean up processes and temp files, handle failures gracefully
  - [ ] 7.6 Display per-hop ping and total chain latency
  - [ ] 7.7 Run `go build ./cmd/bypath` to verify

- [ ] 8. Add chain display to TUI in `internal/tui/tui.go`
  - [ ] 8.1 Add chains section to Home tab model fetching chain status
  - [ ] 8.2 Render chain entries: name, strategy, hop count, status with emoji
  - [ ] 8.3 Show per-hop details on selection: index, protocol, server, engine, status
  - [ ] 8.4 Add color coding (green=running, red=error, gray=stopped)
  - [ ] 8.5 Run `go build ./...` to verify

- [ ] 9. Update documentation
  - [ ] 9.1 Add "Proxy Chains" section to `docs/configuration.md` with examples
  - [ ] 9.2 Add chain API endpoints to `docs/api.md`
  - [ ] 9.3 Add chain feature mention to `README.md`
  - [ ] 9.4 Add chain CLI commands to documentation

- [ ] 10. Integration testing
  - [ ] 10.1 Test YAML parsing of multi-hop chain with `auto_start` in `config_test.go`
  - [ ] 10.2 Test chain config generation produces valid detour JSON in `configgen_test.go`
  - [ ] 10.3 Test strategy selection in new `chain_test.go`
  - [ ] 10.4 Test missing profile returns descriptive error
  - [ ] 10.5 Run `go test -v -race ./...` to verify all tests pass

## Task Dependency Graph

```json
{
  "waves": [
    {"tasks": ["1"]},
    {"tasks": ["2"]},
    {"tasks": ["3"]},
    {"tasks": ["4", "5", "6", "7"]},
    {"tasks": ["8"]},
    {"tasks": ["9", "10"]}
  ]
}
```

## Notes

- Task 1 is a prerequisite for all other tasks since it establishes the config structure.
- Tasks 2 and 3 form the core engine logic and should be completed before interface tasks (4, 5, 7, 8).
- Task 6 (failure handling) enhances task 3 and can be done in parallel with interface tasks.
- Task 9 (docs) and 10 (tests) are final tasks that depend on implementation being complete.
- The existing `StartChain` multi-process logic in `chain.go` is preserved as the fallback strategy.
