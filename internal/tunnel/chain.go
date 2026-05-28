package tunnel

import (
	"context"
	"fmt"
	"log"

	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/profile"
)

// Chain represents a sequence of tunnels where traffic flows through each hop.
// Example: Client → Hop1 (vmess) → Hop2 (wireguard) → Internet
type Chain struct {
	Name    string
	Config  config.ChainConfig
	Hops    []*Tunnel
	Status  Status
}

// StartChain starts all hops in a chain sequentially.
// Each hop's outbound connects to the next hop's inbound.
func (m *Manager) StartChain(ctx context.Context, chainCfg config.ChainConfig, profiles *profile.Manager) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	chain := &Chain{
		Name:   chainCfg.Name,
		Config: chainCfg,
		Hops:   make([]*Tunnel, 0, len(chainCfg.Hops)),
		Status: StatusStarting,
	}

	log.Printf("⛓️  Starting chain: %s (%d hops)", chain.Name, len(chainCfg.Hops))

	var previousListenAddr string

	for i, hopCfg := range chainCfg.Hops {
		// Get the profile link for this hop
		link, err := profiles.GetLink(hopCfg.Profile)
		if err != nil {
			chain.Status = StatusError
			// Stop any already-started hops
			m.stopChainHops(chain)
			return fmt.Errorf("chain %s hop %d: profile %s not found: %w", chain.Name, i, hopCfg.Profile, err)
		}

		hopName := fmt.Sprintf("%s-hop-%d", chain.Name, i)

		// For chained hops after the first, set the outbound to go through
		// the previous hop's SOCKS proxy
		if i > 0 && previousListenAddr != "" {
			link.ChainProxy = previousListenAddr
		}

		// Each hop listens on a unique port for the next hop to connect through
		listenPort := 10800 + i
		link.ListenPort = listenPort
		previousListenAddr = fmt.Sprintf("127.0.0.1:%d", listenPort)

		opts := TunnelOptions{
			EngineName: hopCfg.Engine,
			Isolate:    hopCfg.Isolate,
		}

		// Start this hop (unlock temporarily since StartTunnel also locks)
		m.mu.Unlock()
		if err := m.StartTunnel(ctx, hopName, link, opts); err != nil {
			m.mu.Lock()
			chain.Status = StatusError
			m.stopChainHops(chain)
			return fmt.Errorf("chain %s hop %d failed to start: %w", chain.Name, i, err)
		}
		m.mu.Lock()

		// Add to chain
		if t, exists := m.tunnels[hopName]; exists {
			chain.Hops = append(chain.Hops, t)
		}
	}

	chain.Status = StatusRunning
	m.chains[chain.Name] = chain

	log.Printf("✅ Chain %s started successfully (%d hops)", chain.Name, len(chain.Hops))
	return nil
}

// StopChain stops all hops in a chain.
func (m *Manager) StopChain(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	chain, exists := m.chains[name]
	if !exists {
		return fmt.Errorf("chain %s not found", name)
	}

	m.stopChainHops(chain)
	chain.Status = StatusStopped
	log.Printf("🛑 Chain %s stopped", name)
	return nil
}

// stopChainHops stops all hops in reverse order.
func (m *Manager) stopChainHops(chain *Chain) {
	// Stop in reverse order (last hop first)
	for i := len(chain.Hops) - 1; i >= 0; i-- {
		hop := chain.Hops[i]
		if hop.Process != nil && hop.Process.IsRunning() {
			hop.Process.Stop()
			hop.Status = StatusStopped
		}
	}
}

// GetChainStatus returns the status of all chains.
func (m *Manager) GetChainStatus() map[string]*ChainStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]*ChainStatus)
	for name, chain := range m.chains {
		cs := &ChainStatus{
			Name:   name,
			Status: chain.Status,
			Hops:   make([]HopStatus, 0, len(chain.Hops)),
		}
		for _, hop := range chain.Hops {
			hs := HopStatus{
				Name:     hop.Name,
				Protocol: hop.Profile.Protocol,
				Engine:   hop.Engine.Name,
				Status:   hop.Status,
			}
			if hop.Process != nil && !hop.Process.IsRunning() {
				hs.Status = StatusStopped
			}
			cs.Hops = append(cs.Hops, hs)
		}
		result[name] = cs
	}
	return result
}

// ChainStatus represents the status of a chain and its hops.
type ChainStatus struct {
	Name   string      `json:"name"`
	Status Status      `json:"status"`
	Hops   []HopStatus `json:"hops"`
}

// HopStatus represents the status of a single hop in a chain.
type HopStatus struct {
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Engine   string `json:"engine"`
	Status   Status `json:"status"`
}
