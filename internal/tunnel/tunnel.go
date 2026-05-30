package tunnel

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/engine"
	"github.com/liberoute/bypath/internal/paths"
	"github.com/liberoute/bypath/internal/profile"
)

// Status represents the current state of a tunnel.
type Status string

const (
	StatusStopped  Status = "stopped"
	StatusStarting Status = "starting"
	StatusRunning  Status = "running"
	StatusError    Status = "error"
)

// Tunnel represents a single tunnel connection.
type Tunnel struct {
	Name       string
	Profile    *profile.Link
	Engine     *engine.Engine
	Process    *engine.Process
	Status     Status
	ConfigFile string

	mu sync.Mutex
}

// Manager manages all active tunnels and chains.
type Manager struct {
	engineMgr  *engine.Manager
	config     *config.Config
	configGen  *ConfigGenerator
	tunnels    map[string]*Tunnel
	chains     map[string]*Chain
	mu         sync.RWMutex
}

// NewManager creates a new tunnel manager.
func NewManager(cfg *config.Config, engineMgr *engine.Manager) *Manager {
	return &Manager{
		engineMgr: engineMgr,
		config:    cfg,
		configGen: NewConfigGenerator(paths.Get().TmpDir),
		tunnels:   make(map[string]*Tunnel),
		chains:    make(map[string]*Chain),
	}
}

// StartTunnel starts a single tunnel for the given profile link.
func (m *Manager) StartTunnel(ctx context.Context, name string, link *profile.Link, opts TunnelOptions) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if already running
	if t, exists := m.tunnels[name]; exists && t.Status == StatusRunning {
		return fmt.Errorf("tunnel %s is already running", name)
	}

	// Determine which engine to use based on protocol
	engineName := opts.EngineName
	if engineName == "" {
		engineName = m.resolveEngine(link.Protocol)
	}

	eng, err := m.engineMgr.Get(engineName)
	if err != nil {
		return fmt.Errorf("getting engine for tunnel %s: %w", name, err)
	}

	// Generate config file for the engine
	configFile, err := m.generateConfig(eng, link)
	if err != nil {
		return fmt.Errorf("generating config for tunnel %s: %w", name, err)
	}

	// Build run options
	runOpts := engine.RunOptions{
		Engine:     eng,
		ConfigFile: configFile,
		LogFile:    fmt.Sprintf("./logs/%s.log", name),
	}

	// Apply firejail isolation if configured
	if opts.Isolate && m.config.Isolation.Enabled {
		runOpts.Firejail = &engine.FirejailOptions{
			Enabled:   true,
			Namespace: name,
			NetIface:  opts.NetInterface,
			IP:        opts.IP,
			Gateway:   opts.Gateway,
			DNS:       m.config.Gateway.DNSUpstream,
		}
	}

	// Start the process
	proc, err := engine.StartProcess(ctx, runOpts)
	if err != nil {
		return fmt.Errorf("starting tunnel %s: %w", name, err)
	}

	tunnel := &Tunnel{
		Name:       name,
		Profile:    link,
		Engine:     eng,
		Process:    proc,
		Status:     StatusRunning,
		ConfigFile: configFile,
	}

	m.tunnels[name] = tunnel
	log.Printf("✅ Tunnel %s started (engine: %s, protocol: %s)", name, eng.Name, link.Protocol)

	return nil
}

// StopTunnel stops a running tunnel.
func (m *Manager) StopTunnel(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	t, exists := m.tunnels[name]
	if !exists {
		return fmt.Errorf("tunnel %s not found", name)
	}

	if t.Process != nil {
		if err := t.Process.Stop(); err != nil {
			return fmt.Errorf("stopping tunnel %s: %w", name, err)
		}
	}

	t.Status = StatusStopped
	log.Printf("🛑 Tunnel %s stopped", name)
	return nil
}

// GetStatus returns the status of all tunnels.
func (m *Manager) GetStatus() map[string]Status {
	m.mu.RLock()
	defer m.mu.RUnlock()

	status := make(map[string]Status)
	for name, t := range m.tunnels {
		// Update status from process
		if t.Process != nil && !t.Process.IsRunning() {
			t.Status = StatusStopped
		}
		status[name] = t.Status
	}
	return status
}

// resolveEngine determines which engine to use for a given protocol.
func (m *Manager) resolveEngine(protocol string) string {
	switch protocol {
	case "vmess", "vless", "trojan", "shadowsocks", "hysteria2":
		return "sing-box"
	case "wireguard":
		return "wireguard-go"
	case "openvpn":
		return "openvpn"
	default:
		return "sing-box" // default fallback
	}
}

// generateConfig creates a temporary config file for the engine.
func (m *Manager) generateConfig(eng *engine.Engine, link *profile.Link) (string, error) {
	return m.configGen.Generate(eng, link)
}

// TunnelOptions configures tunnel startup behavior.
type TunnelOptions struct {
	EngineName   string
	Isolate      bool
	NetInterface string
	IP           string
	Gateway      string
}
