package tunnel

import (
	"context"
	"fmt"
	"log"
	"net"
	"os/exec"
	"sync"
	"time"

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
	engineMgr *engine.Manager
	config    *config.Config
	configGen *ConfigGenerator
	tunnels   map[string]*Tunnel
	chains    map[string]*Chain
	mu        sync.RWMutex
}

// NewManager creates a new tunnel manager.
func NewManager(cfg *config.Config, engineMgr *engine.Manager) *Manager {
	cg := NewConfigGenerator(paths.Get().TmpDir)
	cg.WhitelistCountries = cfg.Whitelist.Countries
	cg.GeositeCountries = cfg.Whitelist.GeositeCountries
	cg.BypassDomains = cfg.Whitelist.BypassDomains
	cg.SOCKSPort = cfg.Server.SOCKSPort
	cg.SOCKSListen = cfg.Server.SOCKSListenAddress()
	cg.SOCKSUsername = cfg.Server.SOCKSUsername
	cg.SOCKSPassword = cfg.Server.SOCKSPassword
	cg.SSHHostKey = cfg.Server.SSHHostKey

	return &Manager{
		engineMgr: engineMgr,
		config:    cfg,
		configGen: cg,
		tunnels:   make(map[string]*Tunnel),
		chains:    make(map[string]*Chain),
	}
}

// StartTunnel starts a single tunnel for the given profile link.
func (m *Manager) StartTunnel(ctx context.Context, name string, link *profile.Link, opts TunnelOptions) error {
	// Dispatch to SSH-specific handler if protocol is "ssh"
	if link.Protocol == "ssh" {
		return m.startSSHTunnel(ctx, name, link, opts)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if already running
	if t, exists := m.tunnels[name]; exists && t.Status == StatusRunning {
		return fmt.Errorf("tunnel %s is already running", name)
	}

	// Determine which engine to use based on protocol and profile capabilities.
	engineName := opts.EngineName
	if engineName == "" {
		engineName = m.resolveEngineForLink(link)
	}

	eng, err := m.engineMgr.Get(engineName)
	if err != nil {
		return fmt.Errorf("getting engine for tunnel %s: %w", name, err)
	}

	// Generate config file for the engine
	configFile, err := m.generateConfig(eng, link)
	if err != nil {
		m.configGen.DiscardGeneration()
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
		m.configGen.DiscardConfig(configFile)
		return fmt.Errorf("starting tunnel %s: %w", name, err)
	}

	// An open SOCKS port is not proof of a working tunnel. For OpenVPN require
	// the handshake to complete and one HTTPS round trip to succeed.
	if link.Protocol == "openvpn" {
		listenPort := link.ListenPort
		if listenPort == 0 {
			listenPort = m.config.Server.SOCKSPort
		}
		m.mu.Unlock()
		portErr := waitForPort(listenPort, 20*time.Second)
		healthy := portErr == nil && profile.TestHTTPS(ctx, listenPort)
		m.mu.Lock()
		if !healthy {
			proc.Stop()
			m.configGen.DiscardConfig(configFile)
			if portErr != nil {
				return fmt.Errorf("OpenVPN tunnel %s: port %d not ready: %w", name, listenPort, portErr)
			}
			return fmt.Errorf("OpenVPN tunnel %s did not pass the HTTPS health check", name)
		}
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

// startSSHTunnel starts an SSH tunnel using ssh -D (dynamic SOCKS5 proxy).
func (m *Manager) startSSHTunnel(ctx context.Context, name string, link *profile.Link, opts TunnelOptions) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if already running
	if t, exists := m.tunnels[name]; exists && t.Status == StatusRunning {
		return fmt.Errorf("tunnel %s is already running", name)
	}

	// Get the SSH engine
	eng, err := m.engineMgr.Get("ssh")
	if err != nil {
		return fmt.Errorf("ssh binary not found: %w (install OpenSSH client)", err)
	}

	// Determine listen port
	listenPort := link.ListenPort
	if listenPort == 0 {
		listenPort = m.config.Server.SOCKSPort
	}

	knownHosts := DefaultSSHKnownHosts()
	if err := EnsureSSHKnownHosts(knownHosts); err != nil {
		return err
	}
	sshPassPath := ""
	if link.SSHKeyPath == "" && link.SSHPassword != "" {
		if !m.engineMgr.SSHPassAvailable {
			return fmt.Errorf("sshpass not found: password auth requires sshpass (install it or use key-based auth)")
		}
		resolved, err := exec.LookPath("sshpass")
		if err != nil {
			return fmt.Errorf("sshpass not found: %w", err)
		}
		sshPassPath = resolved
	}

	cmd, err := BuildSSHCommand(link, SSHOptions{
		SSHPath:     eng.Path,
		SSHPassPath: sshPassPath,
		ListenAddr:  m.config.Server.SOCKSListenAddress(),
		ListenPort:  listenPort,
		KnownHosts:  knownHosts,
		HostKey:     m.config.Server.SSHHostKey,
	})
	if err != nil {
		return err
	}

	// Build run options — use Args (not ConfigFile) since SSH doesn't use a config file
	runOpts := engine.RunOptions{
		Engine: &engine.Engine{Name: "ssh", Path: cmd.Binary},
		Args:   cmd.Args,
		Env:    cmd.Env,
	}

	// Start the process
	proc, err := engine.StartProcess(ctx, runOpts)
	if err != nil {
		return fmt.Errorf("starting SSH tunnel %s: %w", name, err)
	}

	// Wait for the SOCKS port to be ready
	m.mu.Unlock()
	portErr := waitForPort(listenPort, 10*time.Second)
	m.mu.Lock()

	if portErr != nil {
		proc.Stop()
		return fmt.Errorf("SSH tunnel %s: port %d not ready: %w", name, listenPort, portErr)
	}

	// Store tunnel in manager's tunnels map
	tunnel := &Tunnel{
		Name:    name,
		Profile: link,
		Engine:  eng,
		Process: proc,
		Status:  StatusRunning,
	}

	m.tunnels[name] = tunnel
	log.Printf("✅ Tunnel %s started (engine: ssh, protocol: ssh, port: %d)", name, listenPort)

	return nil
}

// StopAll stops every tunnel and chain this manager owns and waits briefly for
// each engine to exit. Gateway shutdown calls it so no engine can survive the
// daemon and keep a listener or a generated config alive.
func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for name, t := range m.tunnels {
		if t.Process != nil && t.Process.IsRunning() {
			t.Process.Stop()
			t.Process.WaitStopped(2 * time.Second)
			log.Printf("🛑 Tunnel %s stopped", name)
		}
		t.Status = StatusStopped
	}
	for name, c := range m.chains {
		for i := len(c.Hops) - 1; i >= 0; i-- {
			hop := c.Hops[i]
			if hop.Process != nil && hop.Process.IsRunning() {
				hop.Process.Stop()
				hop.Process.WaitStopped(2 * time.Second)
			}
			hop.Status = StatusStopped
		}
		c.Status = StatusStopped
		log.Printf("🛑 Chain %s stopped", name)
	}
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

	// Remove the whole generation directory: config plus any material
	// extracted from .ovpn profiles. It is per-generation, so stopping one
	// tunnel can never delete another tunnel's keys.
	if t.ConfigFile != "" {
		m.configGen.DiscardConfig(t.ConfigFile)
		t.ConfigFile = ""
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

// resolveEngineForLink picks the only engine that can faithfully run the link.
// VLESS Encryption is xray-only; sing-box would silently drop it. OpenVPN
// profiles run as sing-box 1.14+ endpoints, never through the native binary.
func (m *Manager) resolveEngineForLink(link *profile.Link) string {
	if link.EncryptedVLESS() {
		return "xray"
	}
	switch link.Protocol {
	case "vmess", "vless", "trojan", "shadowsocks", "hysteria2":
		return "sing-box"
	case "wireguard":
		return "wireguard-go"
	case "openvpn":
		return "sing-box"
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

// waitForPort waits for a TCP port to become available.
func waitForPort(port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("port %d not ready after %v", port, timeout)
}
