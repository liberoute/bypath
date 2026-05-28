package gateway

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// DHCPServer is a minimal DHCP server that assigns IPs to LAN clients
// and sets this machine as their gateway and DNS server.
// This is optional — clients can also be configured manually.
type DHCPServer struct {
	enabled    bool
	listenAddr string
	gateway    net.IP    // this machine's IP (gateway for clients)
	subnet     *net.IPNet
	rangeStart net.IP
	rangeEnd   net.IP
	dns        []net.IP
	leaseTime  time.Duration
	leases     map[string]*Lease // MAC -> Lease
	mu         sync.Mutex
}

// Lease represents a DHCP lease.
type Lease struct {
	MAC       net.HardwareAddr
	IP        net.IP
	Hostname  string
	ExpiresAt time.Time
}

// DHCPConfig configures the DHCP server.
type DHCPConfig struct {
	Enabled    bool
	Interface  string
	RangeStart string // e.g., "192.168.1.100"
	RangeEnd   string // e.g., "192.168.1.200"
	Subnet     string // e.g., "255.255.255.0"
	Gateway    string // this machine's IP
	DNS        []string
	LeaseTime  time.Duration
}

// NewDHCPServer creates a new DHCP server.
func NewDHCPServer(cfg DHCPConfig) (*DHCPServer, error) {
	if !cfg.Enabled {
		return &DHCPServer{enabled: false}, nil
	}

	gateway := net.ParseIP(cfg.Gateway)
	if gateway == nil {
		return nil, fmt.Errorf("invalid gateway IP: %s", cfg.Gateway)
	}

	rangeStart := net.ParseIP(cfg.RangeStart)
	rangeEnd := net.ParseIP(cfg.RangeEnd)
	if rangeStart == nil || rangeEnd == nil {
		return nil, fmt.Errorf("invalid DHCP range: %s - %s", cfg.RangeStart, cfg.RangeEnd)
	}

	var dnsServers []net.IP
	for _, d := range cfg.DNS {
		ip := net.ParseIP(d)
		if ip != nil {
			dnsServers = append(dnsServers, ip)
		}
	}
	// Default: use gateway as DNS (since we run a DNS server)
	if len(dnsServers) == 0 {
		dnsServers = []net.IP{gateway}
	}

	leaseTime := cfg.LeaseTime
	if leaseTime == 0 {
		leaseTime = 12 * time.Hour
	}

	return &DHCPServer{
		enabled:    true,
		listenAddr: "0.0.0.0:67",
		gateway:    gateway,
		rangeStart: rangeStart,
		rangeEnd:   rangeEnd,
		dns:        dnsServers,
		leaseTime:  leaseTime,
		leases:     make(map[string]*Lease),
	}, nil
}

// Start begins the DHCP server.
func (d *DHCPServer) Start() error {
	if !d.enabled {
		return nil
	}

	log.Printf("  📡 DHCP server starting on %s", d.listenAddr)
	log.Printf("     Range: %s - %s", d.rangeStart, d.rangeEnd)
	log.Printf("     Gateway: %s", d.gateway)
	log.Printf("     DNS: %v", d.dns)

	// TODO: Implement full DHCP protocol (DISCOVER/OFFER/REQUEST/ACK)
	// For now, this is a placeholder. A full implementation would use
	// raw UDP sockets on port 67/68 with broadcast support.
	// Consider using github.com/insomniacslk/dhcp for a proper implementation.

	log.Println("  ⚠️  DHCP server: placeholder (use static config or external DHCP)")
	return nil
}

// Stop shuts down the DHCP server.
func (d *DHCPServer) Stop() {
	if !d.enabled {
		return
	}
	log.Println("  🛑 DHCP server stopped")
}

// GetLeases returns all active leases.
func (d *DHCPServer) GetLeases() []*Lease {
	d.mu.Lock()
	defer d.mu.Unlock()

	var active []*Lease
	now := time.Now()
	for _, lease := range d.leases {
		if lease.ExpiresAt.After(now) {
			active = append(active, lease)
		}
	}
	return active
}
