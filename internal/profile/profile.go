package profile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Link represents a single proxy/VPN link configuration.
type Link struct {
	Remark     string `json:"remark"`
	Protocol   string `json:"protocol"` // vmess, vless, trojan, shadowsocks, wireguard, openvpn
	RawURI     string `json:"raw_uri"`  // original URI (vmess://..., vless://..., etc.)
	Group      string `json:"group"`

	// Parsed fields (populated from RawURI)
	Address    string `json:"address"`
	Port       int    `json:"port"`
	UUID       string `json:"uuid,omitempty"`
	AlterId    int    `json:"alter_id,omitempty"`
	Security   string `json:"security,omitempty"`
	Network    string `json:"network,omitempty"` // tcp, ws, grpc, etc.
	TLS        bool   `json:"tls,omitempty"`
	Insecure   bool   `json:"insecure,omitempty"` // skip TLS certificate verification
	SNI        string `json:"sni,omitempty"`
	Path       string `json:"path,omitempty"`
	Host       string `json:"host,omitempty"`
	Flow       string `json:"flow,omitempty"`

	// Reality/UTLS fields (populated from VLESS Reality URIs)
	RealityPublicKey string `json:"reality_pbk,omitempty"`  // pbk param
	RealityShortID   string `json:"reality_sid,omitempty"`  // sid param
	Fingerprint      string `json:"fingerprint,omitempty"`  // fp param (UTLS)

	// WireGuard fields
	PublicKey  string `json:"public_key,omitempty"`  // wireguard
	PrivateKey string `json:"private_key,omitempty"` // wireguard
	Endpoint   string `json:"endpoint,omitempty"`    // wireguard

	// SSH-specific fields
	SSHUser     string `json:"ssh_user,omitempty"`     // SSH username (default: "root")
	SSHKeyPath  string `json:"ssh_key_path,omitempty"` // Path to SSH private key file
	SSHPassword string `json:"ssh_password,omitempty"` // Password auth (if no key)

	// HTTPSCapable indicates HTTPS relay capability:
	//   0 = untested (default zero value)
	//   1 = passed HTTPS test
	//  -1 = failed HTTPS test
	HTTPSCapable int `json:"https_capable,omitempty"`

	// CDNDetected indicates the static heuristic flagged this as a CDN link.
	// This is computed, not persisted (use json:"-" or omitempty with recompute on load).
	CDNDetected bool `json:"-"`

	// Chain support
	ChainProxy string `json:"-"` // upstream SOCKS proxy for chaining
	ListenPort int    `json:"-"` // local listen port for this hop
}

// Group represents a collection of links.
type Group struct {
	Name         string   `json:"name"`
	Type         string   `json:"type"` // "basic" or "subscription"
	Links        []*Link  `json:"links"`
	Subscriptions []string `json:"subscriptions,omitempty"`
}

// Manager handles profile/group/link operations.
type Manager struct {
	directory   string
	groups      map[string]*Group
	activeGroup string
	activeLink  *Link
	mu          sync.RWMutex
}

// NewManager creates a new profile manager.
func NewManager(directory string, activeGroup string) (*Manager, error) {
	m := &Manager{
		directory:   directory,
		groups:      make(map[string]*Group),
		activeGroup: activeGroup,
	}

	if err := os.MkdirAll(directory, 0755); err != nil {
		return nil, fmt.Errorf("creating profiles directory: %w", err)
	}

	if err := m.loadAll(); err != nil {
		return nil, err
	}

	return m, nil
}

// GetLink returns a link by its remark name (searches active group first, then all).
func (m *Manager) GetLink(remark string) (*Link, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Search active group first
	if g, ok := m.groups[m.activeGroup]; ok {
		for _, link := range g.Links {
			if link.Remark == remark {
				return link, nil
			}
		}
	}

	// Search all groups
	for _, g := range m.groups {
		for _, link := range g.Links {
			if link.Remark == remark {
				return link, nil
			}
		}
	}

	return nil, fmt.Errorf("link '%s' not found", remark)
}

// AddLink adds a link to a group.
func (m *Manager) AddLink(groupName string, link *Link) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	g, ok := m.groups[groupName]
	if !ok {
		// Create group if it doesn't exist
		g = &Group{Name: groupName, Type: "basic", Links: make([]*Link, 0)}
		m.groups[groupName] = g
	}

	link.Group = groupName
	g.Links = append(g.Links, link)

	return m.saveGroup(g)
}

// RemoveLink removes a link from a group by remark.
func (m *Manager) RemoveLink(groupName, remark string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	g, ok := m.groups[groupName]
	if !ok {
		return fmt.Errorf("group '%s' not found", groupName)
	}

	for i, link := range g.Links {
		if link.Remark == remark {
			g.Links = append(g.Links[:i], g.Links[i+1:]...)
			return m.saveGroup(g)
		}
	}

	return fmt.Errorf("link '%s' not found in group '%s'", remark, groupName)
}

// ListGroups returns all group names.
func (m *Manager) ListGroups() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.groups))
	for name := range m.groups {
		names = append(names, name)
	}
	return names
}

// GetGroup returns a group by name.
func (m *Manager) GetGroup(name string) (*Group, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	g, ok := m.groups[name]
	if !ok {
		return nil, fmt.Errorf("group '%s' not found", name)
	}
	return g, nil
}

// CreateGroup creates a new empty group.
func (m *Manager) CreateGroup(name, groupType string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.groups[name]; exists {
		return fmt.Errorf("group '%s' already exists", name)
	}

	g := &Group{Name: name, Type: groupType, Links: make([]*Link, 0)}
	m.groups[name] = g
	return m.saveGroup(g)
}

// DeleteGroup removes a group and its file.
func (m *Manager) DeleteGroup(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.groups[name]; !exists {
		return fmt.Errorf("group '%s' not found", name)
	}

	delete(m.groups, name)
	return os.Remove(filepath.Join(m.directory, name+".json"))
}

// SetActiveLink sets the currently active link and persists it.
func (m *Manager) SetActiveLink(link *Link) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.activeLink = link

	// Persist to file
	data := fmt.Sprintf("%s\n%s", link.Group, link.Remark)
	os.WriteFile(filepath.Join(m.directory, ".active"), []byte(data), 0644)
}

// GetActiveLink returns the currently active link.
func (m *Manager) GetActiveLink() *Link {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.activeLink != nil {
		return m.activeLink
	}

	// Try to load from persisted file
	data, err := os.ReadFile(filepath.Join(m.directory, ".active"))
	if err != nil {
		return nil
	}

	lines := strings.Split(string(data), "\n")
	if len(lines) < 2 {
		return nil
	}
	group, remark := strings.TrimSpace(lines[0]), strings.TrimSpace(lines[1])

	g, ok := m.groups[group]
	if !ok {
		return nil
	}
	for _, link := range g.Links {
		if strings.TrimSpace(link.Remark) == remark {
			return link
		}
	}
	return nil
}

// loadAll loads all group files from the profiles directory.
func (m *Manager) loadAll() error {
	entries, err := os.ReadDir(m.directory)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		data, err := os.ReadFile(filepath.Join(m.directory, entry.Name()))
		if err != nil {
			continue
		}

		var g Group
		if err := json.Unmarshal(data, &g); err != nil {
			continue
		}

		// Mark CDN detection on each link at load time
		for _, link := range g.Links {
			MarkCDNDetected(link)
		}

		m.groups[g.Name] = &g
	}

	return nil
}

// SaveGroup persists a group to disk by name.
func (m *Manager) SaveGroup(name string) error {
	m.mu.RLock()
	g, ok := m.groups[name]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("group '%s' not found", name)
	}
	return m.saveGroup(g)
}

// saveGroup persists a group to disk.
func (m *Manager) saveGroup(g *Group) error {
	data, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(m.directory, g.Name+".json"), data, 0644)
}
