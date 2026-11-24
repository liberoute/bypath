package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// ErrInvalidGroupName marks a group name that cannot be used as a file name.
var ErrInvalidGroupName = errors.New("invalid group name")

// ValidGroupName accepts names that map to one plain file inside the profile
// directory: no separators, no dot segments, no leading dot (which would
// collide with state files such as .active).
func ValidGroupName(name string) bool {
	if name == "" || len(name) > 64 || name == "." || name == ".." || strings.HasPrefix(name, ".") {
		return false
	}
	if strings.ContainsAny(name, `/\:`+"\x00") {
		return false
	}
	return filepath.Base(name) == name
}

// Link represents a single proxy/VPN link configuration.
type Link struct {
	Remark   string `json:"remark"`
	Protocol string `json:"protocol"` // vmess, vless, trojan, shadowsocks, wireguard, openvpn
	RawURI   string `json:"raw_uri"`  // original URI (vmess://..., vless://..., etc.)
	Group    string `json:"group"`

	// Parsed fields (populated from RawURI)
	Address           string   `json:"address"`
	Port              int      `json:"port"`
	UUID              string   `json:"uuid,omitempty"`
	AlterId           int      `json:"alter_id,omitempty"`
	Security          string   `json:"security,omitempty"`
	Network           string   `json:"network,omitempty"` // tcp, ws, grpc, etc.
	TLS               bool     `json:"tls,omitempty"`
	Insecure          bool     `json:"insecure,omitempty"` // skip TLS certificate verification
	SNI               string   `json:"sni,omitempty"`
	Path              string   `json:"path,omitempty"`
	Host              string   `json:"host,omitempty"`
	Flow              string   `json:"flow,omitempty"`
	ALPN              []string `json:"alpn,omitempty"`
	GRPCServiceName   string   `json:"grpc_service_name,omitempty"`
	GRPCMultiMode     bool     `json:"grpc_multi_mode,omitempty"`
	RealitySpiderX    string   `json:"reality_spider_x,omitempty"`
	WSMaxEarlyData    int      `json:"ws_max_early_data,omitempty"`
	WSEarlyDataHeader string   `json:"ws_early_data_header,omitempty"`
	// UnsupportedParams contains names only, never credential-bearing values.
	// Engines must reject these rather than silently change a stored profile.
	UnsupportedParams []string `json:"unsupported_params,omitempty"`

	// Reality/UTLS fields (populated from VLESS Reality URIs)
	RealityPublicKey string `json:"reality_pbk,omitempty"` // pbk param
	RealityShortID   string `json:"reality_sid,omitempty"` // sid param
	Fingerprint      string `json:"fingerprint,omitempty"` // fp param (UTLS)

	// VLESS Encryption (Xray 26.x). Secret-bearing: never log or echo this value.
	Encryption string `json:"encryption,omitempty"`
	// SupportX25519MLKEM768 is a REALITY compatibility hint from the URI. It is
	// informational only and must never be injected as an Xray JSON property.
	SupportX25519MLKEM768 bool `json:"support_x25519mlkem768,omitempty"`

	// OpenVPN profile reference. Secrets stay in the 0600 .ovpn file, never in JSON.
	OVPNPath             string `json:"ovpn_path,omitempty"`
	OVPNAuthUserPassFile string `json:"ovpn_auth_user_pass_file,omitempty"`

	// XHTTP / SplitHTTP transport fields
	TransportMode string `json:"transport_mode,omitempty"` // mode=auto|packet-up|stream-up|stream-one
	ExtraJSON     string `json:"extra_json,omitempty"`     // raw extra= JSON from URI

	// WireGuard fields
	PublicKey  string `json:"public_key,omitempty"`  // wireguard
	PrivateKey string `json:"private_key,omitempty"` // wireguard
	Endpoint   string `json:"endpoint,omitempty"`    // wireguard

	// SSH-specific fields
	SSHUser     string `json:"ssh_user,omitempty"`     // SSH username (default: "root")
	SSHKeyPath  string `json:"ssh_key_path,omitempty"` // Path to SSH private key file
	SSHPassword string `json:"ssh_password,omitempty"` // Password auth (if no key)

	// HTTPS capable probe result:
	//   0 = untested (default zero value)
	//   1 = passed HTTPS test
	//  -1 = failed HTTPS test
	HTTPSCapable int `json:"https_capable,omitempty"`

	// RequiresAuth marks an OpenVPN profile that asks for a username/password.
	// It is recorded at import so lists can prompt without re-parsing the file.
	RequiresAuth bool `json:"requires_auth,omitempty"`

	// SourceID identifies the subscription that produced this link
	// (sha256 of the normalized URL, truncated). The URL itself is not copied
	// into every link, so a subscription token is stored exactly once.
	SourceID string `json:"source_id,omitempty"`

	// CDNDetected indicates the static heuristic flagged this as a CDN link.
	// This is computed, not persisted (use json:"-" or omitempty with recompute on load).
	CDNDetected bool `json:"-"`

	// Chain support
	ChainProxy string `json:"-"` // upstream SOCKS proxy for chaining
	ListenPort int    `json:"-"` // local listen port for this hop
}

// Group represents a collection of links.
type Group struct {
	Name          string   `json:"name"`
	Type          string   `json:"type"` // "basic" or "subscription"
	Links         []*Link  `json:"links"`
	Subscriptions []string `json:"subscriptions,omitempty"`
	// SubscriptionMeta records the last refresh outcome per URL. It is parallel
	// to Subscriptions and never contains link credentials.
	SubscriptionMeta []SubscriptionInfo `json:"subscription_meta,omitempty"`
}

// SubscriptionInfo is the persisted refresh state of one subscription URL.
type SubscriptionInfo struct {
	URL         string `json:"url"`
	LastRefresh string `json:"last_refresh,omitempty"`
	LastError   string `json:"last_error,omitempty"`
	LinkCount   int    `json:"link_count,omitempty"`
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

	if !ValidGroupName(name) {
		return fmt.Errorf("%w: %q", ErrInvalidGroupName, name)
	}
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

	if !ValidGroupName(name) {
		return fmt.Errorf("%w: %q", ErrInvalidGroupName, name)
	}
	if _, exists := m.groups[name]; !exists {
		return fmt.Errorf("group '%s' not found", name)
	}

	delete(m.groups, name)
	return os.Remove(filepath.Join(m.directory, name+".json"))
}

// RenameGroup renames a group on disk and in memory, updating link.Group and .active.
func (m *Manager) RenameGroup(oldName, newName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	oldName = strings.TrimSpace(oldName)
	newName = strings.TrimSpace(newName)
	if !ValidGroupName(newName) {
		return fmt.Errorf("%w: %q", ErrInvalidGroupName, newName)
	}
	if oldName == "" {
		return fmt.Errorf("empty group name")
	}
	if oldName == newName {
		return nil
	}
	if newName == "default" {
		return fmt.Errorf("'default' is reserved")
	}
	g, ok := m.groups[oldName]
	if !ok {
		return fmt.Errorf("group '%s' not found", oldName)
	}
	if _, exists := m.groups[newName]; exists {
		return fmt.Errorf("group '%s' already exists", newName)
	}

	g.Name = newName
	for _, link := range g.Links {
		link.Group = newName
	}
	m.groups[newName] = g
	delete(m.groups, oldName)

	if err := m.saveGroup(g); err != nil {
		// rollback memory
		g.Name = oldName
		for _, link := range g.Links {
			link.Group = oldName
		}
		m.groups[oldName] = g
		delete(m.groups, newName)
		return err
	}
	_ = os.Remove(filepath.Join(m.directory, oldName+".json"))

	// Update .active if it pointed at the old group
	activePath := filepath.Join(m.directory, ".active")
	if data, err := os.ReadFile(activePath); err == nil {
		lines := strings.Split(string(data), "\n")
		if len(lines) >= 1 && strings.TrimSpace(lines[0]) == oldName {
			remark := ""
			if len(lines) >= 2 {
				remark = lines[1]
			}
			_ = os.WriteFile(activePath, []byte(newName+"\n"+remark), 0644)
		}
	}
	if m.activeGroup == oldName {
		m.activeGroup = newName
	}
	if m.activeLink != nil && m.activeLink.Group == oldName {
		m.activeLink.Group = newName
	}
	return nil
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

// Directory returns the profile storage directory.
func (m *Manager) Directory() string { return m.directory }

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

		// Always overwrite link.Group with the current group name from the file.
		// Links may have a stale group name if the group was renamed — that causes
		// SetActiveLink to write the old name to .active, and GetActiveLink then
		// can't resolve it, falling back to a random group.
		for _, link := range g.Links {
			link.Group = g.Name
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
	if !ValidGroupName(g.Name) {
		return fmt.Errorf("%w: %q", ErrInvalidGroupName, g.Name)
	}
	data, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(m.directory, g.Name+".json"), data, 0644)
}
