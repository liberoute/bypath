// Package app is the single application service used by the CLI, the terminal
// UI and the web panel. Every frontend speaks this contract; none of them owns
// business logic or a second profile manager.
package app

import (
	"errors"
	"fmt"
	"time"

	"github.com/liberoute/bypath/internal/profile"
)

// Error codes are stable API identifiers. Frontends switch on Code, not text.
const (
	CodeInvalid      = "invalid_argument"
	CodeNotFound     = "not_found"
	CodeConflict     = "conflict"
	CodeNeedsCreds   = "credentials_required"
	CodeUnavailable  = "unavailable"
	CodePermanent    = "permanent"
	CodeUnauthorized = "unauthorized"
	CodeInternal     = "internal"
)

// Error is the typed application error returned by every operation.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
	Err     error  `json:"-"`
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

func (e *Error) Unwrap() error { return e.Err }

func errorf(code, format string, args ...interface{}) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// CodeOf extracts the stable code from an error.
func CodeOf(err error) string {
	var ae *Error
	if errors.As(err, &ae) {
		return ae.Code
	}
	return CodeInternal
}

// Status is the live product state shown on every dashboard.
type Status struct {
	Version   string `json:"version"`
	Variant   string `json:"variant"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`

	Running     bool   `json:"running"`
	PID         int    `json:"pid,omitempty"`
	State       string `json:"state"`
	ActiveID    string `json:"active_id,omitempty"`
	ActiveLink  string `json:"active_link,omitempty"`
	ActiveGroup string `json:"active_group,omitempty"`
	// SelectedID/SelectedLink are the persisted selection, which stays put when
	// the gateway runs a different link after a fallback. ActiveLink is what
	// actually carries traffic.
	SelectedID    string `json:"selected_id,omitempty"`
	SelectedLink  string `json:"selected_link,omitempty"`
	FallbackFrom  string `json:"fallback_from,omitempty"`
	FallbackError string `json:"fallback_error,omitempty"`
	// PreviousID/PreviousLink name the connection that was serving before the
	// last successful switch, so an operator can return to it.
	PreviousID   string `json:"previous_id,omitempty"`
	PreviousLink string `json:"previous_link,omitempty"`
	Protocol     string `json:"protocol,omitempty"`
	Engine       string `json:"engine,omitempty"`
	GatewayMode  bool   `json:"gateway_mode"`
	DNSMode      string `json:"dns_mode,omitempty"`
	UptimeSec    int64  `json:"uptime_sec,omitempty"`
	Restarts     int    `json:"restarts"`
	TunRestarts  int    `json:"tun_restarts"`
	Recovery     int    `json:"recovery_attempt"`
	LastError    string `json:"last_error,omitempty"`
	LastHealth   string `json:"last_health,omitempty"`
	// Health evidence separates "the tunnel is not forwarding" from "the
	// tunnel answered but its exit could not be proven". The web panel and the
	// TUI explain state from Code and Detail instead of guessing from LastError.
	HealthCode           string `json:"health_code,omitempty"`
	HealthDetail         string `json:"health_detail,omitempty"`
	HealthTunnelAnswered bool   `json:"health_tunnel_answered"`
	HealthExitIP         string `json:"health_exit_ip,omitempty"`
	HealthUplinkSamples  int    `json:"health_uplink_samples"`
	ExitIP               string `json:"exit_ip,omitempty"`
	APIPort              int    `json:"api_port"`
	DNSPort              int    `json:"dns_port"`
	SOCKSPort            int    `json:"socks_port"`
	LANInterface         string `json:"lan_interface,omitempty"`
	ProfileCount         int    `json:"profile_count"`
	SubCount             int    `json:"subscription_count"`

	// Selection reconciles the persisted next-start choice, what the gateway
	// actually serves and whether the choice was made by the operator.
	Selection     SelectionInfo `json:"selection"`
	LayerMigrated bool          `json:"layer_migrated"`
	LayerReadOnly bool          `json:"layer_read_only,omitempty"`
	LayerWarning  string        `json:"layer_warning,omitempty"`
}

// Connection is the secret-free view of a stored link. Raw URIs, UUIDs,
// subscription tokens and encryption keys are never included.
type Connection struct {
	ID               string `json:"id"`
	Group            string `json:"group"`
	Remark           string `json:"remark"`
	Protocol         string `json:"protocol"`
	Address          string `json:"address"`
	Port             int    `json:"port"`
	Network          string `json:"network,omitempty"`
	Engine           string `json:"engine"`
	TLS              bool   `json:"tls"`
	EncryptedVLESS   bool   `json:"encrypted_vless"`
	Reality          bool   `json:"reality"`
	Active           bool   `json:"active"`
	Selected         bool   `json:"selected"`
	RequiresAuth     bool   `json:"requires_auth"`
	HasCredentials   bool   `json:"has_credentials"`
	CredentialsSaved bool   `json:"credentials_saved"`
	FromSubscription string `json:"from_subscription,omitempty"`
	CDN              bool   `json:"cdn"`
	Health           string `json:"health,omitempty"` // "" | "ok" | "failed"

	// Organisation-layer identity. Group/Remark stay the legacy bucket pair so
	// .active and the gateway keep working; LayerGroup is the user-visible
	// organisation and DisplayName overrides the remark only in the product UI.
	StableID     string `json:"stable_id,omitempty"`
	DisplayName  string `json:"display_name,omitempty"`
	LayerGroupID string `json:"layer_group_id,omitempty"`
	LayerGroup   string `json:"layer_group,omitempty"`
	Hidden       bool   `json:"hidden"`
	Orphaned     bool   `json:"orphaned"`
}

// ConnectionDetail adds diagnostics that are too heavy for a list.
type ConnectionDetail struct {
	Connection
	OVPN            bool     `json:"ovpn"`
	OVPNPath        string   `json:"ovpn_path,omitempty"`
	Source          string   `json:"source,omitempty"`
	Warnings        []string `json:"warnings,omitempty"`
	CredentialStore string   `json:"credential_store,omitempty"` // "saved", "session", ""
}

// ConnectionFilter narrows a listing. Zero values mean "all".
type ConnectionFilter struct {
	Group         string
	Search        string
	Protocol      string
	IncludeHidden bool
}

// ImportResult reports what an import actually created or changed.
type ImportResult struct {
	Created     []Connection              `json:"created"`
	Skipped     []Skipped                 `json:"skipped"`
	Diagnostics []profile.ParseDiagnostic `json:"diagnostics,omitempty"`
	Group       string                    `json:"group"`
	Warning     string                    `json:"warning,omitempty"`
}

// Skipped explains one duplicate or invalid entry in a bulk import.
type Skipped struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// OVPNSource is either a server-side path or pasted profile text.
type OVPNSource struct {
	Path string `json:"path,omitempty"`
	Text string `json:"text,omitempty"`
	Name string `json:"name,omitempty"` // optional display name
	// Refs carries referenced certificates/keys for uploads that arrive over
	// HTTP. Names are relative file names next to the profile; they are never
	// treated as server paths.
	Refs []OVPNRef `json:"refs,omitempty"`
}

// OVPNRef is one uploaded file referenced by an OpenVPN profile (ca, cert,
// key, tls-auth, tls-crypt). Content is written to controlled storage and
// inlined by the importer; it is never returned by an API.
type OVPNRef struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

// OVPNPreview is the safe summary shown before importing.
type OVPNPreview struct {
	Name          string   `json:"name"`
	Host          string   `json:"host"`
	Port          int      `json:"port"`
	Network       string   `json:"network"`
	RequiresAuth  bool     `json:"requires_auth"`
	HasInlineAuth bool     `json:"has_inline_auth"`
	CertFiles     []string `json:"cert_files,omitempty"` // references that will be imported
	Warnings      []string `json:"warnings,omitempty"`
}

// OVPNImport carries the confirmed import choices.
type OVPNImport struct {
	OVPNSource
	Group          string `json:"group"`
	Username       string `json:"username,omitempty"`
	Password       string `json:"password,omitempty"`
	SaveCredential bool   `json:"save_credentials"`
}

// Credentials is a username/password pair. Never logged or returned.
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Subscription is one subscription URL and its last refresh result.
type Subscription struct {
	Group         string   `json:"group"`
	URL           string   `json:"url"`
	RedactedURL   string   `json:"redacted_url"`
	LinkCount     int      `json:"link_count"`
	LastRefresh   string   `json:"last_refresh,omitempty"`
	LastError     string   `json:"last_error,omitempty"`
	Refreshing    bool     `json:"refreshing"`
	Connection    []string `json:"connections,omitempty"`
	LayerGroupID  string   `json:"layer_group_id,omitempty"`
	LayerGroup    string   `json:"layer_group,omitempty"`
	ProposedGroup string   `json:"proposed_group"`
}

// RefreshProgress is delivered to a bounded refresh loop.
type RefreshProgress struct {
	Group string
	URL   string
	Done  bool
	Links int
	Err   string
}

// SubscriptionLink is the secret-free preview of one link a subscription would
// add. It never carries a raw URI, UUID, password or key.
type SubscriptionLink struct {
	Remark         string `json:"remark"`
	Protocol       string `json:"protocol"`
	Address        string `json:"address"`
	Port           int    `json:"port"`
	Network        string `json:"network,omitempty"`
	Engine         string `json:"engine"`
	TLS            bool   `json:"tls"`
	Reality        bool   `json:"reality"`
	EncryptedVLESS bool   `json:"encrypted_vless"`
	CDN            bool   `json:"cdn"`
}

// SubscriptionPreview describes what a subscription or dump contains before
// anything is stored. Fetches are bounded and never persisted.
type SubscriptionPreview struct {
	Group       string             `json:"group"`
	RedactedURL string             `json:"redacted_url"`
	Total       int                `json:"total"`
	Duplicates  int                `json:"duplicates"`
	Links       []SubscriptionLink `json:"links"`
	Truncated   bool               `json:"truncated,omitempty"`
	// Rejected classifies every line that could not be imported: malformed
	// input is parse_failure, a recognized but unsupported configuration is
	// unsupported_configuration. Messages never echo the raw line.
	Rejected      []profile.ParseDiagnostic `json:"rejected,omitempty"`
	RejectedCount int                       `json:"rejected_count,omitempty"`
}

// ActionResult truthfully reports what happened to a lifecycle request.
type ActionResult struct {
	Applied         bool   `json:"applied"`
	RestartRequired bool   `json:"restart_required"`
	Message         string `json:"message"`
}

// LogEntry is one redacted event for the Logs screens.
type LogEntry struct {
	Time    string `json:"time"`
	Level   string `json:"level"`
	Message string `json:"message"`
}

// LogQuery bounds a log read.
type LogQuery struct {
	Limit int
	Since string
}

// Engine describes one tunnel engine available to the product.
type Engine struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Path    string `json:"path,omitempty"`
	Source  string `json:"source,omitempty"`
	Ready   bool   `json:"ready"`
}

// Settings is the non-secret configuration editable from the UIs. Secrets are
// reported as presence flags only.
type Settings struct {
	APIPort                 int      `json:"api_port"`
	DNSPort                 int      `json:"dns_port"`
	SOCKSPort               int      `json:"socks_port"`
	APITokenSet             bool     `json:"api_token_set"`
	GatewayMode             bool     `json:"gateway_mode"`
	LANInterface            string   `json:"lan_interface"`
	DNSMode                 string   `json:"dns_mode"`
	DNSUpstream             []string `json:"dns_upstream"`
	NativeTUN               bool     `json:"native_tun"`
	PreferredEng            string   `json:"preferred_engine"`
	HealthEnabled           bool     `json:"health_enabled"`
	HealthURL               string   `json:"health_url"`
	HealthEvery             string   `json:"health_interval"`
	Isolation               bool     `json:"isolation"`
	AIAuthSet               bool     `json:"admin_password_set"`
	Listen                  string   `json:"listen"`
	LANAccess               bool     `json:"lan_access"`
	SOCKSListen             string   `json:"socks_listen"`
	SOCKSAllowLAN           bool     `json:"socks_allow_lan"`
	SOCKSAuthSet            bool     `json:"socks_auth_set"`
	ServiceRestartSupported bool     `json:"service_restart_supported"`
	ServiceRestartReason    string   `json:"service_restart_reason"`
	TrustedLANIP            string   `json:"trusted_lan_ip"`
	TrustedLANCIDR          string   `json:"trusted_lan_cidr"`
	TrustedLANCIDRs         []string `json:"trusted_lan_cidrs"`
	EffectiveProxyEndpoints []string `json:"effective_proxy_endpoints"`
	WebListen               string   `json:"web_listen"`
	WebPort                 int      `json:"web_port"`
	WebSocket               string   `json:"web_socket"`
}

// SettingsPatch changes only the fields that are set (pointers = optional).
type SettingsPatch struct {
	GatewayMode   *bool     `json:"gateway_mode,omitempty"`
	LANInterface  *string   `json:"lan_interface,omitempty"`
	DNSMode       *string   `json:"dns_mode,omitempty"`
	DNSUpstream   *[]string `json:"dns_upstream,omitempty"`
	NativeTUN     *bool     `json:"native_tun,omitempty"`
	PreferredEng  *string   `json:"preferred_engine,omitempty"`
	HealthEnabled *bool     `json:"health_enabled,omitempty"`
	HealthURL     *string   `json:"health_url,omitempty"`
	HealthEvery   *string   `json:"health_interval,omitempty"`
	Isolation     *bool     `json:"isolation,omitempty"`
	APIToken      *string   `json:"api_token,omitempty"`
	Listen        *string   `json:"listen,omitempty"`
	LANAccess     *bool     `json:"lan_access,omitempty"`
}

// SettingsChange reports whether the running gateway must restart.
type SettingsChange struct {
	Settings        Settings `json:"settings"`
	RestartRequired bool     `json:"restart_required"`
}

// Backup is a portable, schema-tagged configuration archive. It carries
// configuration only: credentials, tokens and subscription URLs are excluded.
type Backup struct {
	Version        int      `json:"version"`
	Created        string   `json:"created"`
	ContainsSecret bool     `json:"contains_secrets"`
	Config         []byte   `json:"config_yaml"`
	Excluded       []string `json:"excluded,omitempty"`
}

// ConnectionID builds the stable UI identifier for a link.
func ConnectionID(group, remark string) string {
	return group + ":" + remark
}

// SplitID reverses ConnectionID. Group names never contain a colon
// (sanitizeGroupName strips it), so the first colon is the separator.
func SplitID(id string) (group, remark string, ok bool) {
	for i := 0; i < len(id); i++ {
		if id[i] == ':' {
			if i == 0 || i == len(id)-1 {
				return "", "", false
			}
			return id[:i], id[i+1:], true
		}
	}
	return "", "", false
}

// EngineFor names the engine a link will use. Shared by every frontend so the
// engine shown in the TUI, the API and the web panel is the same answer.
func EngineFor(link *profile.Link) string {
	if link == nil {
		return "unknown"
	}
	if link.EncryptedVLESS() {
		return "xray"
	}
	switch link.Protocol {
	case "openvpn":
		return "sing-box"
	case "wireguard":
		return "wireguard-go"
	case "ssh":
		return "ssh"
	case "vmess", "vless", "trojan", "shadowsocks":
		if link.Network == "xhttp" || link.Network == "splithttp" {
			return "xray"
		}
		return "sing-box"
	default:
		return "sing-box"
	}
}

// FormatTime renders a timestamp for status surfaces without leaking locale
// specific formats into API responses.
func FormatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
