package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/liberoute/bypath/internal/config"
	"gopkg.in/yaml.v3"
)

// Settings returns the editable, non-secret configuration.
func (s *Local) Settings(ctx context.Context) (Settings, error) {
	cfg := s.Config()
	out := Settings{
		APIPort:       cfg.Server.APIPort,
		DNSPort:       cfg.Server.DNSPort,
		SOCKSPort:     cfg.Server.SOCKSPort,
		APITokenSet:   cfg.Server.APIToken != "",
		GatewayMode:   cfg.Gateway.Enabled,
		LANInterface:  cfg.Gateway.Interface,
		DNSMode:       cfg.Gateway.DNSMode,
		DNSUpstream:   append([]string(nil), cfg.Gateway.DNSUpstream...),
		NativeTUN:     cfg.Gateway.NativeTUN,
		PreferredEng:  cfg.Engines.PreferredEngine,
		HealthEnabled: cfg.HealthCheck.Enabled,
		HealthURL:     cfg.HealthCheck.URL,
		HealthEvery:   cfg.HealthCheck.Interval,
		Isolation:     cfg.Isolation.Enabled,
		AIAuthSet:     false,
		Listen:        cfg.Server.Listen,
		SOCKSListen:   cfg.Server.SOCKSListenAddress(),
		SOCKSAllowLAN: cfg.Server.SOCKSAllowLAN,
		SOCKSAuthSet:  cfg.Server.SOCKSRequiresAuth(),
	}
	if out.DNSMode == "" {
		out.DNSMode = "strict"
	}
	out.LANAccess = cfg.Server.SOCKSListenAddress() != "127.0.0.1"
	out.WebListen, out.WebPort, out.WebSocket = cfg.Server.Web.Listen, cfg.Server.Web.Port, cfg.Server.Web.Socket
	out.EffectiveProxyEndpoints = config.ProxyEndpoints(cfg.Server)
	if lans, err := config.TrustedLANs(cfg.Gateway.Interface, cfg.Server.SOCKSAllowCIDRs); err == nil && len(lans) > 0 {
		cidrs := make([]string, 0, len(lans))
		for _, lan := range lans {
			cidrs = append(cidrs, fmt.Sprintf("%s via %s", lan.CIDR, lan.Interface))
		}
		out.TrustedLANIP = lans[0].IP
		out.TrustedLANCIDRs = cidrs
		out.TrustedLANCIDR = strings.Join(cidrs, ", ")
	}
	if s.runtime != nil && s.serviceOps != nil {
		out.ServiceRestartSupported, out.ServiceRestartReason = s.serviceOps.Supported(ctx, s.configPath)
	} else {
		out.ServiceRestartReason = "service operations require the installed systemd daemon"
	}
	return out, nil
}

// UpdateSettings validates and atomically saves a partial configuration change.
func (s *Local) UpdateSettings(ctx context.Context, patch SettingsPatch) (SettingsChange, error) {
	s.switchMu.Lock()
	defer s.switchMu.Unlock()
	if err := s.serviceMutationGuard(); err != nil {
		return SettingsChange{}, err
	}
	if patch.LANAccess != nil || patch.Listen != nil {
		return SettingsChange{}, errorf(CodeInvalid, "management bind is host-managed; proxy changes require /app/proxy/apply")
	}
	s.mu.Lock()
	// Mutate a copy: validation or a failed write must never leave the live
	// configuration half-applied in memory.
	work := *s.cfg
	cfg := &work
	oldGateway := cfg.Gateway.Enabled
	oldDNSMode := cfg.Gateway.DNSMode
	oldUpstream := strings.Join(cfg.Gateway.DNSUpstream, ",")
	oldNative := cfg.Gateway.NativeTUN
	oldEngine := cfg.Engines.PreferredEngine
	oldListen := cfg.Server.Listen
	oldSocksListen := cfg.Server.SOCKSListenAddress()
	oldSocksAllowLAN := cfg.Server.SOCKSAllowLAN

	if patch.GatewayMode != nil {
		cfg.Gateway.Enabled = *patch.GatewayMode
	}
	if patch.LANInterface != nil {
		if err := validInterface(*patch.LANInterface); err != nil {
			s.mu.Unlock()
			return SettingsChange{}, err
		}
		cfg.Gateway.Interface = strings.TrimSpace(*patch.LANInterface)
	}
	if patch.DNSMode != nil {
		mode := strings.ToLower(strings.TrimSpace(*patch.DNSMode))
		if mode != "strict" && mode != "local" {
			s.mu.Unlock()
			return SettingsChange{}, errorf(CodeInvalid, "dns_mode must be \"strict\" or \"local\"")
		}
		cfg.Gateway.DNSMode = mode
	}
	if patch.DNSUpstream != nil {
		list, err := validateUpstreams(*patch.DNSUpstream)
		if err != nil {
			s.mu.Unlock()
			return SettingsChange{}, err
		}
		cfg.Gateway.DNSUpstream = list
	}
	if patch.NativeTUN != nil {
		cfg.Gateway.NativeTUN = *patch.NativeTUN
	}
	if patch.PreferredEng != nil {
		name := strings.TrimSpace(*patch.PreferredEng)
		if name != "" && name != "sing-box" && name != "xray" {
			s.mu.Unlock()
			return SettingsChange{}, errorf(CodeInvalid, "preferred engine must be empty, \"sing-box\" or \"xray\"")
		}
		cfg.Engines.PreferredEngine = name
	}
	if patch.HealthEnabled != nil {
		cfg.HealthCheck.Enabled = *patch.HealthEnabled
	}
	if patch.HealthURL != nil {
		target := strings.TrimSpace(*patch.HealthURL)
		if target != "" {
			u, err := url.Parse(target)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				s.mu.Unlock()
				return SettingsChange{}, errorf(CodeInvalid, "health check URL must be an absolute http(s) URL")
			}
		}
		cfg.HealthCheck.URL = target
	}
	if patch.HealthEvery != nil {
		d, err := time.ParseDuration(strings.TrimSpace(*patch.HealthEvery))
		if err != nil || d < 5*time.Second {
			s.mu.Unlock()
			return SettingsChange{}, errorf(CodeInvalid, "health interval must be a duration of at least 5s")
		}
		cfg.HealthCheck.Interval = strings.TrimSpace(*patch.HealthEvery)
	}
	if patch.Isolation != nil {
		cfg.Isolation.Enabled = *patch.Isolation
	}
	if patch.APIToken != nil {
		cfg.Server.APIToken = strings.TrimSpace(*patch.APIToken)
	}

	if err := config.ValidateServer(cfg.Server); err != nil {
		s.mu.Unlock()
		return SettingsChange{}, errorf(CodeInvalid, "%s", err)
	}
	if err := s.writeConfig(cfg); err != nil {
		s.mu.Unlock()
		return SettingsChange{}, err
	}
	s.cfg = cfg
	restart := cfg.Gateway.Enabled != oldGateway ||
		cfg.Gateway.DNSMode != oldDNSMode ||
		cfg.Gateway.NativeTUN != oldNative ||
		cfg.Engines.PreferredEngine != oldEngine ||
		strings.Join(cfg.Gateway.DNSUpstream, ",") != oldUpstream ||
		cfg.Server.Listen != oldListen ||
		cfg.Server.SOCKSListenAddress() != oldSocksListen ||
		cfg.Server.SOCKSAllowLAN != oldSocksAllowLAN
	s.mu.Unlock()

	if s.runtime != nil {
		if fields := s.runtime.Reload(cfg); len(fields) > 0 {
			restart = true
		}
	}
	settings, _ := s.Settings(ctx)
	return SettingsChange{Settings: settings, RestartRequired: restart}, nil
}

func validInterface(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	if len(name) > 32 || strings.ContainsAny(name, "/\\ \t\x00") {
		return errorf(CodeInvalid, "interface name contains invalid characters")
	}
	return nil
}

func validateUpstreams(list []string) ([]string, error) {
	out := make([]string, 0, len(list))
	for _, raw := range list {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if net.ParseIP(raw) == nil {
			return nil, errorf(CodeInvalid, "DNS upstream %q is not an IP address", raw)
		}
		out = append(out, raw)
	}
	if len(out) == 0 {
		return nil, errorf(CodeInvalid, "at least one DNS upstream is required")
	}
	return out, nil
}

// writeConfig persists the configuration transactionally. The caller holds
// s.mu. A previous file is copied to config.yaml.bak first; the new file is
// written to a temporary sibling and renamed into place, so an invalid write
// can never leave a truncated config.
func (s *Local) writeConfig(cfg *config.Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return asAppError(err, CodeInternal, "encoding configuration")
	}
	path := s.configPath
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return asAppError(err, CodeInternal, "creating config directory")
	}
	if old, err := os.ReadFile(path); err == nil {
		_ = os.WriteFile(path+".bak", old, 0600)
	}
	tmp, err := os.CreateTemp(dir, ".config-*.yaml")
	if err != nil {
		return asAppError(err, CodeInternal, "creating temporary config")
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		cleanup()
		return asAppError(err, CodeInternal, "restricting config permissions")
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return asAppError(err, CodeInternal, "writing temporary config")
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return asAppError(err, CodeInternal, "flushing temporary config")
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return asAppError(err, CodeInternal, "closing temporary config")
	}
	if err := os.Rename(tmpName, path); err != nil {
		// Windows cannot rename over an existing file.
		_ = os.Remove(path)
		if err2 := os.Rename(tmpName, path); err2 != nil {
			cleanup()
			return asAppError(err2, CodeInternal, "installing config")
		}
	}
	return nil
}

// Backup returns a non-secret configuration export. Credentials, API tokens and
// subscription URLs are excluded by construction.
func (s *Local) Backup(ctx context.Context, includeSecrets bool) (Backup, error) {
	if includeSecrets {
		return Backup{}, &Error{
			Code:    CodeInvalid,
			Message: "secret export is not supported",
			Hint:    "backups contain configuration only; credentials are never exported",
		}
	}
	cfg := s.Config()
	clean := *cfg
	clean.Server.APIToken = ""
	clean.Server.SOCKSUsername = ""
	clean.Server.SOCKSPassword = ""
	clean.Routing.ExternalOutbounds = make(map[string]string, len(cfg.Routing.ExternalOutbounds))
	for k, v := range cfg.Routing.ExternalOutbounds {
		clean.Routing.ExternalOutbounds[k] = stripUserinfo(v)
	}
	data, err := yaml.Marshal(&clean)
	if err != nil {
		return Backup{}, asAppError(err, CodeInternal, "encoding backup")
	}
	return Backup{
		Version:        1,
		Created:        time.Now().UTC().Format(time.RFC3339),
		ContainsSecret: false,
		Config:         data,
		Excluded:       []string{"server.api_token", "server.socks_username", "server.socks_password", "credentials", "subscriptions"},
	}, nil
}

func stripUserinfo(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	u.User = nil
	return u.String()
}

// Restore validates a backup and installs its configuration. Credentials and
// connections are not part of a backup and are left untouched. Host-local
// security state is merged before validation, so a portable backup cannot move
// the management surface, trust a different SSH host key, or redirect the
// daemon's directories.
func (s *Local) Restore(ctx context.Context, data []byte) error {
	s.switchMu.Lock()
	defer s.switchMu.Unlock()
	if err := s.serviceMutationGuard(); err != nil {
		return err
	}
	var b Backup
	if err := json.Unmarshal(data, &b); err != nil {
		return errorf(CodeInvalid, "invalid backup file: %v", err)
	}
	if b.Version != 1 {
		return errorf(CodeInvalid, "unsupported backup version %d", b.Version)
	}
	if len(b.Config) == 0 {
		return errorf(CodeInvalid, "backup contains no configuration")
	}

	restored, err := config.Parse(b.Config)
	if err != nil {
		return errorf(CodeInvalid, "backup configuration is invalid: %v", err)
	}

	s.mu.Lock()
	// Directories and the API token are host-local security state, not portable
	// settings. A backup from another host (or a tampered one) must not be able
	// to point the root daemon at a caller-chosen binary directory, redirect
	// profile writes, or silently drop token auth.
	restored.Engines.Directory = s.cfg.Engines.Directory
	restored.Profiles.Directory = s.cfg.Profiles.Directory
	restored.Server.APIToken = s.cfg.Server.APIToken
	// The management surface and its exposure are host-local too: an imported
	// document may change tunnel behaviour, not open the API or panel on a new
	// address.
	restored.Server.Listen = s.cfg.Server.Listen
	restored.Server.APIPort = s.cfg.Server.APIPort
	restored.Server.Web = s.cfg.Server.Web
	// Proxy exposure and its credentials are host-local security state: a
	// backup must not be able to open the listener or change who may use it.
	restored.Server.SOCKSPort = s.cfg.Server.SOCKSPort
	restored.Server.SOCKSListen = s.cfg.Server.SOCKSListen
	restored.Server.SOCKSAllowLAN = s.cfg.Server.SOCKSAllowLAN
	restored.Server.SOCKSUsername = s.cfg.Server.SOCKSUsername
	restored.Server.SOCKSPassword = s.cfg.Server.SOCKSPassword
	// Host-key trust is a property of this host's known_hosts, not of a portable
	// document: importing a backup must not relax verification.
	restored.Server.SSHHostKey = s.cfg.Server.SSHHostKey
	// Gateway mode and its DNS policy decide whether this host forwards traffic
	// and where DNS goes. A tampered backup must not turn the host into a
	// gateway, open a DNS listener, or send lookups to a new resolver.
	restored.Server.DNSPort = s.cfg.Server.DNSPort
	restored.Gateway = s.cfg.Gateway
	// Routing decides which traffic leaves the tunnel. Keep this host's rules
	// and outbounds; a backup must not route the default path direct.
	restored.Routing = s.cfg.Routing
	restored.Isolation = s.cfg.Isolation
	// The legacy whitelist decides which traffic is routed direct. It is host
	// policy: an imported document must not widen it with new countries, bypass
	// suffixes or an override list, and must not repoint the geosite source.
	restored.Whitelist = s.cfg.Whitelist
	restored.Engines.PreferSystem = s.cfg.Engines.PreferSystem
	// A restored chain may describe hops, but only this host may mark one for
	// automatic connection at startup, and a chain this host starts on its own
	// keeps the host's hops: a backup must not redirect the automatic
	// connection through a profile it chose.
	hostChains := make(map[string]config.ChainConfig, len(s.cfg.Chains))
	for _, c := range s.cfg.Chains {
		hostChains[c.Name] = c
	}
	for i := range restored.Chains {
		host, ok := hostChains[restored.Chains[i].Name]
		if ok && host.AutoStart {
			restored.Chains[i] = host
			continue
		}
		restored.Chains[i].AutoStart = false
	}

	if err := restored.NormalizeAndValidate(); err != nil {
		s.mu.Unlock()
		return errorf(CodeInvalid, "backup configuration is invalid: %v", err)
	}

	old := *s.cfg
	*s.cfg = *restored
	if err := s.writeConfig(s.cfg); err != nil {
		*s.cfg = old
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()

	if s.runtime != nil {
		s.runtime.Reload(s.cfg)
	}
	return nil
}

// ReloadConfig re-reads the configuration file, applies it to the running
// gateway and returns the fields that still need a restart. It is the single
// reload path for SIGHUP and for the API.
func (s *Local) ReloadConfig() ([]string, error) {
	s.switchMu.Lock()
	defer s.switchMu.Unlock()
	if err := s.serviceMutationGuard(); err != nil {
		return nil, err
	}
	cfg, err := config.Load(s.configPath)
	if err != nil {
		return nil, errorf(CodeInvalid, "config reload failed: %v", err)
	}
	var restart []string
	if s.runtime != nil {
		restart = s.runtime.Reload(cfg)
	}
	s.mu.Lock()
	s.cfg = cfg
	s.mu.Unlock()
	return restart, nil
}
