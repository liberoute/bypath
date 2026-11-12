package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/control"
	"github.com/liberoute/bypath/internal/paths"
	"github.com/liberoute/bypath/internal/pidfile"
	"github.com/liberoute/bypath/internal/profile"
)

// OpenDefault returns the application contract for a frontend process. When a
// gateway process owns the state, the caller gets the HTTP client; otherwise
// the returned service is the in-process owner.
func OpenDefault() (Contract, error) {
	p := paths.Get()

	// Prefer the permissioned local socket: it identifies the running daemon
	// without reading root-only configuration or an API token.
	if svc, ok, err := openControlSocket(p.ControlSocket); err != nil {
		return nil, err
	} else if ok {
		return svc, nil
	}

	cfg, err := config.Load(p.ConfigFile)
	if err != nil {
		if pid, running := pidfile.IsRunningFromFile(p.PidFile); running {
			if p.ControlSocket == "" {
				return nil, errorf(CodeUnavailable,
					"gateway PID %d is running but this account cannot read %s to locate its API; run this command as the owning account",
					pid, p.ConfigFile)
			}
			return nil, &Error{
				Code:    CodeUnavailable,
				Message: fmt.Sprintf("gateway PID %d is running but not reachable from this account", pid),
				Hint:    "make sure the control socket " + p.ControlSocket + " is available and this account is in the '" + control.GroupName + "' group",
			}
		}
		if errors.Is(err, os.ErrPermission) {
			return nil, &Error{
				Code:    CodeUnauthorized,
				Message: fmt.Sprintf("cannot read %s", p.ConfigFile),
				Hint:    "run this command as the owning account or ask an administrator for access",
			}
		}
		// A missing config must not prevent read-only inspection; operations
		// that need configuration report their own errors.
		cfg = &config.Config{}
		cfg.Server.Listen = "127.0.0.1"
	}
	return OpenWith(p, cfg, p.ConfigFile)
}

// openControlSocket probes the socket before returning a client. A missing or
// stale socket falls back to config-based discovery for compatibility with
// older daemons; a permission denial is reported instead of silently falling
// back to an API address this account cannot authenticate to.
func openControlSocket(path string) (Contract, bool, error) {
	if path == "" {
		return nil, false, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	conn, err := control.DialContext(ctx, path)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return nil, false, &Error{
				Code:    CodeUnauthorized,
				Message: "access to the gateway control socket " + path + " was denied; add this account to the '" + control.GroupName + "' group, then start a new login session",
				Hint:    "the gateway daemon controls which accounts may manage it",
			}
		}
		return nil, false, nil
	}
	conn.Close()
	return NewRemoteSocket(path), true, nil
}

// OpenWith builds the contract for an explicit installation and configuration.
func OpenWith(p *paths.Resolved, cfg *config.Config, configPath string) (Contract, error) {
	if cfg == nil {
		cfg = &config.Config{}
	}
	if cfg.Profiles.Directory == "" {
		cfg.Profiles.Directory = p.ProfileDir
	}
	if cfg.Profiles.ActiveGroup == "" {
		cfg.Profiles.ActiveGroup = "default"
	}
	if pid, running := pidfile.IsRunningFromFile(p.PidFile); running && pid != os.Getpid() {
		return RemoteFromConfig(cfg), nil
	}
	mgr, err := profile.NewManager(cfg.Profiles.Directory, cfg.Profiles.ActiveGroup)
	if err != nil {
		return nil, errorf(CodeInternal, "opening profiles: %v", err)
	}
	return NewLocal(Options{
		Paths:      p,
		Config:     cfg,
		ConfigPath: configPath,
		Profiles:   mgr,
	})
}
