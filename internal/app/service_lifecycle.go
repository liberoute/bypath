package app

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strings"

	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/serviceop"
)

const CodeUnsupported = "unsupported"

type ServiceOperation = serviceop.Operation
type ProxyApply struct {
	SOCKSPort   int    `json:"socks_port"`
	SOCKSListen string `json:"socks_listen"`
	ConfirmLAN  bool   `json:"confirm_lan"`
	ConfirmAll  bool   `json:"confirm_all"`
}

func operationError(err error) error {
	switch {
	case errors.Is(err, serviceop.ErrUnsupported):
		return &Error{Code: CodeUnsupported, Message: err.Error(), Err: err}
	case errors.Is(err, serviceop.ErrBusy):
		return asAppError(err, CodeConflict, "service operation")
	case errors.Is(err, serviceop.ErrNotFound):
		return asAppError(err, CodeNotFound, "service operation")
	}
	return asAppError(err, CodeUnavailable, "service operation")
}
func (s *Local) ServiceOperationPending() bool { return s.serviceOps != nil && s.serviceOps.Busy() }

func (s *Local) serviceMutationGuard() error {
	if s.serviceOps != nil && s.serviceOps.Busy() {
		return errorf(CodeConflict, "service operation pending; wait for verification or rollback")
	}
	return nil
}
func (s *Local) RestartService(ctx context.Context, confirm bool) (ServiceOperation, error) {
	if !confirm {
		return ServiceOperation{}, errorf(CodeInvalid, "confirm must be true")
	}
	s.switchMu.Lock()
	defer s.switchMu.Unlock()
	return s.queueService(ctx, nil)
}
func (s *Local) queueService(ctx context.Context, proposed *config.Config) (ServiceOperation, error) {
	if s.runtime == nil || s.serviceOps == nil {
		return ServiceOperation{}, operationError(serviceop.ErrUnsupported)
	}
	if s.runtime.Status().State != "CONNECTED" {
		return ServiceOperation{}, errorf(CodeConflict, "a serving tunnel is required for verified service operations")
	}
	cfg := s.Config()
	st, _ := s.Status(ctx)
	op, err := s.serviceOps.Queue(ctx, s.configPath, filepath.Join(cfg.Profiles.Directory, ".active"), s.paths.ControlSocket, st.ActiveID, st.SelectedID, proposed)
	return op, operationError(err)
}
func (s *Local) ApplyProxy(ctx context.Context, req ProxyApply) (ServiceOperation, error) {
	s.switchMu.Lock()
	defer s.switchMu.Unlock()
	if err := s.serviceMutationGuard(); err != nil {
		return ServiceOperation{}, err
	}
	work := *s.Config()
	old := work.Server
	work.Server.SOCKSPort = req.SOCKSPort
	work.Server.SOCKSListen = strings.TrimSpace(req.SOCKSListen)
	if work.Server.SOCKSListen == "" {
		return ServiceOperation{}, errorf(CodeInvalid, "socks_listen is required")
	}
	work.Server.SOCKSAllowLAN = work.Server.SOCKSListen != "127.0.0.1"
	if work.Server.SOCKSAllowLAN {
		if !req.ConfirmLAN {
			return ServiceOperation{}, errorf(CodeInvalid, "LAN proxy exposure requires confirm_lan")
		}
		lan, err := config.TrustedLANs(work.Gateway.Interface, work.Server.SOCKSAllowCIDRs)
		if err != nil {
			return ServiceOperation{}, errorf(CodeInvalid, "%s", err)
		}
		if work.Server.SOCKSListen == "0.0.0.0" {
			if !req.ConfirmAll {
				return ServiceOperation{}, errorf(CodeInvalid, "all-interface bind requires confirm_all")
			}
		} else {
			trusted := false
			for _, l := range lan {
				if work.Server.SOCKSListen == l.IP {
					trusted = true
				}
			}
			if !trusted {
				return ServiceOperation{}, errorf(CodeInvalid, "socks_listen must be 127.0.0.1, a trusted LAN IP, or confirmed 0.0.0.0")
			}
		}
	}
	if err := config.ValidateServer(work.Server); err != nil {
		return ServiceOperation{}, errorf(CodeInvalid, "%s", err)
	}
	if old.SOCKSPort != req.SOCKSPort || old.SOCKSListenAddress() != work.Server.SOCKSListenAddress() {
		if err := checkProxyListeners(old, work.Server); err != nil {
			return ServiceOperation{}, errorf(CodeConflict, "proposed proxy listener conflicts: %s", err)
		}
	}
	return s.queueService(ctx, &work)
}

// Binding without reuse detects both TCP and UDP collisions. The current
// daemon-owned endpoint is excluded only when the port/bind is unchanged.
var checkProxyListeners = func(old, proposed config.ServerConfig) error {
	if old.SOCKSPort == proposed.SOCKSPort {
		return checkSamePort(proposed.SOCKSPort)
	}
	for _, endpoint := range config.ProxyEndpoints(proposed) {
		tcp, err := net.Listen("tcp4", endpoint)
		if err != nil {
			return err
		}
		udp, err := net.ListenPacket("udp4", endpoint)
		tcp.Close()
		if err != nil {
			return err
		}
		udp.Close()
	}
	return nil
}

func (s *Local) ServiceOperation(ctx context.Context, id string) (ServiceOperation, error) {
	if s.serviceOps == nil {
		return ServiceOperation{}, operationError(serviceop.ErrUnsupported)
	}
	op, err := s.serviceOps.Get(id)
	return op, operationError(err)
}
