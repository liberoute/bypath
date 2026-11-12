//go:build !linux

package proxyguard

import (
	"errors"
	"github.com/liberoute/bypath/internal/config"
)

func Ensure(cfg *config.Config) error {
	if cfg.Server.SOCKSListenAddress() != "127.0.0.1" {
		return errors.New("LAN proxy unsupported without owned Linux IPv4 firewall")
	}
	return nil
}
func Cleanup() error { return nil }
