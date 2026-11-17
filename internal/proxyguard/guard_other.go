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

// RecordToken, CleanupOwned and the sentinels exist so the stop path compiles
// unchanged; there is never a guard to remove on a platform without the Linux
// firewall.
var (
	ErrGuardBusy     = errors.New("proxy guard is in use by a running bypath process")
	ErrGuardReplaced = errors.New("proxy guard belongs to a different run")
	ErrGuardUnshared = errors.New("proxy guard state directory is not shared with the firewall owner")
)

func RecordToken() string       { return "" }
func CleanupOwned(string) error { return nil }
