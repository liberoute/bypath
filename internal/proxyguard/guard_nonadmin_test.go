//go:build linux

package proxyguard

// Root container without NET_ADMIN: iptables is installed but every ruleset
// query fails. This is the environment that regressed in the security review.
// Run it with:
//
//	docker run --rm -e BYPATH_GUARD_NO_NETADMIN=1 bypath-guard-test \
//	    go test -count=1 -v -run NoNetAdmin ./internal/proxyguard

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestNoNetAdminLoopbackStartsWithRealFirewall(t *testing.T) {
	if os.Getenv("BYPATH_GUARD_NO_NETADMIN") != "1" {
		t.Skip("set BYPATH_GUARD_NO_NETADMIN=1 in a root container without NET_ADMIN")
	}
	if os.Geteuid() != 0 {
		t.Skip("root container required")
	}
	if _, err := run("-S", "INPUT"); err == nil {
		t.Skip("this container still has firewall access; run it without NET_ADMIN")
	}

	old := statePath
	dir := filepath.Join("/var/lib", fmt.Sprintf("bypath-nonetadmin-test-%d", os.Getpid()))
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	statePath = filepath.Join(dir, "proxy-input.json")
	t.Cleanup(func() {
		releaseHeld()
		statePath = old
		os.RemoveAll(dir)
	})

	if err := Ensure(loopbackConfig()); err != nil {
		t.Fatalf("loopback-only startup required firewall access: %v", err)
	}
	if err := Ensure(iptablesConfig()); err == nil {
		t.Fatal("LAN-exposed startup succeeded without firewall access")
	}
}
