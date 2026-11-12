package main

import (
	"fmt"
	"os"

	"github.com/liberoute/bypath/internal/gateway"
)

// cmdHostDNS is the systemd lifecycle hook. The unit runs
// `bypath host-dns restore` as ExecStartPre and ExecStopPost so a crashed or
// SIGKILLed gateway can never leave the host resolver pointed at a listener
// that is no longer running. It is not part of the operator interface.
func cmdHostDNS(args []string) {
	if len(args) != 1 || args[0] != "restore" {
		fmt.Fprintln(os.Stderr, "usage: bypath host-dns restore")
		os.Exit(2)
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "host-dns restore changes host resolver configuration and must run as root")
		os.Exit(1)
	}
	if err := gateway.RestoreHostDNS(); err != nil {
		fmt.Fprintf(os.Stderr, "host DNS restore failed: %v\n", err)
		os.Exit(1)
	}
}
