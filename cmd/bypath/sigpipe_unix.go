//go:build linux || darwin

package main

import (
	"os/signal"
	"syscall"
)

// ignoreSIGPIPE keeps a closed stdout/stderr from killing the process mid
// write. Go raises SIGPIPE for fd 1 and 2 by default, so `bypath --help |
// head` could die with a signal instead of finishing cleanly.
func ignoreSIGPIPE() {
	signal.Ignore(syscall.SIGPIPE)
}
