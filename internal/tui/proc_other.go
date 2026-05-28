//go:build !linux

package tui

import "os/exec"

func setSysProcAttr(cmd *exec.Cmd) {
	// No-op on non-Linux platforms
}
