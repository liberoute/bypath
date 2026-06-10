//go:build !linux

package main

import "fmt"

func openTUI() {
	fmt.Println("TUI is not supported on this platform. Use 'bypath run' to start the gateway.")
}
