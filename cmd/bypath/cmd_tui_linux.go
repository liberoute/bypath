//go:build linux

package main

import "github.com/liberoute/bypath/internal/tui"

func openTUI() {
	menu := tui.New()
	menu.Run()
}
