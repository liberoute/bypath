package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/liberoute/bypath/internal/app"
)

// cmdStatus reports what the running gateway is doing. It is deliberately
// read-only: it never starts, stops or reconfigures the service.
func cmdStatus(args []string) {
	jsonOut := false
	for _, a := range args {
		switch a {
		case "--json":
			jsonOut = true
		case "-h", "--help":
			fmt.Println("Usage: bypath status [--json]")
			return
		default:
			fmt.Printf("Unknown option: %s\n", a)
			os.Exit(2)
		}
	}

	svc, err := openService()
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		fmt.Println("   Is the gateway running? Check `systemctl status bypath` or the log.")
		os.Exit(1)
	}
	st, err := svc.Status(context.Background())
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		os.Exit(1)
	}

	if jsonOut {
		data, err := json.MarshalIndent(st, "", "  ")
		if err != nil {
			fmt.Printf("❌ %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(data))
		os.Exit(statusExitCode(st))
	}

	state := st.State
	if state == "" {
		state = "UNKNOWN"
	}
	fmt.Printf("Bypath %s (%s)\n", st.Version, st.Variant)
	if !st.Running {
		fmt.Println("Service:     not running")
	} else {
		fmt.Printf("Service:     running (pid %d, uptime %s)\n", st.PID, formatUptime(st.UptimeSec))
	}
	fmt.Printf("State:       %s\n", state)
	if st.ActiveLink != "" {
		fmt.Printf("Active:      %s", st.ActiveLink)
		if st.Protocol != "" {
			fmt.Printf(" [%s]", strings.ToUpper(st.Protocol))
		}
		if st.Engine != "" {
			fmt.Printf(" via %s", st.Engine)
		}
		fmt.Println()
	}
	if st.SelectedLink != "" && st.SelectedLink != st.ActiveLink {
		fmt.Printf("Selected:    %s\n", st.SelectedLink)
	}
	if st.ActiveGroup != "" {
		fmt.Printf("Group:       %s\n", st.ActiveGroup)
	}
	if st.GatewayMode {
		fmt.Printf("Gateway:     enabled (DNS %s)\n", st.DNSMode)
	} else {
		fmt.Println("Gateway:     disabled (proxy-only)")
	}
	if st.FallbackError != "" {
		fmt.Printf("Fallback:    %s\n", st.FallbackError)
	}
	if st.Recovery > 0 {
		fmt.Printf("Recovery:    attempt %d\n", st.Recovery)
	}
	os.Exit(statusExitCode(st))
}

// statusExitCode makes the exit status carry the probe result: success only
// when a gateway was found running, so a monitoring check can rely on it.
func statusExitCode(st app.Status) int {
	if st.Running {
		return 0
	}
	return 1
}

func formatUptime(seconds int64) string {
	if seconds <= 0 {
		return "just started"
	}
	d := seconds / 86400
	h := (seconds % 86400) / 3600
	m := (seconds % 3600) / 60
	s := seconds % 60
	switch {
	case d > 0:
		return fmt.Sprintf("%dd%dh", d, h)
	case h > 0:
		return fmt.Sprintf("%dh%dm", h, m)
	case m > 0:
		return fmt.Sprintf("%dm%ds", m, s)
	default:
		return fmt.Sprintf("%ds", s)
	}
}
