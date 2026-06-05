package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/liberoute/bypath/internal/profile"
)

func cmdTest(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: bypath test <uri|config-file> [-e engine]")
		os.Exit(1)
	}

	forceEngine := ""
	var input string

	for i := 0; i < len(args); i++ {
		if (args[i] == "-e" || args[i] == "--engine") && i+1 < len(args) {
			forceEngine = args[i+1]
			i++
		} else {
			input = args[i]
		}
	}

	if strings.Contains(input, "://") {
		link, err := profile.ParseURI(input)
		if err != nil {
			fmt.Printf("❌ Invalid URI: %v\n", err)
			os.Exit(1)
		}

		detectedEngine := detectEngine(link.Protocol, forceEngine)
		fmt.Printf("📋 Parsed link:\n")
		fmt.Printf("   Protocol: %s\n", link.Protocol)
		fmt.Printf("   Server:   %s:%d\n", link.Address, link.Port)
		fmt.Printf("   Remark:   %s\n", link.Remark)
		fmt.Printf("   Network:  %s\n", link.Network)
		fmt.Printf("   TLS:      %v\n", link.TLS)
		fmt.Printf("   Engine:   %s\n", detectedEngine)
	} else {
		detectedEngine := detectEngineFromFile(input, forceEngine)
		fmt.Printf("📋 Config file: %s\n", input)
		fmt.Printf("   Engine:   %s\n", detectedEngine)
	}

	fmt.Println("\n✅ Config is valid (dry-run)")
}
