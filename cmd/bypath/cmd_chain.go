package main

import (
	"fmt"
	"os"

	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/paths"
	"gopkg.in/yaml.v3"
)

func cmdChain(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage:")
		fmt.Println("  bypath chain add <name> <hop1> <hop2> [hop3...] [--auto-start]")
		fmt.Println("  bypath chain remove <name>")
		fmt.Println("  bypath chain list")
		fmt.Println("  bypath chain start <name>")
		fmt.Println("  bypath chain stop <name>")
		fmt.Println("  bypath chain status [name]")
		os.Exit(1)
	}

	subCmd := args[0]
	subArgs := args[1:]

	switch subCmd {
	case "add":
		cmdChainAdd(subArgs)
	case "remove", "rm", "del":
		cmdChainRemove(subArgs)
	case "list":
		cmdChainList(subArgs)
	case "start":
		cmdChainStart(subArgs)
	case "stop":
		cmdChainStop(subArgs)
	case "status":
		cmdChainStatus(subArgs)
	default:
		fmt.Printf("Unknown chain command: %s\n", subCmd)
		os.Exit(1)
	}
}

func cmdChainAdd(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: bypath chain add <name> <hop1-profile> [hop2-profile...] [--auto-start]")
		os.Exit(1)
	}

	chainName := args[0]
	autoStart := false
	var hopProfiles []string

	for _, arg := range args[1:] {
		if arg == "--auto-start" {
			autoStart = true
		} else {
			hopProfiles = append(hopProfiles, arg)
		}
	}

	if len(hopProfiles) == 0 {
		fmt.Println("❌ At least one hop profile is required")
		os.Exit(1)
	}

	configPath := paths.Get().ConfigFile
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Printf("❌ Cannot load config: %v\n", err)
		os.Exit(1)
	}

	for _, chain := range cfg.Chains {
		if chain.Name == chainName {
			fmt.Printf("❌ Chain '%s' already exists\n", chainName)
			os.Exit(1)
		}
	}

	hops := make([]config.HopConfig, len(hopProfiles))
	for i, p := range hopProfiles {
		hops[i] = config.HopConfig{Profile: p}
	}

	newChain := config.ChainConfig{
		Name:      chainName,
		Hops:      hops,
		AutoStart: autoStart,
	}

	cfg.Chains = append(cfg.Chains, newChain)

	data, err := yaml.Marshal(cfg)
	if err != nil {
		fmt.Printf("❌ Cannot marshal config: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		fmt.Printf("❌ Cannot write config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✅ Chain '%s' added with %d hop(s)\n", chainName, len(hopProfiles))
	if autoStart {
		fmt.Println("   Auto-start: enabled")
	}
}

func cmdChainRemove(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: bypath chain remove <name>")
		os.Exit(1)
	}

	chainName := args[0]

	configPath := paths.Get().ConfigFile
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Printf("❌ Cannot load config: %v\n", err)
		os.Exit(1)
	}

	found := false
	for i, chain := range cfg.Chains {
		if chain.Name == chainName {
			cfg.Chains = append(cfg.Chains[:i], cfg.Chains[i+1:]...)
			found = true
			break
		}
	}

	if !found {
		fmt.Printf("❌ Chain '%s' not found\n", chainName)
		os.Exit(1)
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		fmt.Printf("❌ Cannot marshal config: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		fmt.Printf("❌ Cannot write config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✅ Chain '%s' removed\n", chainName)
}

func cmdChainList(_ []string) {
	fmt.Println("chain list: not implemented")
}

func cmdChainStart(_ []string) {
	fmt.Println("chain start: not implemented")
}

func cmdChainStop(_ []string) {
	fmt.Println("chain stop: not implemented")
}

func cmdChainStatus(_ []string) {
	fmt.Println("chain status: not implemented")
}
