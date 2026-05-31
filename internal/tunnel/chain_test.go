package tunnel

import (
	"testing"

	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/engine"
	"github.com/liberoute/bypath/internal/profile"
)

// newTestManager creates a minimal tunnel Manager for testing resolveChainStrategy.
func newTestManager() *Manager {
	cfg := &config.Config{
		Server: config.ServerConfig{SOCKSPort: 2801},
	}
	engMgr := engine.NewManager(config.EnginesConfig{Directory: "."})
	return NewManager(cfg, engMgr)
}

// setupProfilesWithLinks creates a profile.Manager in a temp dir and adds the given links.
func setupProfilesWithLinks(t *testing.T, links map[string]*profile.Link) *profile.Manager {
	t.Helper()
	tmpDir := t.TempDir()

	pm, err := profile.NewManager(tmpDir, "default")
	if err != nil {
		t.Fatalf("creating profile manager: %v", err)
	}

	for remark, link := range links {
		link.Remark = remark
		if err := pm.AddLink("default", link); err != nil {
			t.Fatalf("adding link %s: %v", remark, err)
		}
	}

	return pm
}

func TestResolveChainStrategy_SSHHop(t *testing.T) {
	m := newTestManager()

	// Create profiles with an SSH link and a sing-box link
	profiles := setupProfilesWithLinks(t, map[string]*profile.Link{
		"ssh-relay": {
			Protocol: "ssh",
			Address:  "relay.example.com",
			Port:     22,
			SSHUser:  "root",
			SSHKeyPath: "/path/to/key",
		},
		"vless-exit": {
			Protocol: "vless",
			Address:  "exit.example.com",
			Port:     443,
			UUID:     "test-uuid",
			TLS:      true,
			SNI:      "exit.example.com",
		},
	})

	// Chain with SSH as first hop → must resolve to multi-process
	hops := []config.HopConfig{
		{Profile: "ssh-relay"},
		{Profile: "vless-exit"},
	}

	strategy := m.resolveChainStrategy(hops, profiles)
	if strategy != StrategyMultiProcess {
		t.Errorf("chain with SSH hop: got %q, want %q", strategy, StrategyMultiProcess)
	}
}

func TestResolveChainStrategy_SSHOnlyHop(t *testing.T) {
	m := newTestManager()

	// Chain with only SSH hops
	profiles := setupProfilesWithLinks(t, map[string]*profile.Link{
		"ssh-hop1": {
			Protocol: "ssh",
			Address:  "hop1.example.com",
			Port:     22,
			SSHUser:  "admin",
		},
		"ssh-hop2": {
			Protocol: "ssh",
			Address:  "hop2.example.com",
			Port:     2222,
			SSHUser:  "root",
		},
	})

	hops := []config.HopConfig{
		{Profile: "ssh-hop1"},
		{Profile: "ssh-hop2"},
	}

	strategy := m.resolveChainStrategy(hops, profiles)
	if strategy != StrategyMultiProcess {
		t.Errorf("chain with only SSH hops: got %q, want %q", strategy, StrategyMultiProcess)
	}
}

func TestResolveChainStrategy_SingBoxOnly(t *testing.T) {
	m := newTestManager()

	// Chain with only sing-box compatible protocols → single-process
	profiles := setupProfilesWithLinks(t, map[string]*profile.Link{
		"vmess-hop": {
			Protocol: "vmess",
			Address:  "vmess.example.com",
			Port:     443,
			UUID:     "uuid-vmess",
			Security: "auto",
		},
		"trojan-hop": {
			Protocol: "trojan",
			Address:  "trojan.example.com",
			Port:     443,
			UUID:     "pass-trojan",
			TLS:      true,
			SNI:      "trojan.example.com",
		},
	})

	hops := []config.HopConfig{
		{Profile: "vmess-hop"},
		{Profile: "trojan-hop"},
	}

	strategy := m.resolveChainStrategy(hops, profiles)
	if strategy != StrategySingleProcess {
		t.Errorf("chain with only sing-box protocols: got %q, want %q", strategy, StrategySingleProcess)
	}
}

func TestResolveChainStrategy_SSHMiddleHop(t *testing.T) {
	m := newTestManager()

	// SSH in the middle of a chain → multi-process
	profiles := setupProfilesWithLinks(t, map[string]*profile.Link{
		"vmess-entry": {
			Protocol: "vmess",
			Address:  "entry.example.com",
			Port:     443,
			UUID:     "uuid-entry",
			Security: "auto",
		},
		"ssh-middle": {
			Protocol: "ssh",
			Address:  "middle.example.com",
			Port:     22,
			SSHUser:  "tunnel",
		},
		"vless-exit": {
			Protocol: "vless",
			Address:  "exit.example.com",
			Port:     443,
			UUID:     "uuid-exit",
			TLS:      true,
			SNI:      "exit.example.com",
		},
	})

	hops := []config.HopConfig{
		{Profile: "vmess-entry"},
		{Profile: "ssh-middle"},
		{Profile: "vless-exit"},
	}

	strategy := m.resolveChainStrategy(hops, profiles)
	if strategy != StrategyMultiProcess {
		t.Errorf("chain with SSH in middle: got %q, want %q", strategy, StrategyMultiProcess)
	}
}
