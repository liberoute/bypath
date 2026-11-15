package config

import (
	"path/filepath"
	"testing"
)

// TestShippedDefaultRoutingPolicy pins the routing policy that ships in
// configs/default.yaml: exactly one catch-all rule that sends unmatched traffic
// through the tunnel. A fresh install carries no country, domain or address
// exception, so nothing about the operator's location or network is assumed.
func TestShippedDefaultRoutingPolicy(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "configs", "default.yaml"))
	if err != nil {
		t.Fatalf("Load default.yaml: %v", err)
	}

	if cfg.Routing.CountrySplit != "" {
		t.Fatalf("shipped config enables country_split %q; split routing must stay opt-in", cfg.Routing.CountrySplit)
	}

	want := []RoutingRule{{Match: "default", Outbound: "proxy"}}
	got := cfg.Routing.Rules
	if len(got) != len(want) {
		t.Fatalf("routing.rules has %d entries, want exactly %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("routing.rules[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}
