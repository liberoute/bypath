package gateway

import (
	"testing"

	"github.com/liberoute/bypath/internal/config"
)

// TestRoutingChangedDetectsCountrySplit pins the reload diff against the field
// the split toggle writes. A settings/restore reload that only changes
// routing.country_split used to report "all changes applied" while the engine
// kept the previous policy.
func TestRoutingChangedDetectsCountrySplit(t *testing.T) {
	off := &config.Config{}
	on := &config.Config{}
	on.Routing.CountrySplit = "ir"

	if !routingChanged(off, on) {
		t.Fatal("enabling country_split was not detected as a routing change")
	}
	if !routingChanged(on, off) {
		t.Fatal("disabling country_split was not detected as a routing change")
	}
	if routingChanged(off, &config.Config{}) {
		t.Fatal("identical configurations reported a routing change")
	}

	// A change of country is a policy change too.
	other := &config.Config{}
	other.Routing.CountrySplit = "de"
	if !routingChanged(on, other) {
		t.Fatal("changing the split country was not detected")
	}
}

// TestReloadReportsCountrySplitRestart is the end-to-end half of the same
// contract: the reload response must name the restart, because the running
// engine cannot republish a compiled routing plan.
func TestReloadReportsCountrySplitRestart(t *testing.T) {
	oldCfg := &config.Config{}
	gw := &Gateway{config: oldCfg}

	newCfg := &config.Config{}
	newCfg.Routing.CountrySplit = "ir"

	restart := gw.Reload(newCfg)
	found := false
	for _, field := range restart {
		if field == "routing" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Reload(country_split) = %v, want a routing restart", restart)
	}
	if oldCfg.Routing.CountrySplit != "ir" {
		t.Fatalf("gateway config was not updated: country_split = %q", oldCfg.Routing.CountrySplit)
	}
}

// TestReloadWithoutRoutingChangeReportsNothing keeps the other direction
// honest: an unrelated edit must not force an engine restart.
func TestReloadWithoutRoutingChangeReportsNothing(t *testing.T) {
	oldCfg := &config.Config{}
	gw := &Gateway{config: oldCfg}

	newCfg := &config.Config{}
	newCfg.HealthCheck.URL = "https://example.net/health"

	if restart := gw.Reload(newCfg); len(restart) != 0 {
		t.Fatalf("Reload(unrelated change) = %v, want none", restart)
	}
}
