package gateway

import (
	"testing"

	"github.com/liberoute/bypath/internal/config"
)

// TestEngineConfigGeneratorCarriesCountrySplit pins the runtime wiring: the
// split policy must reach the engine generator with and without explicit
// routing.rules. Missing this left the engine proxying traffic the panel
// already reported as direct.
func TestEngineConfigGeneratorCarriesCountrySplit(t *testing.T) {
	tests := []struct {
		name    string
		rules   []config.RoutingRule
		country string
		want    []string
	}{
		{
			name:    "split with whitelist routing",
			country: "ir",
			want:    []string{"builtin", "probe", "country-split", "country-split", "default"},
		},
		{
			name:    "split with explicit rules",
			country: "ir",
			rules:   []config.RoutingRule{{Match: "domain_suffix:example.com", Outbound: "proxy"}},
			want:    []string{"builtin", "probe", "rule", "country-split", "country-split", "default"},
		},
		{
			name: "no split keeps proxy-only plan",
			want: []string{"builtin", "probe", "default"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Routing.CountrySplit = tt.country
			cfg.Routing.Rules = tt.rules

			gw := &Gateway{config: cfg, socksPort: 2801, dnsPort: 53}
			cg := gw.engineConfigGenerator(nil)
			if cg.CountrySplit != tt.country {
				t.Fatalf("generator CountrySplit = %q, want %q", cg.CountrySplit, tt.country)
			}

			plan := cg.SingboxRoutingPlan()
			scopes := make([]string, len(plan))
			for i, entry := range plan {
				scopes[i] = entry.Scope
				if entry.Scope != "country-split" {
					continue
				}
				if entry.Outbound != "direct" {
					t.Errorf("country-split %s outbound = %q, want direct", entry.Kind, entry.Outbound)
				}
			}
			if len(scopes) != len(tt.want) {
				t.Fatalf("plan scopes = %v, want %v", scopes, tt.want)
			}
			for i := range tt.want {
				if scopes[i] != tt.want[i] {
					t.Fatalf("plan scopes = %v, want %v", scopes, tt.want)
				}
			}
			if tt.country != "" {
				geosite, geoip := plan[len(plan)-3], plan[len(plan)-2]
				if geosite.Kind != "geosite" || geosite.Value != tt.country {
					t.Errorf("first split entry = %s:%s, want geosite:%s", geosite.Kind, geosite.Value, tt.country)
				}
				if geoip.Kind != "geoip" || geoip.Value != tt.country {
					t.Errorf("second split entry = %s:%s, want geoip:%s", geoip.Kind, geoip.Value, tt.country)
				}
			}
		})
	}
}
