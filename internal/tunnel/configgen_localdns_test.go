package tunnel

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/liberoute/bypath/internal/engine"
	"github.com/liberoute/bypath/internal/profile"
)

// A dns rule may only reference a server tag the same config defines.
func TestGenerateSingBoxLocalDNSServerIsDefined(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.GatewayMode = true
	cg.LocalDNSRules = localDNSFixtureRules()
	assertLocalDNSConfig(t, cg)
}

// The routing-rules builder is the one gateway mode uses; it must also pin the
// local suffix to its own server before the catch-all resolver.
func TestGenerateSingBoxLocalDNSResolveWithRoutingRules(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.GatewayMode = true
	cg.RoutingRules = []RoutingRule{{Match: "default", Outbound: "proxy"}}
	cg.LocalDNSRules = localDNSFixtureRules()
	assertLocalDNSConfig(t, cg)
}

func localDNSFixtureRules() []LocalDNSRule {
	return []LocalDNSRule{
		{Server: "192.0.2.53", Domains: []string{"home", "lan"}},
		{Server: "10.0.0.53", Domains: []string{"corp"}},
	}
}

type localDNSRouteRule struct {
	Action       string   `json:"action"`
	Server       string   `json:"server"`
	Invert       bool     `json:"invert"`
	DomainSuffix []string `json:"domain_suffix"`
}

func assertLocalDNSConfig(t *testing.T, cg *ConfigGenerator) {
	t.Helper()
	eng := &engine.Engine{Name: "sing-box"}
	link := &profile.Link{
		Protocol: "vmess",
		Address:  "192.0.2.4",
		Port:     443,
		UUID:     "test-uuid",
		Security: "auto",
	}

	configFile, err := cg.Generate(eng, link)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	raw, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var doc struct {
		DNS struct {
			Servers []struct {
				Tag    string `json:"tag"`
				Type   string `json:"type"`
				Server string `json:"server"`
			} `json:"servers"`
			Rules []struct {
				DomainSuffix []string `json:"domain_suffix"`
				Server       string   `json:"server"`
			} `json:"rules"`
			Final string `json:"final"`
		} `json:"dns"`
		Route struct {
			Rules []localDNSRouteRule `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse config: %v", err)
	}

	tags := map[string]bool{}
	for _, s := range doc.DNS.Servers {
		tags[s.Tag] = true
	}
	for i, want := range []string{"192.0.2.53", "10.0.0.53"} {
		tag := localDNSTag(i)
		if !tags[tag] {
			t.Fatalf("%s server missing from generated config: tags=%v", tag, tags)
		}
		found := false
		for _, s := range doc.DNS.Servers {
			if s.Tag == tag && s.Server == want && s.Type == "udp" {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s must be a udp server for %s, got %+v", tag, want, doc.DNS.Servers)
		}
	}
	if len(doc.DNS.Rules) == 0 || doc.DNS.Rules[0].Server != "dns-local-0" {
		t.Fatalf("local_dns rule must come first and reference dns-local-0: %+v", doc.DNS.Rules)
	}
	for _, r := range doc.DNS.Rules {
		if !tags[r.Server] {
			t.Fatalf("rule references undefined dns server %q (tags=%v)", r.Server, tags)
		}
	}
	if !tags[doc.DNS.Final] {
		t.Fatalf("final dns server %q is not defined (tags=%v)", doc.DNS.Final, tags)
	}

	// Connection-time resolution runs the route resolve actions, not the DNS
	// rules, so the local suffix must be pinned to its server before the
	// catch-all resolver.
	localResolve := map[string]int{}
	catchAllAt := -1
	var catchAll *localDNSRouteRule
	for i := range doc.Route.Rules {
		r := &doc.Route.Rules[i]
		if r.Action != "resolve" {
			continue
		}
		if !tags[r.Server] {
			t.Fatalf("route resolve references undefined dns server %q (tags=%v)", r.Server, tags)
		}
		if strings.HasPrefix(r.Server, "dns-local-") {
			localResolve[r.Server] = i
			continue
		}
		if catchAllAt < 0 {
			catchAllAt, catchAll = i, r
		}
	}
	for i := range cg.LocalDNSRules {
		tag := localDNSTag(i)
		if _, ok := localResolve[tag]; !ok {
			t.Fatalf("no route resolve rule for %s: %+v", tag, doc.Route.Rules)
		}
	}
	if catchAllAt < 0 {
		t.Fatalf("no catch-all resolve rule: %+v", doc.Route.Rules)
	}

	// The catch-all re-resolves the destination, so it must skip the suffixes
	// that a local resolver already answered.
	for tag, at := range localResolve {
		if catchAllAt < at {
			t.Fatalf("catch-all resolve rule precedes the %s resolve rule: %+v", tag, doc.Route.Rules)
		}
	}
	if !catchAll.Invert {
		t.Fatalf("catch-all resolve must invert the local suffix match: %+v", *catchAll)
	}
	want := []string{"home", "lan", "corp"}
	if !reflect.DeepEqual(catchAll.DomainSuffix, want) {
		t.Fatalf("catch-all resolve must exclude all local suffixes %v, got %v", want, catchAll.DomainSuffix)
	}
}
