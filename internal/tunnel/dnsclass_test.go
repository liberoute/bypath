package tunnel

import "testing"

func newSplitClassifier(t *testing.T, cg *ConfigGenerator) *NameClassifier {
	t.Helper()
	return cg.NameClassifier("sing-box")
}

// TestNameClassifier_PlanOrder pins first-match-wins: a direct rule, the split
// geosite class and the default each decide their own names, and a look-alike
// host does not inherit a suffix rule.
func TestNameClassifier_PlanOrder(t *testing.T) {
	writeValidGeoRuleSet(t, "geosite", "ir")
	writeValidGeoRuleSet(t, "geoip", "ir")

	cg := NewConfigGenerator(t.TempDir())
	cg.CountrySplit = "ir"
	cg.RoutingRules = []RoutingRule{
		{Match: "domain:portal.example", Outbound: "direct"},
		{Match: "domain_suffix:shop.example", Outbound: "direct"},
		{Match: "domain_suffix:blocked.example", Outbound: "proxy"},
		{Match: "default", Outbound: "proxy"},
	}
	c := newSplitClassifier(t, cg)

	cases := map[string]NameClass{
		"portal.example":          NameClassDirect,
		"www.shop.example":        NameClassDirect,
		"blocked.example":         NameClassProxy,
		"www.blocked.example":     NameClassProxy,
		"ir.example":              NameClassDirect,
		"news.ir.example":         NameClassDirect,
		"other.example":           NameClassProxy,
		"lookalikeportal.example": NameClassProxy,
	}
	for host, want := range cases {
		if got := c.Classify(host); got != want {
			t.Errorf("Classify(%q) = %q, want %q", host, got, want)
		}
	}
}

// TestNameClassifier_UserRuleBeatsSplit keeps the generator's order: an explicit
// rule before the split decides a name even when the split class would too.
func TestNameClassifier_UserRuleBeatsSplit(t *testing.T) {
	writeValidGeoRuleSet(t, "geosite", "ir")
	writeValidGeoRuleSet(t, "geoip", "ir")

	cg := NewConfigGenerator(t.TempDir())
	cg.CountrySplit = "ir"
	cg.RoutingRules = []RoutingRule{
		{Match: "domain_suffix:proxy.ir.example", Outbound: "proxy"},
		{Match: "default", Outbound: "proxy"},
	}
	c := newSplitClassifier(t, cg)

	if got := c.Classify("a.proxy.ir.example"); got != NameClassProxy {
		t.Fatalf("explicit proxy rule lost to the split: %q", got)
	}
	if got := c.Classify("b.ir.example"); got != NameClassDirect {
		t.Fatalf("split class = %q, want direct", got)
	}
}

// TestNameClassifier_MissingSplitAssetKeepsProxy is the fail-closed contract: a
// missing rule set produces no direct class, so its names stay on the tunnel.
func TestNameClassifier_MissingSplitAssetKeepsProxy(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.CountrySplit = "qq"
	cg.RoutingRules = []RoutingRule{{Match: "default", Outbound: "proxy"}}
	c := newSplitClassifier(t, cg)

	for _, host := range []string{"qq.example", "anything.example"} {
		if got := c.Classify(host); got != NameClassProxy {
			t.Errorf("Classify(%q) = %q, want proxy", host, got)
		}
	}
}

// TestNameClassifier_DenyAndDirectDefault covers the non-proxy finals the
// gateway must not confuse with a direct path.
func TestNameClassifier_DenyAndDirectDefault(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.RoutingRules = []RoutingRule{
		{Match: "domain_suffix:corp.example", Outbound: "deny"},
		{Match: "domain_suffix:portal.example", Outbound: "proxy"},
		{Match: "default", Outbound: "direct"},
	}
	c := newSplitClassifier(t, cg)

	if got := c.Classify("host.corp.example"); got != NameClassBlock {
		t.Errorf("deny rule class = %q, want block", got)
	}
	if got := c.Classify("portal.example"); got != NameClassProxy {
		t.Errorf("proxy rule class = %q, want proxy", got)
	}
	if got := c.Classify("elsewhere.example"); got != NameClassDirect {
		t.Errorf("default class = %q, want direct", got)
	}
}

// TestNameClassifier_XrayDat covers the .dat engine: the classifier reads
// geosite.dat the way xray loads it, so a DIRECT geosite rule keeps its names on
// the direct resolver.
func TestNameClassifier_XrayDat(t *testing.T) {
	writeXrayGeoDat(t, "geosite.dat", []string{"CATEGORY-IR"})

	cg := NewConfigGenerator(t.TempDir())
	cg.RoutingRules = []RoutingRule{
		{Match: "geosite:CATEGORY-IR", Outbound: "direct"},
		{Match: "default", Outbound: "proxy"},
	}
	c := cg.NameClassifier("xray")

	if got := c.Classify("news.category-ir.example"); got != NameClassDirect {
		t.Errorf("xray geosite class = %q, want direct", got)
	}
	if got := c.Classify("example.com"); got != NameClassProxy {
		t.Errorf("xray default class = %q, want proxy", got)
	}
}
