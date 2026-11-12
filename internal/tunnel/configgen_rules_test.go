package tunnel

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/liberoute/bypath/internal/engine"
)

func writeVarintBytes(buf *bytes.Buffer, n int) {
	for n >= 0x80 {
		buf.WriteByte(byte(n&0x7f) | 0x80)
		n >>= 7
	}
	buf.WriteByte(byte(n))
}

// buildXrayDat writes a minimal v2fly-style category list. The filler keeps the
// file above the size threshold the availability check applies.
func buildXrayDat(codes []string, filler int) []byte {
	var buf bytes.Buffer
	for _, code := range codes {
		var body bytes.Buffer
		body.WriteByte(0x0a)
		writeVarintBytes(&body, len(code))
		body.WriteString(code)
		if filler > 0 {
			body.WriteByte(0x12)
			writeVarintBytes(&body, filler)
			body.Write(make([]byte, filler))
		}
		buf.WriteByte(0x0a)
		writeVarintBytes(&buf, body.Len())
		buf.Write(body.Bytes())
	}
	return buf.Bytes()
}

// installGeoDat stages a fake geo database in the local-mode engine directory
// for the duration of the test.
func installGeoDat(t *testing.T, name string, codes []string) {
	t.Helper()
	t.Chdir(t.TempDir())
	if err := os.MkdirAll("./engines", 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("./engines", name), buildXrayDat(codes, 1600), 0644); err != nil {
		t.Fatal(err)
	}
}

func ruleByDomain(rules []map[string]interface{}, domain string) map[string]interface{} {
	for _, r := range rules {
		if ds, ok := r["domain_suffix"].([]interface{}); ok {
			for _, d := range ds {
				if d == domain {
					return r
				}
			}
		}
		if ds, ok := r["domain"].([]interface{}); ok {
			for _, d := range ds {
				if d == "domain:"+domain || d == domain {
					return r
				}
			}
		}
	}
	return nil
}

func ruleHasIP(rules []map[string]interface{}, want string) map[string]interface{} {
	for _, r := range rules {
		ips, ok := r["ip"].([]interface{})
		if !ok {
			continue
		}
		for _, ip := range ips {
			if ip == want {
				return r
			}
		}
	}
	return nil
}

func TestSingboxRules_CountryDirectAndForeignProxy(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.RoutingRules = []RoutingRule{
		{Match: "domain_suffix:de", Outbound: "direct"},
		{Match: "geoip:de", Outbound: "direct"},
		{Match: "domain_suffix:blocked.example", Outbound: "proxy"},
		{Match: "default", Outbound: "proxy"},
	}
	path, err := cg.generateSingBox(testVlessLink())
	if err != nil {
		t.Fatalf("generateSingBox: %v", err)
	}
	cfg := loadJSON(t, path)
	route := cfg["route"].(map[string]interface{})
	if route["final"] != "proxy" {
		t.Fatalf("route.final = %v, want proxy", route["final"])
	}
	rules := getSingboxRules(t, cfg)
	ir := ruleByDomain(rules, "de")
	if ir == nil {
		t.Fatal("domain_suffix:de rule missing")
	}
	if ir["outbound"] != "direct" || ir["action"] != "route" {
		t.Fatalf("domain_suffix:de = %v, want route/direct", ir)
	}
	forced := ruleByDomain(rules, "blocked.example")
	if forced == nil || forced["outbound"] != "proxy" {
		t.Fatalf("force-proxy rule missing or not proxy: %v", forced)
	}
}

func TestSingboxRules_OrderPreservesForceProxyBeforeGeoipDirect(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.RoutingRules = []RoutingRule{
		{Match: "domain_suffix:forced.example", Outbound: "proxy"},
		{Match: "geoip:de", Outbound: "direct"},
		{Match: "default", Outbound: "proxy"},
	}
	path, err := cg.generateSingBox(testVlessLink())
	if err != nil {
		t.Fatalf("generateSingBox: %v", err)
	}
	rules := getSingboxRules(t, loadJSON(t, path))
	forcedIdx, geoIdx := -1, -1
	for i, r := range rules {
		if ds, ok := r["domain_suffix"].([]interface{}); ok {
			for _, d := range ds {
				if d == "forced.example" && r["outbound"] == "proxy" {
					forcedIdx = i
				}
			}
		}
		if rs, ok := r["rule_set"].([]interface{}); ok && len(rs) > 0 && rs[0] == "geoip-de" {
			geoIdx = i
		}
	}
	if forcedIdx == -1 {
		t.Fatal("force-proxy rule missing")
	}
	if geoIdx != -1 && forcedIdx >= geoIdx {
		t.Fatalf("force-proxy rule (idx %d) must precede geoip:de direct (idx %d)", forcedIdx, geoIdx)
	}
}

func TestSingboxRules_DenyBecomesReject(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.RoutingRules = []RoutingRule{
		{Match: "domain_suffix:ads.example", Outbound: "deny"},
		{Match: "default", Outbound: "proxy"},
	}
	path, err := cg.generateSingBox(testVlessLink())
	if err != nil {
		t.Fatalf("generateSingBox: %v", err)
	}
	r := ruleByDomain(getSingboxRules(t, loadJSON(t, path)), "ads.example")
	if r == nil {
		t.Fatal("deny rule missing")
	}
	if r["action"] != "reject" {
		t.Fatalf("deny rule action = %v, want reject", r["action"])
	}
	if _, has := r["outbound"]; has {
		t.Fatalf("deny rule must not carry an outbound: %v", r)
	}
}

func TestSingboxRules_DefaultDenyRejectsUnmatched(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.RoutingRules = []RoutingRule{
		{Match: "domain_suffix:de", Outbound: "direct"},
		{Match: "default", Outbound: "block"},
	}
	path, err := cg.generateSingBox(testVlessLink())
	if err != nil {
		t.Fatalf("generateSingBox: %v", err)
	}
	cfg := loadJSON(t, path)
	route := cfg["route"].(map[string]interface{})
	rules := getSingboxRules(t, cfg)
	if len(rules) == 0 {
		t.Fatal("no rules")
	}
	last := rules[len(rules)-1]
	if last["action"] != "reject" {
		t.Fatalf("last rule = %v, want a matcher-less reject", last)
	}
	if _, has := last["outbound"]; has {
		t.Fatalf("catch-all reject must not name an outbound: %v", last)
	}
	if route["final"] != "proxy" {
		t.Fatalf("route.final = %v; a denied default still needs a defined final tag", route["final"])
	}
}

func TestXrayRules_DenyUsesBlackholeOutbound(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.RoutingRules = []RoutingRule{
		{Match: "domain_suffix:ads.example", Outbound: "block"},
		{Match: "default", Outbound: "proxy"},
	}
	path, err := cg.Generate(&engine.Engine{Name: "xray"}, testVlessLink())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	cfg := loadJSON(t, path)
	r := ruleByDomain(getXrayRules(t, cfg), "ads.example")
	if r == nil || r["outboundTag"] != xrayBlockOutboundTag {
		t.Fatalf("deny rule = %v, want outboundTag %q", r, xrayBlockOutboundTag)
	}
	outbounds := cfg["outbounds"].([]interface{})
	found := false
	for _, raw := range outbounds {
		ob := raw.(map[string]interface{})
		if ob["tag"] == xrayBlockOutboundTag && ob["protocol"] == "blackhole" {
			found = true
		}
	}
	if !found {
		t.Fatal("xray config has no blackhole outbound tagged block")
	}
}

func TestXrayRules_DefaultDenyCatchAll(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.RoutingRules = []RoutingRule{
		{Match: "domain_suffix:de", Outbound: "direct"},
		{Match: "default", Outbound: "deny"},
	}
	path, err := cg.Generate(&engine.Engine{Name: "xray"}, testVlessLink())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	rules := getXrayRules(t, loadJSON(t, path))
	last := rules[len(rules)-1]
	if last["outboundTag"] != xrayBlockOutboundTag {
		t.Fatalf("catch-all = %v, want outboundTag %q", last, xrayBlockOutboundTag)
	}
}

func TestXrayRules_GeoipSkippedWhenDatabaseMissing(t *testing.T) {
	t.Chdir(t.TempDir())
	cg := NewConfigGenerator(t.TempDir())
	cg.RoutingRules = []RoutingRule{
		{Match: "geoip:zz", Outbound: "direct"},
		{Match: "default", Outbound: "proxy"},
	}
	path, err := cg.Generate(&engine.Engine{Name: "xray"}, testVlessLink())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	rules := getXrayRules(t, loadJSON(t, path))
	if r := ruleHasIP(rules, "geoip:zz"); r != nil {
		t.Fatalf("geoip rule emitted without a database: %v", r)
	}
	last := rules[len(rules)-1]
	if last["outboundTag"] != "proxy" {
		t.Fatalf("catch-all = %v, want proxy", last)
	}
}

func TestXrayRules_GeoipDirectWhenDatabaseHasCategory(t *testing.T) {
	installGeoDat(t, "geoip.dat", []string{"DE", "US"})
	cg := NewConfigGenerator(t.TempDir())
	cg.RoutingRules = []RoutingRule{
		{Match: "geoip:de", Outbound: "direct"},
		{Match: "default", Outbound: "proxy"},
	}
	path, err := cg.Generate(&engine.Engine{Name: "xray"}, testVlessLink())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	r := ruleHasIP(getXrayRules(t, loadJSON(t, path)), "geoip:de")
	if r == nil {
		t.Fatal("geoip:de rule missing although geoip.dat has DE")
	}
	if r["outboundTag"] != "direct" {
		t.Fatalf("geoip:de outboundTag = %v, want direct", r["outboundTag"])
	}
}

func TestXrayRules_GeoipSkippedWhenCategoryAbsent(t *testing.T) {
	installGeoDat(t, "geoip.dat", []string{"US"})
	cg := NewConfigGenerator(t.TempDir())
	cg.RoutingRules = []RoutingRule{
		{Match: "geoip:de", Outbound: "direct"},
		{Match: "default", Outbound: "proxy"},
	}
	path, err := cg.Generate(&engine.Engine{Name: "xray"}, testVlessLink())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if r := ruleHasIP(getXrayRules(t, loadJSON(t, path)), "geoip:de"); r != nil {
		t.Fatal("geoip:de was emitted although the database has no DE category (xray would refuse to start)")
	}
}

func TestXrayRules_GeositeGuardedByCategory(t *testing.T) {
	installGeoDat(t, "geosite.dat", []string{"de"})
	cg := NewConfigGenerator(t.TempDir())
	cg.RoutingRules = []RoutingRule{
		{Match: "geosite:de", Outbound: "direct"},
		{Match: "geosite:missing", Outbound: "direct"},
		{Match: "default", Outbound: "proxy"},
	}
	path, err := cg.Generate(&engine.Engine{Name: "xray"}, testVlessLink())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	rules := getXrayRules(t, loadJSON(t, path))
	foundCountry, foundMissing := false, false
	for _, r := range rules {
		ds, ok := r["domain"].([]interface{})
		if !ok {
			continue
		}
		for _, d := range ds {
			if d == "geosite:de" {
				foundCountry = true
			}
			if d == "geosite:missing" {
				foundMissing = true
			}
		}
	}
	if !foundCountry {
		t.Fatal("geosite:de rule missing although geosite.dat has the tag")
	}
	if foundMissing {
		t.Fatal("geosite:missing rule emitted although the tag is absent (xray would refuse to start)")
	}
}
