package tunnel

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/liberoute/bypath/internal/engine"
	"github.com/liberoute/bypath/internal/geo"
	"github.com/liberoute/bypath/internal/paths"
)

// writeValidGeoRuleSet provisions a minimal but structurally valid binary rule
// set where the generator looks for it. Only the SRS magic matters to the
// validity gate; sing-box itself is not started by these tests.
func writeValidGeoRuleSet(t *testing.T, kind, name string) {
	t.Helper()
	writeGeoFixture(t, fmt.Sprintf("%s-%s.srs", kind, name), []byte("SRS\x00stub"))
}

// writeXrayGeoDat provisions a .dat carrying the given category codes, which is
// the shape xray checks before it accepts a geoip:/geosite: rule.
func writeXrayGeoDat(t *testing.T, name string, codes []string) {
	t.Helper()
	var buf bytes.Buffer
	for _, code := range codes {
		var body bytes.Buffer
		body.WriteByte(0x0a)
		writeTestVarint(&body, len(code))
		body.WriteString(code)
		// xray's asset lookup ignores files under 1000 bytes, so each entry
		// carries a filler field the scanner skips.
		body.WriteByte(0x12)
		writeTestVarint(&body, 1200)
		body.Write(make([]byte, 1200))
		buf.WriteByte(0x0a)
		writeTestVarint(&buf, body.Len())
		buf.Write(body.Bytes())
	}
	writeGeoFixture(t, name, buf.Bytes())
}

func writeGeoFixture(t *testing.T, name string, data []byte) {
	t.Helper()
	dir := paths.Get().GeoDir
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if _, err := os.Stat(path); err == nil {
		// Tracked fixtures already provide this asset; they must be loadable,
		// because the generator only accepts validated rule sets now.
		if geo.ValidSRSFile(path) {
			return
		}
		t.Fatalf("%s exists but is not a valid rule set", path)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(path) })
}

func writeTestVarint(buf *bytes.Buffer, n int) {
	for n >= 0x80 {
		buf.WriteByte(byte(n&0x7f) | 0x80)
		n >>= 7
	}
	buf.WriteByte(byte(n))
}

// writeBrokenGeoFixture leaves a file where a rule set belongs but gives it
// content sing-box cannot load.
func writeBrokenGeoFixture(t *testing.T, name string) {
	t.Helper()
	writeGeoFixture(t, name, []byte("<html>error page served with 200</html>"))
}

// TestSingbox_MissingGeoipAsset_StaysProxied is the fail-closed contract: a
// whitelist country with no usable geoip asset gets no DIRECT rule and no
// dangling rule_set definition. Its traffic falls through to the proxy.
func TestSingbox_MissingGeoipAsset_StaysProxied(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.WhitelistCountries = []string{"zz"}

	cfg := loadJSON(t, mustGenerateSingBox(t, cg))
	for _, r := range getSingboxRules(t, cfg) {
		if rs, ok := r["rule_set"].([]interface{}); ok {
			for _, tag := range rs {
				if tag == "geoip-zz" {
					t.Fatalf("missing geoip asset still produced a rule: %v", r)
				}
			}
		}
	}
	if defs, ok := cfg["route"].(map[string]interface{})["rule_set"]; ok {
		for _, defRaw := range defs.([]interface{}) {
			if def, ok := defRaw.(map[string]interface{}); ok && def["tag"] == "geoip-zz" {
				t.Fatalf("missing geoip asset still produced a definition: %v", def)
			}
		}
	}
}

// TestSingbox_BrokenGeoAssets_DroppedFromRulesAndDNS covers a truncated or
// non-binary asset: existence alone is not enough, because sing-box refuses the
// whole config when a referenced rule set cannot be loaded.
func TestSingbox_BrokenGeoAssets_DroppedFromRulesAndDNS(t *testing.T) {
	writeBrokenGeoFixture(t, "geoip-zz.srs")
	writeBrokenGeoFixture(t, "geosite-zz.srs")

	cg := NewConfigGenerator(t.TempDir())
	cg.GatewayMode = true
	cg.DNSPort = 53
	cg.WhitelistCountries = []string{"zz"}
	cg.GeositeCountries = []string{"zz"}

	cfg := loadJSON(t, mustGenerateSingBox(t, cg))

	defined := map[string]bool{}
	if route, ok := cfg["route"].(map[string]interface{}); ok {
		if defs, ok := route["rule_set"].([]interface{}); ok {
			for _, defRaw := range defs {
				if def, ok := defRaw.(map[string]interface{}); ok {
					if tag, _ := def["tag"].(string); tag != "" {
						defined[tag] = true
					}
				}
			}
		}
		for _, r := range getSingboxRules(t, cfg) {
			for _, tag := range ruleSetRefs(r) {
				if tag == "geoip-zz" || tag == "geosite-zz" {
					t.Fatalf("broken asset still produced a route rule: %v", r)
				}
			}
		}
	}

	dns, ok := cfg["dns"].(map[string]interface{})
	if !ok {
		t.Fatal("missing dns section")
	}
	dnsRules, _ := dns["rules"].([]interface{})
	for _, raw := range dnsRules {
		rule, _ := raw.(map[string]interface{})
		for _, tag := range ruleSetRefs(rule) {
			if !defined[tag] {
				t.Fatalf("DNS rule references undefined rule_set %q", tag)
			}
		}
	}
}

// TestXray_MissingGeoipCategory_SkipsRule keeps the xray path fail-closed too:
// xray aborts startup when a rule names a category its geoip.dat lacks.
func TestXray_MissingGeoipCategory_SkipsRule(t *testing.T) {
	writeXrayGeoDat(t, "geoip.dat", []string{"AA"})

	cg := NewConfigGenerator(t.TempDir())
	cg.WhitelistCountries = []string{"aa", "zz"}

	eng := &engine.Engine{Name: "xray"}
	configFile, err := cg.Generate(eng, testVlessLink())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	rules := getXrayRules(t, loadJSON(t, configFile))

	sawAA, sawZZ := false, false
	for _, r := range rules {
		for _, ip := range stringList(r["ip"]) {
			switch ip {
			case "geoip:aa":
				sawAA = true
			case "geoip:zz":
				sawZZ = true
			}
		}
	}
	if !sawAA {
		t.Fatal("geoip:aa rule missing although the category is present")
	}
	if sawZZ {
		t.Fatal("geoip:zz rule emitted although the category is absent")
	}
}

func mustGenerateSingBox(t *testing.T, cg *ConfigGenerator) string {
	t.Helper()
	path, err := cg.generateSingBox(testVlessLink())
	if err != nil {
		t.Fatalf("generateSingBox: %v", err)
	}
	return path
}

func ruleSetRefs(rule map[string]interface{}) []string {
	return stringList(rule["rule_set"])
}

func stringList(v interface{}) []string {
	raw, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
