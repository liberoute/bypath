package tunnel

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liberoute/bypath/internal/engine"
	"github.com/liberoute/bypath/internal/geo"
	"github.com/liberoute/bypath/internal/paths"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// writeValidGeoRuleSet provisions a minimal but structurally valid binary rule
// set where the generator looks for it. The content is written by sing-box's
// own writer, because the generator now validates with sing-box's own reader:
// a magic-only stub is no longer a usable asset.
func writeValidGeoRuleSet(t *testing.T, kind, name string) {
	t.Helper()
	writeGeoFixture(t, fmt.Sprintf("%s-%s.srs", kind, name), buildRuleSet(t, kind, name))
}

// buildRuleSet encodes one domain/IP entry so a real parser can load it.
func buildRuleSet(t *testing.T, kind, name string) []byte {
	t.Helper()
	rule := option.HeadlessRule{Type: C.RuleTypeDefault}
	if kind == "geoip" {
		rule.DefaultOptions.IPCIDR = []string{"198.51.100.0/24"}
	} else {
		rule.DefaultOptions.DomainSuffix = []string{name + ".example"}
	}
	var buf bytes.Buffer
	if err := srs.Write(&buf, option.PlainRuleSet{Rules: []option.HeadlessRule{rule}}, C.RuleSetVersionCurrent); err != nil {
		t.Fatalf("encode %s-%s rule set: %v", kind, name, err)
	}
	return buf.Bytes()
}

// writeXrayGeoDat provisions a .dat carrying the given category codes, which is
// the shape xray checks before it accepts a geoip:/geosite: rule.
func writeXrayGeoDat(t *testing.T, name string, codes []string) {
	t.Helper()
	writeGeoFixture(t, name, buildXrayDatFile(name, codes, 1200))
}

// buildXrayDatFile frames one entry per code the way xray's loader reads them:
// field 1 is the category code, field 2 a repeated Domain (geosite) or CIDR
// (geoip) message that is actually parsed, and the size padding rides in an
// unknown high-numbered field the parser never opens. Padding in field 2 is what
// real xray rejects with "cannot parse invalid wire-format data".
func buildXrayDatFile(name string, codes []string, filler int) []byte {
	isIP := strings.Contains(name, "geoip")
	var buf bytes.Buffer
	for i, code := range codes {
		var entry bytes.Buffer
		if isIP {
			entry.WriteByte(0x0a) // CIDR.ip
			writeTestVarint(&entry, 4)
			entry.Write([]byte{198, 51, 100, byte(i + 1)})
			entry.WriteByte(0x10) // CIDR.prefix
			entry.WriteByte(24)
		} else {
			entry.WriteByte(0x12) // Domain.value, type defaults to Plain
			value := strings.ToLower(code) + ".example"
			writeTestVarint(&entry, len(value))
			entry.WriteString(value)
		}

		var body bytes.Buffer
		body.WriteByte(0x0a)
		writeTestVarint(&body, len(code))
		body.WriteString(code)
		body.WriteByte(0x12)
		writeTestVarint(&body, entry.Len())
		body.Write(entry.Bytes())
		if filler > 0 {
			// xray's asset lookup ignores files under 1000 bytes.
			body.Write([]byte{0xa2, 0x06}) // field 100, wire type 2: kept unparsed
			writeTestVarint(&body, filler)
			body.Write(make([]byte, filler))
		}
		buf.WriteByte(0x0a)
		writeTestVarint(&buf, body.Len())
		buf.Write(body.Bytes())
	}
	return buf.Bytes()
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
