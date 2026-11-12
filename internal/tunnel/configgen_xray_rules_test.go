package tunnel

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/liberoute/bypath/internal/paths"
)

func writeVarint(buf *bytes.Buffer, n int) {
	for n >= 0x80 {
		buf.WriteByte(byte(n&0x7f) | 0x80)
		n >>= 7
	}
	buf.WriteByte(byte(n))
}

func buildDat(codes []string, filler int) []byte {
	var buf bytes.Buffer
	for _, code := range codes {
		var body bytes.Buffer
		body.WriteByte(0x0a)
		writeVarint(&body, len(code))
		body.WriteString(code)
		if filler > 0 {
			body.WriteByte(0x12)
			writeVarint(&body, filler)
			body.Write(make([]byte, filler))
		}
		buf.WriteByte(0x0a)
		writeVarint(&buf, body.Len())
		buf.Write(body.Bytes())
	}
	return buf.Bytes()
}

// useGeoAssets points the path resolver at a throwaway install with the given
// xray databases.
func useGeoAssets(t *testing.T, files map[string][]byte) {
	t.Helper()
	t.Chdir(t.TempDir())
	paths.Reset()
	t.Cleanup(paths.Reset)
	if err := os.MkdirAll("engines", 0o755); err != nil {
		t.Fatal(err)
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join("engines", name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestXrayGeositeRuleUsesInstalledCategorySpelling(t *testing.T) {
	// v2fly's geosite.dat carries "CATEGORY-DE", not "ir"; xray rejects a tag it
	// cannot find, so the rule must reference the spelling present in the file.
	useGeoAssets(t, map[string][]byte{
		"geosite.dat": buildDat([]string{"0X0", "CATEGORY-DE", "CN"}, 1200),
	})
	cg := &ConfigGenerator{}
	rule := cg.xrayRuleFromMatcher("geosite:de", "direct")
	if rule == nil {
		t.Fatal("geosite:de was dropped even though geosite.dat has CATEGORY-DE")
	}
	domains, _ := rule["domain"].([]string)
	if len(domains) != 1 || domains[0] != "geosite:CATEGORY-DE" {
		t.Fatalf("domain = %v, want [geosite:CATEGORY-DE]", domains)
	}
}

func TestXrayGeositeRuleDroppedWhenCategoryMissing(t *testing.T) {
	useGeoAssets(t, map[string][]byte{
		"geosite.dat": buildDat([]string{"CN"}, 1200),
	})
	cg := &ConfigGenerator{}
	if rule := cg.xrayRuleFromMatcher("geosite:de", "direct"); rule != nil {
		t.Fatalf("geosite:de emitted without a matching category: %v", rule)
	}
}

func TestXrayGeoipRuleDroppedWhenDatMissing(t *testing.T) {
	useGeoAssets(t, nil)
	cg := &ConfigGenerator{}
	if rule := cg.xrayRuleFromMatcher("geoip:de", "direct"); rule != nil {
		t.Fatalf("geoip:de emitted without geoip.dat: %v", rule)
	}
}

func TestXrayDenyRuleUsesBlackhole(t *testing.T) {
	useGeoAssets(t, nil)
	cg := &ConfigGenerator{}
	rule := cg.xrayRuleFromMatcher("ip_cidr:203.0.113.12/32", "deny")
	if rule == nil {
		t.Fatal("deny rule dropped")
	}
	if rule["outboundTag"] != xrayBlockOutboundTag {
		t.Fatalf("outboundTag = %v, want %q", rule["outboundTag"], xrayBlockOutboundTag)
	}
}