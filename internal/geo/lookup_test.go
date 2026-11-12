package geo

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func pbKey(buf *bytes.Buffer, num, wire int) {
	writeVarint(buf, num<<3|wire)
}

func pbString(buf *bytes.Buffer, num int, value string) {
	pbKey(buf, num, 2)
	writeVarint(buf, len(value))
	buf.WriteString(value)
}

func pbVarint(buf *bytes.Buffer, num int, value int) {
	pbKey(buf, num, 0)
	writeVarint(buf, value)
}

func pbBytes(buf *bytes.Buffer, num int, value []byte) {
	pbKey(buf, num, 2)
	writeVarint(buf, len(value))
	buf.Write(value)
}

func wrapEntry(body []byte) []byte {
	var buf bytes.Buffer
	pbBytes(&buf, 1, body)
	return buf.Bytes()
}

func geositeEntry(code string, domains ...[2]interface{}) []byte {
	var body bytes.Buffer
	pbString(&body, 1, code)
	for _, d := range domains {
		var sub bytes.Buffer
		pbVarint(&sub, 1, d[0].(int))
		pbString(&sub, 2, d[1].(string))
		pbBytes(&body, 2, sub.Bytes())
	}
	return wrapEntry(body.Bytes())
}

func geoipEntry(code string, ip net.IP, prefix int) []byte {
	var body bytes.Buffer
	pbString(&body, 1, code)
	var cidr bytes.Buffer
	pbBytes(&cidr, 1, ip)
	pbVarint(&cidr, 2, prefix)
	pbBytes(&body, 2, cidr.Bytes())
	return wrapEntry(body.Bytes())
}

func writeGeoSite(t *testing.T, entries ...[]byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "geosite.dat")
	if err := os.WriteFile(path, bytes.Join(entries, nil), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeGeoIP(t *testing.T, entries ...[]byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "geoip.dat")
	if err := os.WriteFile(path, bytes.Join(entries, nil), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLookupGeoSiteMatcherTypes(t *testing.T) {
	path := writeGeoSite(t,
		geositeEntry("de",
			[2]interface{}{2, "shop.example"}, // Domain: suffix at a label boundary
			[2]interface{}{3, "www.exact.example"}, // Full: exact
			[2]interface{}{0, "substring"},    // Plain: substring
			[2]interface{}{1, `^shop..*.example$`},
		),
	)

	cases := []struct {
		domain  string
		matched bool
	}{
		{"shop.example", true},
		{"www.shop.example", true},
		{"notshop.example", false},
		{"www.exact.example", true},
		{"exact.example", false},
		{"any-substring-host.example", true},
		{"shop.mysite.example", true},
		{"example.net", false},
	}
	for _, tc := range cases {
		got, found := LookupGeoSite(path, "de", tc.domain)
		if !found {
			t.Fatalf("category de not found for %q", tc.domain)
		}
		if got != tc.matched {
			t.Errorf("LookupGeoSite(%q) = %v, want %v", tc.domain, got, tc.matched)
		}
	}
}

func TestLookupGeoSiteCategorySpelling(t *testing.T) {
	path := writeGeoSite(t, geositeEntry("CATEGORY-DE", [2]interface{}{2, "legacy.example"}))
	if matched, found := LookupGeoSite(path, "de", "www.legacy.example."); !matched || !found {
		t.Fatalf("CATEGORY-DE lookup = %v, %v", matched, found)
	}
}

func TestLookupGeoSiteMissingCategory(t *testing.T) {
	path := writeGeoSite(t, geositeEntry("cn", [2]interface{}{2, "baidu.com"}))
	if matched, found := LookupGeoSite(path, "de", "shop.example"); matched || found {
		t.Fatalf("missing category reported matched=%v found=%v", matched, found)
	}
	if _, found := LookupGeoSite(filepath.Join(t.TempDir(), "missing.dat"), "de", "shop.example"); found {
		t.Fatal("missing file reported a category")
	}
}

func TestLookupGeoIPContainment(t *testing.T) {
	path := writeGeoIP(t,
		geoipEntry("DE", net.IPv4(198, 51, 100, 0).To4(), 24),
		geoipEntry("US", net.IPv4(8, 8, 8, 0).To4(), 24),
	)
	if matched, found := LookupGeoIP(path, "de", net.ParseIP("198.51.100.4")); !matched || !found {
		t.Fatalf("198.51.100.4 in geoip:de = %v, %v", matched, found)
	}
	if matched, _ := LookupGeoIP(path, "de", net.ParseIP("203.0.113.4")); matched {
		t.Fatal("203.0.113.4 matched geoip:de /24")
	}
	if matched, _ := LookupGeoIP(path, "us", net.ParseIP("8.8.8.8")); !matched {
		t.Fatal("8.8.8.8 did not match geoip:us")
	}
	if _, found := LookupGeoIP(path, "fr", net.ParseIP("8.8.8.8")); found {
		t.Fatal("missing geoip category reported found")
	}
}

func TestLookupGeoIPIPv6(t *testing.T) {
	path := writeGeoIP(t, geoipEntry("DE", net.ParseIP("2001:db8::"), 32))
	if matched, found := LookupGeoIP(path, "de", net.ParseIP("2001:db8::1")); !matched || !found {
		t.Fatalf("IPv6 containment = %v, %v", matched, found)
	}
	if matched, _ := LookupGeoIP(path, "de", net.ParseIP("2001:db9::1")); matched {
		t.Fatal("out-of-prefix IPv6 matched")
	}
}

func TestLookupRejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "geosite.dat")
	if err := os.WriteFile(path, []byte("<html>not a list</html>"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, found := LookupGeoSite(path, "de", "shop.example"); found {
		t.Fatal("garbage file reported a category")
	}
}
