package engine

import "testing"

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"26.10.31", "26.3.27", 1},
		{"26.3.27", "26.3.27", 0},
		{"25.1.1", "26.3.27", -1},
		{"1.14", "1.14.0", 0},
		{"1.13.9", "1.14.0", -1},
		{"2.0.0", "1.99.99", 1},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestVersionTokenExtraction(t *testing.T) {
	cases := map[string]string{
		"Xray 26.10.31 (Xray, Penetration Test)":               "26.10.31",
		"sing-box version 1.14.4":                              "1.14.4",
		"Xray 1.8.24\nA unified platform for anti-censorship.": "1.8.24",
		"sing-box version 1.13.0-beta.4":                       "1.13.0",
	}
	for raw, want := range cases {
		m := versionToken.FindStringSubmatch(raw)
		if m == nil || m[1] != want {
			t.Errorf("version token of %q = %v, want %q", raw, m, want)
		}
	}
}

func TestRequireVersionSkipsDescriptors(t *testing.T) {
	// Tests and embedded modules use descriptors without a binary path.
	if err := (&Engine{Name: "xray"}).RequireVersion("26.3.27"); err != nil {
		t.Fatalf("descriptor engine should skip the probe: %v", err)
	}
	if err := (&Engine{Name: "xray"}).RequireVersion("999.0.0"); err != nil {
		t.Fatalf("descriptor engine should skip the probe: %v", err)
	}
}
