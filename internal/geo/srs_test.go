package geo

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func writeRuleSet(t *testing.T, options option.DefaultHeadlessRule) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.srs")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	set := option.PlainRuleSet{Rules: []option.HeadlessRule{{
		Type:           C.RuleTypeDefault,
		DefaultOptions: options,
	}}}
	if err := srs.Write(file, set, C.RuleSetVersionCurrent); err != nil {
		t.Fatalf("write rule set: %v", err)
	}
	return path
}

// TestRuleSetNestedSuffixMatchesSubdomains pins the matcher to sing-box: a
// published ".ir" entry routes every host under .ir and is why irna.ir is
// DIRECT even though the list has no explicit irna.ir entry.
func TestRuleSetNestedSuffixMatchesSubdomains(t *testing.T) {
	set, err := LoadSRS(writeRuleSet(t, option.DefaultHeadlessRule{
		DomainSuffix: []string{".ir", "varzesh3.com"},
	}))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	cases := map[string]bool{
		"irna.ir":              true,
		"www.irna.ir":          true,
		"IRNA.IR":              true,
		"varzesh3.com":         true,
		"www.varzesh3.com":     true,
		"ir":                   false,
		"notiran.com":          false,
		"example.com":          false,
		"varzesh3.com.evil.io": false,
	}
	for host, want := range cases {
		if got := set.MatchDomain(host); got != want {
			t.Errorf("MatchDomain(%q) = %v, want %v", host, got, want)
		}
	}
	if !set.Complete() {
		t.Fatal("plain suffix list should be complete")
	}
}

func TestRuleSetKeywordListsAreIncomplete(t *testing.T) {
	set, err := LoadSRS(writeRuleSet(t, option.DefaultHeadlessRule{
		DomainKeyword: []string{"bank"},
	}))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if set.Complete() {
		t.Fatal("keyword entries must mark a negative answer as inconclusive")
	}
}

func TestRuleSetMatchesIPPrefixes(t *testing.T) {
	set, err := LoadSRS(writeRuleSet(t, option.DefaultHeadlessRule{
		IPCIDR: []string{"5.22.0.0/16"},
	}))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !set.MatchIP(net.ParseIP("5.22.1.9")) {
		t.Fatal("5.22.1.9 should match 5.22.0.0/16")
	}
	if set.MatchIP(net.ParseIP("8.8.4.4")) {
		t.Fatal("8.8.4.4 should not match 5.22.0.0/16")
	}
}
