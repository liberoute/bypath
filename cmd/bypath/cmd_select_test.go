package main

import (
	"testing"

	"github.com/liberoute/bypath/internal/app"
)

func testLinks(remarks ...string) []app.Connection {
	out := make([]app.Connection, len(remarks))
	for i, r := range remarks {
		out[i] = app.Connection{Remark: r, Group: "yv3"}
	}
	return out
}

// 'bypath list' prints cleanRemark(), so the name an operator copies is not
// the stored remark for profiles that carry a flag emoji or a "provider - "
// prefix. Selecting by that displayed name used to fail with "Link not found".
func TestMatchRemarkAcceptsDisplayedName(t *testing.T) {
	cases := []struct {
		name   string
		links  []app.Connection
		target string
		want   string
	}{
		{"flag emoji prefix", testLinks("🇳🇱 NL-03 1300 [T]"), "NL-03 1300 [T]", "🇳🇱 NL-03 1300 [T]"},
		{"provider prefix", testLinks("Provider - US 1000 [D]"), "US 1000 [D]", "Provider - US 1000 [D]"},
		{"pipe suffix", testLinks("🇩🇪 Germany 1003 [CF] | 2x"), "Germany 1003 [CF]", "🇩🇪 Germany 1003 [CF] | 2x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ambiguous := matchRemark(tc.links, tc.target)
			if ambiguous {
				t.Fatal("unexpected ambiguous result")
			}
			if got == nil || got.Remark != tc.want {
				t.Fatalf("matchRemark(%q) = %+v, want remark %q", tc.target, got, tc.want)
			}
		})
	}
}

func TestMatchRemarkPrefersExactRawRemark(t *testing.T) {
	links := testLinks("🇺🇸 US 1000", "US 1000")
	got, ambiguous := matchRemark(links, "US 1000")
	if ambiguous || got == nil || got.Remark != "US 1000" {
		t.Fatalf("exact raw remark must win: got=%+v ambiguous=%v", got, ambiguous)
	}
}

func TestMatchRemarkRefusesAmbiguousDisplayedName(t *testing.T) {
	links := testLinks("🇺🇸 US 1000", "Provider - US 1000")
	got, ambiguous := matchRemark(links, "US 1000")
	if !ambiguous || got != nil {
		t.Fatalf("expected an unambiguous refusal, got=%+v ambiguous=%v", got, ambiguous)
	}
}

func TestMatchRemarkReportsMissingName(t *testing.T) {
	got, ambiguous := matchRemark(testLinks("🇳🇱 NL-03 1300 [T]"), "NL-04 1300 [T]")
	if got != nil || ambiguous {
		t.Fatalf("unknown name must not match: got=%+v ambiguous=%v", got, ambiguous)
	}
}

func TestMatchRemarkAcceptsTruncatedDisplayedName(t *testing.T) {
	long := "🇳🇱 Netherlands Amsterdam 3103 [CF]"
	displayed := cleanRemark(long)
	got, ambiguous := matchRemark(testLinks(long), displayed)
	if ambiguous || got == nil || got.Remark != long {
		t.Fatalf("truncated displayed name must match: got=%+v ambiguous=%v displayed=%q", got, ambiguous, displayed)
	}
}
