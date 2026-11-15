package profile

import (
	"testing"
	"time"

	"pgregory.net/rapid"
)

// Feature: cdn-https-detection, Property 5: HTTPS-capable links are preferred in auto-select
//
// For any set of bench results where at least one link is HTTPS-capable,
// the auto-selected link SHALL be HTTPS-capable (even if a non-HTTPS link has lower latency).
//
// **Validates: Requirements 5.1, 5.2**
func TestProperty5_HTTPSCapablePreferred(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate a non-empty slice of bench results with at least one HTTPS-capable + Passed link.
		n := rapid.IntRange(2, 20).Draw(t, "numResults")

		results := make([]*BenchResult, n)
		for i := range results {
			results[i] = &BenchResult{
				Link:    &Link{Remark: rapid.StringMatching(`[a-z]{3,10}`).Draw(t, "remark")},
				Latency: time.Duration(rapid.IntRange(1, 10000).Draw(t, "latencyMs")) * time.Millisecond,
				HTTPSOk: rapid.Bool().Draw(t, "httpsOk"),
				Passed:  rapid.Bool().Draw(t, "passed"),
			}
		}

		// Ensure at least one result is HTTPS-capable AND passed.
		forceIdx := rapid.IntRange(0, n-1).Draw(t, "forceHTTPSIdx")
		results[forceIdx].HTTPSOk = true
		results[forceIdx].Passed = true
		results[forceIdx].Latency = time.Duration(rapid.IntRange(1, 10000).Draw(t, "forcedLatency")) * time.Millisecond

		sel := SelectBest(results)

		if sel.Best == nil {
			t.Fatal("SelectBest returned nil Best when at least one HTTPS-capable passing link exists")
		}

		if !sel.Best.HTTPSOk {
			t.Fatalf("SelectBest chose a non-HTTPS link (latency=%v) when HTTPS-capable links exist",
				sel.Best.Latency)
		}
	})
}

// Feature: cdn-https-detection, Property 6: Auto-select falls back when no HTTPS links exist
//
// For any set of bench results where no link is HTTPS-capable but at least one link
// passed the HTTP relay test, the auto-selected link SHALL be the one with the lowest
// latency among passing links.
//
// **Validates: Requirements 5.3**
func TestProperty6_FallbackToLowestLatency(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate a non-empty slice of bench results with NO HTTPS-capable links
		// but at least one passing link.
		n := rapid.IntRange(2, 20).Draw(t, "numResults")

		results := make([]*BenchResult, n)
		for i := range results {
			results[i] = &BenchResult{
				Link:    &Link{Remark: rapid.StringMatching(`[a-z]{3,10}`).Draw(t, "remark")},
				Latency: time.Duration(rapid.IntRange(1, 10000).Draw(t, "latencyMs")) * time.Millisecond,
				HTTPSOk: false, // No HTTPS-capable links
				Passed:  rapid.Bool().Draw(t, "passed"),
			}
		}

		// Ensure at least one result passed the HTTP relay test.
		forceIdx := rapid.IntRange(0, n-1).Draw(t, "forcePassIdx")
		results[forceIdx].Passed = true
		results[forceIdx].Latency = time.Duration(rapid.IntRange(1, 10000).Draw(t, "forcedLatency")) * time.Millisecond

		sel := SelectBest(results)

		if sel.Best == nil {
			t.Fatal("SelectBest returned nil Best when at least one passing link exists")
		}

		// Verify NoHTTPS flag is set.
		if !sel.NoHTTPS {
			t.Fatal("SelectBest did not set NoHTTPS=true when no HTTPS-capable links exist")
		}

		// Verify the selected link has the lowest latency among all passing links.
		var minLatency time.Duration
		for _, r := range results {
			if r.Passed {
				if minLatency == 0 || r.Latency < minLatency {
					minLatency = r.Latency
				}
			}
		}

		if sel.Best.Latency != minLatency {
			t.Fatalf("SelectBest chose link with latency %v, but lowest passing latency is %v",
				sel.Best.Latency, minLatency)
		}
	})
}
