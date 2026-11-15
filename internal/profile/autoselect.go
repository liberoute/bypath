package profile

import "time"

// BenchResult holds the outcome of benchmarking a single link.
type BenchResult struct {
	Link    *Link
	Latency time.Duration
	HTTPSOk bool // true if the link passed the HTTPS connectivity test
	Passed  bool // true if the link passed the basic HTTP relay test
}

// SelectResult holds the outcome of the auto-select algorithm.
type SelectResult struct {
	Best    *BenchResult   // the selected best link (nil if no links passed)
	Skipped []*BenchResult // links that were faster but lacked HTTPS
	NoHTTPS bool           // true if fallback was used (no HTTPS-capable links)
}

// SelectBest picks the best link from a set of bench results.
//
// The algorithm:
//  1. Filter to only results where Passed == true.
//  2. Among passing results, find HTTPS-capable ones (HTTPSOk == true).
//  3. If HTTPS-capable links exist, pick the one with lowest latency as Best.
//  4. Collect any non-HTTPS links with lower latency than Best into Skipped.
//  5. If no HTTPS-capable links exist, set NoHTTPS=true and pick the fastest overall.
//  6. Return nil Best if no links passed at all.
func SelectBest(results []*BenchResult) *SelectResult {
	// Step 1: filter to passing results only.
	var passing []*BenchResult
	for _, r := range results {
		if r.Passed {
			passing = append(passing, r)
		}
	}

	// Step 6: no passing links at all.
	if len(passing) == 0 {
		return &SelectResult{}
	}

	// Step 2: separate HTTPS-capable from non-HTTPS.
	var httpsCapable []*BenchResult
	var nonHTTPS []*BenchResult
	for _, r := range passing {
		if r.HTTPSOk {
			httpsCapable = append(httpsCapable, r)
		} else {
			nonHTTPS = append(nonHTTPS, r)
		}
	}

	// Step 5: no HTTPS-capable links — fall back to fastest overall.
	if len(httpsCapable) == 0 {
		best := passing[0]
		for _, r := range passing[1:] {
			if r.Latency < best.Latency {
				best = r
			}
		}
		return &SelectResult{
			Best:    best,
			NoHTTPS: true,
		}
	}

	// Step 3: pick the HTTPS-capable link with lowest latency.
	best := httpsCapable[0]
	for _, r := range httpsCapable[1:] {
		if r.Latency < best.Latency {
			best = r
		}
	}

	// Step 4: collect non-HTTPS links that are faster than the chosen best.
	var skipped []*BenchResult
	for _, r := range nonHTTPS {
		if r.Latency < best.Latency {
			skipped = append(skipped, r)
		}
	}

	return &SelectResult{
		Best:    best,
		Skipped: skipped,
	}
}
