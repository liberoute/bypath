package bench

import (
	"context"
	"errors"
	"time"
)

// probeTimeout bounds one liveness request so a blocked endpoint cannot spend
// the whole per-link budget before the next candidate is tried.
const probeTimeout = 6 * time.Second

// ProbeURLs are the candidate endpoints for a liveness/latency probe. HTTPS to
// 1.1.1.1 is blocked on the target network class, so it is a last resort.
// Cloudflare hosts are deliberately absent: a policy that routes Cloudflare
// DIRECT makes a dead tunnel look alive (S0.5).
var ProbeURLs = []string{
	"https://www.gstatic.com/generate_204",
	"https://connectivitycheck.gstatic.com/generate_204",
	"https://1.1.1.1/cdn-cgi/trace",
}

// PickProbeURL returns the first probe URL that answers through the proxy on
// port. It is used before a measurement so latency is sampled against one
// endpoint the path can actually reach.
func PickProbeURL(ctx context.Context, port int) (string, error) {
	var lastErr error
	for _, url := range ProbeURLs {
		pctx, cancel := context.WithTimeout(ctx, probeTimeout)
		_, err := FetchHTTPSThroughProxy(pctx, port, url, 4096)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		return url, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no probe URL answered")
	}
	return "", lastErr
}
