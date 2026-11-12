package bench

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/liberoute/bypath/internal/profile"
)

// FetchHTTPSThroughProxy is the proof-bearing GET. No redirect can turn a TLS
// test into plaintext or silently replace an independent identity operator.
func FetchHTTPSThroughProxy(ctx context.Context, port int, target string, limit int64) ([]byte, error) {
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return nil, fmt.Errorf("proof target must be HTTPS")
	}
	if limit <= 0 || limit > 1<<20 {
		limit = 4096
	}
	proxyAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 6 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, rawPort, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			destPort, err := strconv.Atoi(rawPort)
			if err != nil {
				return nil, err
			}
			return profile.DialSOCKS5(ctx, proxyAddr, host, destPort, 6*time.Second)
		}, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.TLS == nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTPS proof endpoint did not return success")
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}
