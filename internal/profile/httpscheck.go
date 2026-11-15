package profile

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

// TestHTTPS checks if a proxy can relay HTTPS traffic.
// It performs a real SOCKS5 CONNECT followed by a verified TLS handshake and
// HTTP GET, so an open port or a TCP-only relay is not mistaken for a healthy
// tunnel. No external binary (curl) is involved; /dev/null does not exist on
// Windows and schannel behavior varies across hosts.
func TestHTTPS(ctx context.Context, proxyPort int) bool {
	return testHTTPS(ctx, proxyPort, "https://cp.cloudflare.com", nil)
}

// TestURL checks one operator-configured health URL through the proxy. Any 2xx
// response counts as reachable; the caller decides how many failures mean the
// tunnel is degraded.
func TestURL(ctx context.Context, proxyPort int, target string) bool {
	if target == "" {
		return false
	}
	return testHTTPS(ctx, proxyPort, target, nil)
}

// TestAnyURL probes independent endpoints through the proxy and succeeds as
// soon as one returns a 2xx. Probes run concurrently under one deadline, so a
// blocked or slow endpoint cannot lengthen the health window, and a single
// unreachable host cannot mark the whole tunnel down.
func TestAnyURL(ctx context.Context, proxyPort int, targets []string) bool {
	return testAnyURL(ctx, proxyPort, targets, nil)
}

func testAnyURL(ctx context.Context, proxyPort int, targets []string, tlsConfig *tls.Config) bool {
	seen := make(map[string]bool, len(targets))
	unique := make([]string, 0, len(targets))
	for _, target := range targets {
		if target == "" || seen[target] {
			continue
		}
		seen[target] = true
		unique = append(unique, target)
	}
	if len(unique) == 0 {
		return false
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan bool, len(unique))
	for _, target := range unique {
		go func(target string) {
			results <- testHTTPS(ctx, proxyPort, target, tlsConfig)
		}(target)
	}
	for range unique {
		if <-results {
			return true
		}
	}
	return false
}

// FetchThroughProxy performs a bounded HTTPS GET through the local SOCKS
// listener. It is used for exit-IP probes: the response is not a secret, and
// the caller decides how to parse it.
func FetchThroughProxy(ctx context.Context, proxyPort int, target string, limit int64) ([]byte, error) {
	body, _, err := GetThroughProxy(ctx, proxyPort, target, nil, limit)
	return body, err
}

// GetThroughProxy is FetchThroughProxy with explicit request headers and the
// response status returned. DNS-over-HTTPS needs the JSON accept header; the
// caller is responsible for supplying only protocol headers.
func GetThroughProxy(ctx context.Context, proxyPort int, target string, headers map[string]string, limit int64) ([]byte, int, error) {
	return GetThroughProxyAt(ctx, net.JoinHostPort("127.0.0.1", strconv.Itoa(proxyPort)), target, headers, limit)
}

// GetThroughProxyAt is GetThroughProxy against an explicit SOCKS listener
// address, for a proxy bound to a LAN address instead of loopback.
func GetThroughProxyAt(ctx context.Context, proxyAddr, target string, headers map[string]string, limit int64) ([]byte, int, error) {
	if limit <= 0 || limit > 1<<20 {
		limit = 1 << 16
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, portStr, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			port, err := strconv.Atoi(portStr)
			if err != nil {
				return nil, err
			}
			return dialSOCKS5(ctx, proxyAddr, host, port, 8*time.Second)
		},
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 8 * time.Second,
		DisableKeepAlives:   true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, 0, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, resp.StatusCode, fmt.Errorf("exit probe: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	return body, resp.StatusCode, err
}

// testHTTPS is the testable core of TestHTTPS. The extra parameters let the
// negative and positive TLS cases run against a local TLS server without ever
// weakening the production call (which always uses system roots).
func testHTTPS(ctx context.Context, proxyPort int, target string, tlsConfig *tls.Config) bool {
	testCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	proxyAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(proxyPort))
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if tlsConfig != nil {
		cfg = tlsConfig.Clone()
		if cfg.MinVersion < tls.VersionTLS12 {
			cfg.MinVersion = tls.VersionTLS12
		}
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, portStr, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			port, err := strconv.Atoi(portStr)
			if err != nil {
				return nil, err
			}
			return dialSOCKS5(ctx, proxyAddr, host, port, 6*time.Second)
		},
		TLSClientConfig:     cfg,
		TLSHandshakeTimeout: 6 * time.Second,
		DisableKeepAlives:   true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second}

	req, err := http.NewRequestWithContext(testCtx, http.MethodGet, target, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// dialSOCKS5 performs a no-auth SOCKS5 CONNECT. Domain names are sent to the
// proxy (SOCKS5h semantics) so DNS resolution happens on the tunnel side.
func dialSOCKS5(ctx context.Context, proxyAddr, host string, port int, timeout time.Duration) (net.Conn, error) {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, err
	}
	var head [2]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		conn.Close()
		return nil, err
	}
	if head[0] != 0x05 || head[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5: server chose auth method %d", head[1])
	}

	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 0x01)
			req = append(req, v4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			conn.Close()
			return nil, fmt.Errorf("socks5: hostname too long")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}

	var resp [4]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		conn.Close()
		return nil, err
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5: CONNECT failed, REP=%d", resp[1])
	}
	var skip int
	switch resp[3] {
	case 0x01:
		skip = 4
	case 0x04:
		skip = 16
	case 0x03:
		var n [1]byte
		if _, err := io.ReadFull(conn, n[:]); err != nil {
			conn.Close()
			return nil, err
		}
		skip = int(n[0])
	default:
		conn.Close()
		return nil, fmt.Errorf("socks5: unknown address type %d", resp[3])
	}
	if _, err := io.CopyN(io.Discard, conn, int64(skip+2)); err != nil {
		conn.Close()
		return nil, err
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// DialSOCKS5 exposes the no-auth SOCKS5 CONNECT used by the health checks so
// in-process callers (the routing panel) can test one destination through the
// same tunnel the health checks use.
func DialSOCKS5(ctx context.Context, proxyAddr, host string, port int, timeout time.Duration) (net.Conn, error) {
	return dialSOCKS5(ctx, proxyAddr, host, port, timeout)
}
