//go:build realnet

package tunnel

// Bounded real-network validation for VLESS Encryption subscriptions.
//
// Run with:
//   BYPATH_REALNET_SUB=/path/to/decoded.txt \
//   BYPATH_XRAY=/path/to/xray \
//   BYPATH_REALNET_OUT=/path/to/results.json \
//   go test -tags realnet ./internal/tunnel -run TestRealVLESSBatch -v -timeout 30m
//
// The subscription file is expected to contain one URI per line (a decoded
// subscription or a plain list). Results never include UUIDs, keys or other
// URI secrets.

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/liberoute/bypath/internal/acceptance"
	"github.com/liberoute/bypath/internal/engine"
	"github.com/liberoute/bypath/internal/profile"
)

type vlessRealResult struct {
	Index         int               `json:"index"`
	Server        string            `json:"server"`
	Port          int               `json:"port"`
	IPv6          bool              `json:"ipv6"`
	Encrypted     bool              `json:"encrypted"`
	ConfigValid   bool              `json:"config_valid"`
	Status        acceptance.Status `json:"status"`
	Detail        string            `json:"detail,omitempty"`
	LatencyMS     int64             `json:"latency_ms,omitempty"`
	ProxyEgress   string            `json:"proxy_egress,omitempty"`
	DirectEgress  string            `json:"direct_egress,omitempty"`
	EgressDiffers bool              `json:"egress_differs"`
	HealthCheck   bool              `json:"health_check"`
}

var (
	realUUIDRe = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
	realEncRe  = regexp.MustCompile(`mlkem768x25519plus[^\s"',}]*`)
	realB64Re  = regexp.MustCompile(`[A-Za-z0-9+/_-]{40,}={0,2}`)
)

func redactDetail(s string) string {
	s = realUUIDRe.ReplaceAllString(s, "<uuid>")
	s = realEncRe.ReplaceAllString(s, "mlkem768x25519plus.<redacted>")
	s = realB64Re.ReplaceAllString(s, "<redacted>")
	s = strings.TrimSpace(s)
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

func loadRealnetURIs(t *testing.T) []string {
	t.Helper()
	path := os.Getenv("BYPATH_REALNET_SUB")
	if path == "" {
		t.Skip("BYPATH_REALNET_SUB not set")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading subscription file: %v", err)
	}
	var uris []string
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.Contains(line, "://") {
			uris = append(uris, line)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("reading subscription file: %v", err)
	}
	if len(uris) == 0 {
		t.Fatal("subscription file contains no URIs")
	}
	limit, _ := strconv.Atoi(os.Getenv("BYPATH_REALNET_LIMIT"))
	if limit > 0 && len(uris) > limit {
		uris = uris[:limit]
	}
	return uris
}

func socks5DialContext(ctx context.Context, proxyAddr, host string, port int, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, err
	}
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
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
		req = append(req, []byte(host)...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}
	resp := make([]byte, 4)
	if _, err := io.ReadFull(conn, resp); err != nil {
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
		one := make([]byte, 1)
		if _, err := io.ReadFull(conn, one); err != nil {
			conn.Close()
			return nil, err
		}
		skip = int(one[0])
	default:
		conn.Close()
		return nil, fmt.Errorf("socks5: unknown address type %d", resp[3])
	}
	if _, err := io.CopyN(io.Discard, conn, int64(skip+2)); err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func fetchViaProxy(ctx context.Context, proxyAddr, url string, timeout time.Duration) (string, int, time.Duration, error) {
	start := time.Now()
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
			return socks5DialContext(ctx, proxyAddr, host, port, timeout)
		},
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: timeout,
		DisableKeepAlives:   true,
	}
	client := &http.Client{Transport: transport, Timeout: timeout}
	defer transport.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", 0, 0, err
	}
	req.Header.Set("User-Agent", "bypath-realnet/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, time.Since(start), err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", resp.StatusCode, time.Since(start), err
	}
	return string(body), resp.StatusCode, time.Since(start), nil
}

func directEgress(ctx context.Context, timeout time.Duration) string {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ipify.org?format=json", nil)
	if err != nil {
		return ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	var payload struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&payload); err != nil {
		return ""
	}
	return payload.IP
}

func proxyEgressVia(ctx context.Context, proxyAddr string, timeout time.Duration) string {
	body, status, _, err := fetchViaProxy(ctx, proxyAddr, "https://api.ipify.org?format=json", timeout)
	if err != nil || status != 200 {
		return ""
	}
	var payload struct {
		IP string `json:"ip"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		return ""
	}
	return payload.IP
}

func hasGlobalIPv6() bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipnet.IP
		if ip.To4() != nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		if ip.IsGlobalUnicast() {
			return true
		}
	}
	return false
}

func runVLESSRealnet(t *testing.T, index int, uri, xrayPath, proxyAddr string, basePort int, direct string, v6Available bool) vlessRealResult {
	link, err := profile.ParseURI(uri)
	if err != nil {
		return vlessRealResult{Index: index, Status: acceptance.Failed, Detail: redactDetail(err.Error())}
	}
	res := vlessRealResult{Index: index, Server: link.Address, Port: link.Port, IPv6: strings.Contains(link.Address, ":"), Encrypted: link.EncryptedVLESS()}
	if res.IPv6 && !v6Available {
		res.Status = acceptance.BlockedByNetwork
		res.Detail = "host has no global IPv6 address; dual-stack acceptance is not claimed"
		return res
	}
	res.DirectEgress = direct
	if res.IPv6 {
		res.DirectEgress = ""
	}

	dir, err := os.MkdirTemp(t.TempDir(), fmt.Sprintf("vless-%02d-", index))
	if err != nil {
		res.Status = acceptance.Failed
		res.Detail = redactDetail(err.Error())
		return res
	}
	link.ListenPort = basePort + index
	cg := NewConfigGenerator(dir)
	cfgPath, err := cg.Generate(&engine.Engine{Name: "xray", Path: xrayPath}, link)
	if err != nil {
		res.Status = acceptance.Failed
		res.Detail = redactDetail(err.Error())
		return res
	}

	testCtx, cancelTest := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelTest()
	out, err := exec.CommandContext(testCtx, xrayPath, "run", "-test", "-c", cfgPath).CombinedOutput()
	if err != nil {
		res.Status = acceptance.Failed
		res.Detail = redactDetail(string(out))
		return res
	}
	res.ConfigValid = true

	runCtx, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()
	cmd := exec.CommandContext(runCtx, xrayPath, "run", "-c", cfgPath)
	cmd.WaitDelay = 2 * time.Second
	var logBuf strings.Builder
	cmd.Stdout = &logBuf
	cmd.Stderr = &logBuf
	if err := cmd.Start(); err != nil {
		res.Status = acceptance.Failed
		res.Detail = redactDetail(err.Error())
		return res
	}
	defer func() {
		cancelRun()
		_ = cmd.Wait()
	}()

	deadline := time.Now().Add(12 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", proxyAddr, 400*time.Millisecond)
		if err == nil {
			conn.Close()
			ready = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !ready {
		res.Status = acceptance.Failed
		res.Detail = redactDetail(tailString(logBuf.String(), 500))
		return res
	}

	reqCtx, cancelReq := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancelReq()
	body, status, latency, err := fetchViaProxy(reqCtx, proxyAddr, "https://www.gstatic.com/generate_204", 10*time.Second)
	_ = body
	if err != nil {
		// Only classify as an environment block when the direct egress probe
		// also failed; otherwise this is a genuine tunnel failure.
		res.Status = acceptance.Failed
		res.Detail = redactDetail(err.Error())
		if direct == "" && !res.IPv6 {
			res.Status = acceptance.BlockedByNetwork
			res.Detail += " (direct egress probe also failed)"
		}
		return res
	}
	if status != http.StatusNoContent && status != http.StatusOK {
		res.Status = acceptance.Failed
		res.Detail = fmt.Sprintf("status %d", status)
		return res
	}
	if !profile.TestHTTPS(reqCtx, basePort+index) {
		res.Status = acceptance.Failed
		return res
	}
	res.HealthCheck = true
	res.Status = acceptance.Success
	res.LatencyMS = latency.Milliseconds()
	res.ProxyEgress = proxyEgressVia(reqCtx, proxyAddr, 10*time.Second)
	if res.ProxyEgress != "" && res.DirectEgress != "" {
		res.EgressDiffers = res.ProxyEgress != res.DirectEgress
	}
	return res
}

func tailString(s string, n int) string {
	if len(s) <= n {
		return strings.TrimSpace(s)
	}
	return strings.TrimSpace(s[len(s)-n:])
}

func TestRealVLESSBatch(t *testing.T) {
	uris := loadRealnetURIs(t)
	xrayPath := os.Getenv("BYPATH_XRAY")
	if xrayPath == "" {
		t.Skip("BYPATH_XRAY not set")
	}
	if _, err := os.Stat(xrayPath); err != nil {
		t.Fatalf("xray binary not found: %v", err)
	}

	egressCtx, cancelEgress := context.WithTimeout(context.Background(), 15*time.Second)
	direct := directEgress(egressCtx, 10*time.Second)
	cancelEgress()
	v6 := hasGlobalIPv6()
	t.Logf("entries=%d direct_egress=%q global_ipv6=%v", len(uris), direct, v6)

	concurrency, _ := strconv.Atoi(os.Getenv("BYPATH_REALNET_CONCURRENCY"))
	if concurrency <= 0 {
		concurrency = 3
	}
	basePort := 24100
	if v := os.Getenv("BYPATH_REALNET_BASE_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 1024 && n < 60000-len(uris) {
			basePort = n
		}
	}

	results := make([]vlessRealResult, len(uris))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, uri := range uris {
		wg.Add(1)
		go func(index int, uri string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			proxyAddr := fmt.Sprintf("127.0.0.1:%d", basePort+index)
			results[index] = runVLESSRealnet(t, index, uri, xrayPath, proxyAddr, basePort, direct, v6)
		}(i, uri)
	}
	wg.Wait()

	counts := map[acceptance.Status]int{}
	ok := 0
	blocked := 0
	for _, r := range results {
		counts[r.Status]++
		if r.Status == acceptance.BlockedByNetwork {
			blocked++
		}
		if r.Status == acceptance.Success {
			ok++
			t.Logf("[%02d] %s:%d ok latency=%dms proxy_egress=%s direct_egress=%s differs=%v",
				r.Index+1, r.Server, r.Port, r.LatencyMS, r.ProxyEgress, r.DirectEgress, r.EgressDiffers)
		} else {
			t.Logf("[%02d] %s:%d status=%s detail=%s", r.Index+1, r.Server, r.Port, r.Status, r.Detail)
		}
	}

	if outPath := os.Getenv("BYPATH_REALNET_OUT"); outPath != "" {
		data, _ := json.MarshalIndent(map[string]interface{}{
			"generated_at":  time.Now().UTC().Format(time.RFC3339),
			"entries":       len(uris),
			"success":       ok,
			"counts":        counts,
			"direct_egress": direct,
			"global_ipv6":   v6,
			"results":       results,
		}, "", "  ")
		if err := os.WriteFile(outPath, data, 0600); err != nil {
			t.Errorf("writing results: %v", err)
		}
	}

	t.Logf("summary: %d/%d success, %d blocked by network, statuses=%v", ok, len(uris), blocked, counts)

	// Only encrypted entries can speak to the modern-encryption matrix case;
	// unencrypted successes must not be promoted into its evidence.
	encryptedTotal, encryptedOK, encryptedBlocked := 0, 0, 0
	for _, r := range results {
		if !r.Encrypted {
			continue
		}
		encryptedTotal++
		switch r.Status {
		case acceptance.Success:
			encryptedOK++
		case acceptance.BlockedByNetwork:
			encryptedBlocked++
		}
	}
	if encryptedTotal > 0 {
		observed := acceptance.Failed
		switch {
		case encryptedOK > 0:
			observed = acceptance.Success
		case encryptedBlocked == encryptedTotal:
			observed = acceptance.BlockedByNetwork
		}
		if matrixCase, found := acceptance.Standard().Case("vless.modern-encryption.xray"); found {
			res := acceptance.Result{Case: matrixCase.ID, Status: observed}
			if err := matrixCase.Evaluate(res); err != nil {
				t.Errorf("acceptance matrix: %v", err)
			}
			recordAcceptanceEvidence(t, res)
		}
	} else {
		t.Logf("acceptance: no encrypted VLESS entry ran; vless.modern-encryption.xray stays NOT_TESTED")
	}

	if ok == 0 {
		if blocked == len(uris) {
			t.Skip("every VLESS attempt was blocked by the observed network state; no success is claimed")
		}
		t.Fatalf("no VLESS endpoint completed an HTTPS round trip")
	}
}
