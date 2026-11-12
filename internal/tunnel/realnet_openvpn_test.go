//go:build realnet

package tunnel

// Bounded real-network validation for OpenVPN profiles through the sing-box
// 1.14 openvpn-client endpoint.
//
// Run with:
//   BYPATH_OPENVPN_PROFILE=/path/to/profile-or-directory \
//   BYPATH_SINGBOX=/path/to/sing-box (1.14+) \
//   BYPATH_OPENVPN_OUT=/path/to/results.json \
//   go test -tags realnet ./internal/tunnel -run TestRealOpenVPN -v -timeout 20m
//
// The test proves the tunnel with an HTTPS round trip, never with process or
// port startup alone. It snapshots host routes/DNS/interfaces before and after
// and fails if the process changed host networking.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/liberoute/bypath/internal/acceptance"
	"github.com/liberoute/bypath/internal/engine"
	"github.com/liberoute/bypath/internal/openvpn"
	"github.com/liberoute/bypath/internal/profile"
)

type openvpnRealResult struct {
	Profile       string            `json:"profile"`
	Server        string            `json:"server"`
	Proto         string            `json:"proto"`
	ConfigValid   bool              `json:"config_valid"`
	HTTPSReady    bool              `json:"https_ready"`
	HandshakeMS   int64             `json:"handshake_ms,omitempty"`
	LatencyMS     int64             `json:"latency_ms,omitempty"`
	ProxyEgress   string            `json:"proxy_egress,omitempty"`
	DirectEgress  string            `json:"direct_egress,omitempty"`
	EgressDiffers bool              `json:"egress_differs"`
	HostDNSIntact bool              `json:"host_dns_intact"`
	HealthCheck   bool              `json:"health_check"`
	ProxyIPFamily string            `json:"proxy_ip_family,omitempty"`
	RecoveryOK    bool              `json:"recovery_ok"`
	RecoveryMS    int64             `json:"recovery_ms,omitempty"`
	Status        acceptance.Status `json:"status"`
	Detail        string            `json:"detail,omitempty"`
}

type runningEngine struct {
	cancel context.CancelFunc
	cmd    *exec.Cmd
	logs   *stringBuilder
	done   chan struct{}
}

func (r *runningEngine) stop() {
	if r == nil || r.cancel == nil {
		return
	}
	r.cancel()
	select {
	case <-r.done:
	case <-time.After(8 * time.Second):
	}
}

func startEngine(t *testing.T, binary, cfgPath string, port int) *runningEngine {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, binary, "run", "-c", cfgPath)
	cmd.Dir = filepath.Dir(cfgPath)
	cmd.WaitDelay = 3 * time.Second
	logs := &stringBuilder{}
	cmd.Stdout = logs
	cmd.Stderr = logs
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("starting %s: %v", filepath.Base(binary), err)
	}
	eng := &runningEngine{cancel: cancel, cmd: cmd, logs: logs, done: make(chan struct{})}
	go func() {
		_ = cmd.Wait()
		close(eng.done)
	}()
	t.Cleanup(eng.stop)

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 300*time.Millisecond)
		if err == nil {
			conn.Close()
			return eng
		}
		select {
		case <-eng.done:
			t.Fatalf("engine exited before listening on :%d: %s", port, redactDetail(tailString(logs.String(), 600)))
		default:
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("engine did not listen on :%d: %s", port, redactDetail(tailString(logs.String(), 600)))
	return nil
}

// waitProxyHTTPS retries until an HTTPS request actually completes through the
// proxy. An open SOCKS port is not treated as readiness: OpenVPN handshakes can
// still be in progress or fail after the listener is up.
func waitProxyHTTPS(ctx context.Context, proxyAddr string, timeout time.Duration) (time.Duration, int, error) {
	start := time.Now()
	deadline := time.Now().Add(timeout)
	var lastErr error
	lastStatus := 0
	for time.Now().Before(deadline) {
		reqCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		_, status, _, err := fetchViaProxy(reqCtx, proxyAddr, "https://www.gstatic.com/generate_204", 8*time.Second)
		cancel()
		if err == nil && (status == http.StatusNoContent || status == http.StatusOK) {
			return time.Since(start), status, nil
		}
		lastStatus = status
		lastErr = err
		select {
		case <-ctx.Done():
			return time.Since(start), lastStatus, ctx.Err()
		case <-time.After(1500 * time.Millisecond):
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("last HTTPS status %d", lastStatus)
	}
	return time.Since(start), lastStatus, lastErr
}

func proxyPublicIP(ctx context.Context, proxyAddr string, url string) string {
	reqCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	body, status, _, err := fetchViaProxy(reqCtx, proxyAddr, url, 10*time.Second)
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

func hostNetworkSnapshot(t *testing.T) string {
	t.Helper()
	var commands [][]string
	switch runtime.GOOS {
	case "windows":
		commands = [][]string{
			{"route", "print", "-4"},
			{"route", "print", "-6"},
			{"netsh", "interface", "ip", "show", "dnsservers"},
			{"netsh", "interface", "show", "interface"},
		}
	case "linux":
		commands = [][]string{
			{"ip", "route", "show", "table", "all"},
			{"ip", "-brief", "addr"},
			{"sh", "-c", "cat /etc/resolv.conf"},
		}
	default:
		t.Skipf("host snapshot not implemented for %s", runtime.GOOS)
	}
	var b strings.Builder
	for _, args := range commands {
		b.WriteString("$ " + strings.Join(args, " ") + "\n")
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			fmt.Fprintf(&b, "(exit: %v)\n", err)
		}
		b.WriteString(normalizeSnapshot(string(out)))
		b.WriteString("\n")
	}
	return b.String()
}

func normalizeSnapshot(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimRight(line, " \t")
		if strings.TrimSpace(line) == "" {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

func openvpnRealnetProfiles(t *testing.T) []string {
	t.Helper()
	path := os.Getenv("BYPATH_OPENVPN_PROFILE")
	if path == "" {
		t.Skip("BYPATH_OPENVPN_PROFILE not set")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("profile path: %v", err)
	}
	if !info.IsDir() {
		return []string{path}
	}
	var out []string
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatalf("listing profiles: %v", err)
	}
	for _, e := range entries {
		if !e.IsDir() && strings.EqualFold(filepath.Ext(e.Name()), ".ovpn") {
			out = append(out, filepath.Join(path, e.Name()))
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		t.Fatalf("no .ovpn profiles in %s", path)
	}
	return out
}

func runOpenVPNProfile(t *testing.T, profilePath, singboxPath, direct string, port int) openvpnRealResult {
	res := openvpnRealResult{Profile: filepath.Base(profilePath), DirectEgress: direct}

	prof, err := openvpn.ParseFile(profilePath)
	if err != nil {
		res.Status = acceptance.Failed
		res.Detail = redactDetail(err.Error())
		return res
	}
	res.Server = prof.Remotes[0].Host
	res.Proto = prof.Proto

	link := &profile.Link{
		Protocol:   "openvpn",
		Remark:     filepath.Base(profilePath),
		Address:    prof.Remotes[0].Host,
		Port:       prof.Remotes[0].Port,
		Network:    prof.Proto,
		OVPNPath:   profilePath,
		ListenPort: port,
	}

	cfgDir := t.TempDir()
	cg := NewConfigGenerator(cfgDir)
	cfgPath, err := cg.Generate(&engine.Engine{Name: "sing-box", Path: singboxPath}, link)
	if err != nil {
		res.Status = acceptance.Failed
		res.Detail = redactDetail(err.Error())
		return res
	}

	checkCtx, cancelCheck := context.WithTimeout(context.Background(), 30*time.Second)
	out, err := exec.CommandContext(checkCtx, singboxPath, "check", "-c", cfgPath).CombinedOutput()
	cancelCheck()
	if err != nil {
		res.Status = acceptance.Failed
		res.Detail = redactDetail(string(out))
		return res
	}
	res.ConfigValid = true

	proxyAddr := fmt.Sprintf("127.0.0.1:%d", port)
	eng := startEngine(t, singboxPath, cfgPath, port)
	// One OpenVPN session at a time: a profile's engine must be gone before the
	// next profile connects, otherwise the account's later sessions displace
	// the earlier tunnel and the run reports failures that belong to the
	// harness, not to the profile.
	defer eng.stop()

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	hs, status, err := waitProxyHTTPS(ctx, proxyAddr, 75*time.Second)
	if err != nil {
		// BLOCKED_BY_NETWORK requires evidence that direct egress is also
		// unavailable; otherwise the tunnel itself is the failure.
		res.Status = acceptance.Failed
		res.Detail = redactDetail(fmt.Sprintf("%v (status %d)", err, status))
		if direct == "" {
			res.Status = acceptance.BlockedByNetwork
			res.Detail += " (direct egress probe also failed)"
		}
		return res
	}
	res.HTTPSReady = true
	res.HandshakeMS = hs.Milliseconds()

	// The production readiness gate must also accept this tunnel.
	if !profile.TestHTTPS(ctx, port) {
		res.Status = acceptance.Failed
		res.Detail = "production HTTPS gate failed after the tunnel reported ready"
		return res
	}
	res.HealthCheck = true

	_, _, latency, err := fetchViaProxy(ctx, proxyAddr, "https://www.gstatic.com/generate_204", 10*time.Second)
	if err == nil {
		res.LatencyMS = latency.Milliseconds()
	}

	res.ProxyEgress = proxyPublicIP(ctx, proxyAddr, "https://api.ipify.org?format=json")
	if res.ProxyEgress != "" {
		res.ProxyIPFamily = "ipv4"
		if strings.Contains(res.ProxyEgress, ":") {
			res.ProxyIPFamily = "ipv6"
		}
		if ip := net.ParseIP(res.ProxyEgress); ip != nil && ip.To4() == nil {
			res.ProxyIPFamily = "ipv6"
		}
	}
	if res.ProxyEgress != "" && res.DirectEgress != "" {
		res.EgressDiffers = res.ProxyEgress != res.DirectEgress
	}

	// Host resolver must keep working while the tunnel is up: the endpoint uses
	// its own DNS path and must not have replaced the system resolver.
	if _, err := net.LookupHost("example.com"); err == nil {
		res.HostDNSIntact = true
	}

	// Failure recovery: kill the engine, confirm the SOCKS port is gone, then
	// restart with the same config and require a fresh HTTPS round trip.
	eng.stop()
	closed := false
	for i := 0; i < 25; i++ {
		conn, err := net.DialTimeout("tcp", proxyAddr, 200*time.Millisecond)
		if err != nil {
			closed = true
			break
		}
		conn.Close()
		time.Sleep(200 * time.Millisecond)
	}
	if !closed {
		res.Status = acceptance.Failed
		res.Detail = "SOCKS port still open after stopping the engine"
		return res
	}
	restartStart := time.Now()
	startEngine(t, singboxPath, cfgPath, port)
	_, _, err = waitProxyHTTPS(ctx, proxyAddr, 60*time.Second)
	if err != nil {
		res.Status = acceptance.Failed
		res.Detail = redactDetail(err.Error())
		return res
	}
	res.RecoveryOK = true
	res.RecoveryMS = (time.Since(restartStart)).Milliseconds()
	res.Status = acceptance.Success
	return res
}

func TestRealOpenVPN(t *testing.T) {
	profiles := openvpnRealnetProfiles(t)
	singboxPath := os.Getenv("BYPATH_SINGBOX")
	if singboxPath == "" {
		t.Skip("BYPATH_SINGBOX not set")
	}
	basePort, _ := strconv.Atoi(os.Getenv("BYPATH_REALNET_BASE_PORT"))
	if basePort <= 1024 {
		basePort = 24300
	}

	before := hostNetworkSnapshot(t)
	defer func() {
		after := hostNetworkSnapshot(t)
		if before != after {
			t.Errorf("host routes/DNS/interfaces changed during the OpenVPN test")
			t.Logf("before:\n%s", before)
			t.Logf("after:\n%s", after)
		}
	}()

	egressCtx, cancelEgress := context.WithTimeout(context.Background(), 15*time.Second)
	direct := directEgress(egressCtx, 10*time.Second)
	cancelEgress()
	t.Logf("profiles=%d direct_egress=%q", len(profiles), direct)

	results := make([]openvpnRealResult, 0, len(profiles))
	ok := 0
	blocked := 0
	for i, p := range profiles {
		res := runOpenVPNProfile(t, p, singboxPath, direct, basePort+i)
		results = append(results, res)
		if res.Status == acceptance.BlockedByNetwork {
			blocked++
		}
		if res.Status == acceptance.Success {
			ok++
			t.Logf("[%s] %s %s:%s ok handshake=%dms latency=%dms egress=%s (direct %s, differs=%v) dns_intact=%v recovery=%dms",
				res.Profile, res.Proto, res.Server, res.Proto, res.HandshakeMS, res.LatencyMS, res.ProxyEgress, res.DirectEgress, res.EgressDiffers, res.HostDNSIntact, res.RecoveryMS)
		} else {
			t.Logf("[%s] %s status=%s detail=%s", res.Profile, res.Proto, res.Status, res.Detail)
		}
	}

	if outPath := os.Getenv("BYPATH_OPENVPN_OUT"); outPath != "" {
		data, _ := json.MarshalIndent(map[string]interface{}{
			"generated_at":  time.Now().UTC().Format(time.RFC3339),
			"profiles":      len(profiles),
			"success":       ok,
			"direct_egress": direct,
			"results":       results,
		}, "", "  ")
		if err := os.WriteFile(outPath, data, 0600); err != nil {
			t.Errorf("writing results: %v", err)
		}
	}

	t.Logf("summary: %d/%d profiles passed handshake+HTTPS+recovery, %d blocked by network", ok, len(profiles), blocked)

	// Feed the observed outcome through the expected-results matrix so a
	// blocked or partial run can never be reported as a pass.
	observed := acceptance.Failed
	switch {
	case ok > 0:
		observed = acceptance.Success
	case blocked == len(profiles):
		observed = acceptance.BlockedByNetwork
	}
	if matrixCase, found := acceptance.Standard().Case("openvpn.sing-box-endpoint"); found {
		res := acceptance.Result{Case: matrixCase.ID, Status: observed}
		if err := matrixCase.Evaluate(res); err != nil {
			t.Errorf("acceptance matrix: %v", err)
		}
		recordAcceptanceEvidence(t, res)
	}

	if ok == 0 {
		if blocked == len(profiles) {
			t.Skip("every OpenVPN attempt was blocked by the observed network state; no success is claimed")
		}
		t.Fatalf("no OpenVPN profile completed an HTTPS round trip")
	}
}
