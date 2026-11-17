package app

import (
	"context"
	"errors"
	"net"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/engine"
	"github.com/liberoute/bypath/internal/profile"
	"github.com/liberoute/bypath/internal/tunnel"
)

const auditProxyConfig = `{
  "inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": 19001}],
  "outbounds": [
    {"type": "vless", "tag": "proxy", "server": "example.net", "server_port": 443, "uuid": "33333333-3333-3333-3333-333333333333"},
    {"type": "block", "tag": "block"}
  ],
  "route": {"final": "proxy"}
}`

func TestAuditIsolatedConfig(t *testing.T) {
	cases := []struct {
		name    string
		config  string
		wantErr string
	}{
		{"proxy only", auditProxyConfig, ""},
		{"direct outbound", `{"outbounds":[{"type":"vless","tag":"proxy","server":"a","server_port":1,"uuid":"x"},{"type":"direct","tag":"direct"}],"route":{"final":"proxy"}}`, "direct"},
		{"direct rule", `{"outbounds":[{"type":"vless","tag":"proxy","server":"a","server_port":1,"uuid":"x"},{"type":"block","tag":"block"}],"route":{"rules":[{"domain_suffix":["ir"],"outbound":"direct"}],"final":"proxy"}}`, "routes to"},
		{"final direct", `{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}`, "direct"},
		{"xray freedom", `{"outbounds":[{"protocol":"freedom","tag":"direct"}]}`, "freedom"},
		{"xray freedom rule", `{"outbounds":[{"protocol":"vless","tag":"proxy"}],"routing":{"rules":[{"type":"field","outboundTag":"direct"}]}}`, "routes to"},
		{"tun inbound", `{"inbounds":[{"type":"tun","tag":"tun"}],"outbounds":[{"type":"vless","tag":"proxy"}],"route":{"final":"proxy"}}`, "tun"},
		{"auto route", `{"inbounds":[{"type":"mixed","auto_route":true}],"outbounds":[{"type":"vless","tag":"proxy"}],"route":{"final":"proxy"}}`, "auto_route"},
		{"no outbound", `{"inbounds":[{"type":"mixed","listen":"127.0.0.1"}],"route":{"final":"proxy"}}`, "no non-direct outbound"},
		{"invalid json", `{`, "not valid JSON"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := auditIsolatedConfig([]byte(tc.config))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected audit error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("audit error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestMedianAndPercentile(t *testing.T) {
	d := []time.Duration{30 * time.Millisecond, 10 * time.Millisecond, 20 * time.Millisecond}
	if got := median(d); got != 20*time.Millisecond {
		t.Fatalf("median = %v", got)
	}
	if got := percentile(d, 0.9); got != 30*time.Millisecond {
		t.Fatalf("p90 = %v", got)
	}
	if median(nil) != 0 || percentile(nil, 0.9) != 0 {
		t.Fatal("empty samples must be zero")
	}
}

func TestStopReasonCodesAreStable(t *testing.T) {
	// The UI switches on these strings; renaming one silently breaks ranking.
	for _, code := range []string{
		ReasonConfigNotIsolated, ReasonPathDirectTarget, ReasonExitEqualsUplink,
		ReasonExitEqualsServing, ReasonExitAmbiguous, ReasonExitChanged,
		ReasonExitUnknown, ReasonPolicyChanged, ReasonControlFailed,
		ReasonRouteExplainMissing, ReasonIsolationUnverified,
	} {
		if code != strings.ToUpper(code) || strings.Contains(code, " ") {
			t.Fatalf("unstable reason code %q", code)
		}
	}
}

func TestTestJobLifecycle(t *testing.T) {
	svc, _ := newTestLocal(t)
	ctx := context.Background()
	for _, uri := range []string{
		"vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&type=ws#node-a",
		"vless://22222222-2222-2222-2222-222222222222@example.net:443?security=tls&type=ws#node-b",
	} {
		if _, err := svc.ImportURI(ctx, "default", uri); err != nil {
			t.Fatal(err)
		}
	}

	release := make(chan struct{})
	svc.testLink = func(ctx context.Context, target testTarget, shared testShared) TestResult {
		select {
		case <-release:
		case <-ctx.Done():
			return TestResult{ConnectionID: target.id, Group: target.link.Group, Remark: target.link.Remark, Status: TestStatusCancelled}
		}
		return TestResult{ConnectionID: target.id, Group: target.link.Group, Remark: target.link.Remark, Status: TestStatusOK, LatencyMS: 12, P50MS: 12, P90MS: 15}
	}

	job, err := svc.StartTestJob(ctx, TestRequest{Kind: TestKindLatency, Scope: TestScope{Kind: TestScopeGroup, Group: "default"}})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if job.Total != 2 || job.State != TestJobRunning {
		t.Fatalf("unexpected initial job: %+v", job)
	}
	if _, err := svc.StartTestJob(ctx, TestRequest{Scope: TestScope{Kind: TestScopeGroup, Group: "default"}}); err == nil || CodeOf(err) != CodeConflict {
		t.Fatalf("second job error = %v, want conflict", err)
	}
	close(release)
	waitJobState(t, svc, job.ID, TestJobDone)
	done, err := svc.GetTestJob(ctx, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if done.Completed != 2 || len(done.Results) != 2 {
		t.Fatalf("completed=%d results=%d", done.Completed, len(done.Results))
	}
	for _, res := range done.Results {
		if res.Status != TestStatusOK || res.LatencyMS != 12 {
			t.Fatalf("unexpected result: %+v", res)
		}
	}
	backlog, _, stop, err := svc.SubscribeTestEvents(job.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	stop()
	if len(backlog) < 3 {
		t.Fatalf("expected result and terminal events, got %d", len(backlog))
	}
}

func TestTestJobCancelStopsWorkers(t *testing.T) {
	svc, _ := newTestLocal(t)
	ctx := context.Background()
	if _, err := svc.ImportURI(ctx, "default", "vless://33333333-3333-3333-3333-333333333333@example.net:443?security=tls&type=ws#slow"); err != nil {
		t.Fatal(err)
	}
	svc.testLink = func(ctx context.Context, target testTarget, shared testShared) TestResult {
		<-ctx.Done()
		return TestResult{ConnectionID: target.id, Status: TestStatusCancelled}
	}
	job, err := svc.StartTestJob(ctx, TestRequest{Scope: TestScope{Kind: TestScopeAll}})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if err := svc.CancelTestJob(ctx, job.ID); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	waitJobState(t, svc, job.ID, TestJobCancelled)
	done, _ := svc.GetTestJob(ctx, job.ID)
	if done.Completed != 1 || done.Results[0].Status != TestStatusCancelled {
		t.Fatalf("cancelled result missing: %+v", done)
	}
}

func waitJobState(t *testing.T, svc *Local, id, want string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		job, err := svc.GetTestJob(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if job.State == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	job, _ := svc.GetTestJob(context.Background(), id)
	t.Fatalf("job state = %s (%+v), want %s", job.State, job, want)
}

func TestLivePathRefusesDirectRoutedTarget(t *testing.T) {
	svc, _ := newTestLocal(t)
	ctx := context.Background()
	if _, err := svc.ImportURI(ctx, "default", "vless://44444444-4444-4444-4444-444444444444@example.net:443?security=tls&type=ws#serving"); err != nil {
		t.Fatal(err)
	}
	cfg := svc.Config()
	cfg.Routing.Rules = []config.RoutingRule{
		{Match: "domain_suffix:ipify.org", Outbound: "direct"},
		{Match: "default", Outbound: "proxy"},
	}
	// The live path refuses to measure a route it cannot compute. sing-box
	// resolves before its builtin private rule, so the connected gateway needs
	// an answering resolver for the decision to be certain.
	svc.runtime = &fakeRuntime{state: "CONNECTED"}
	cfg.Server.DNSPort = startFakeDNS(t, net.IPv4(203, 0, 113, 9))
	link, _, err := svc.findLink("default:serving")
	if err != nil {
		t.Fatal(err)
	}
	shared := testShared{uplink: "203.0.113.9", servingExit: "198.51.100.7", servingLink: link}

	res := svc.runLiveLinkTest(ctx, testTarget{link: link, id: "default:serving"}, shared)
	if res.Status != TestStatusInconclusive || res.Reason != ReasonPathDirectTarget {
		t.Fatalf("DIRECT-routed target was not refused: %+v", res)
	}
	if res.Path == nil || res.Path.Kind != "live" || len(res.Path.RouteDecisions) != 1 {
		t.Fatalf("live proof missing route decision: %+v", res.Path)
	}
	if res.LatencyMS != 0 {
		t.Fatalf("latency stored for a refused path: %+v", res)
	}
}

func TestLivePathNeverStartsAnIsolatedInstance(t *testing.T) {
	svc, _ := newTestLocal(t)
	ctx := context.Background()
	if _, err := svc.ImportURI(ctx, "default", "vless://55555555-5555-5555-5555-555555555555@example.net:443?security=tls&type=ws#serving"); err != nil {
		t.Fatal(err)
	}
	link, _, err := svc.findLink("default:serving")
	if err != nil {
		t.Fatal(err)
	}
	// The SOCKS port has no listener, so the identity probe fails quickly; the
	// assertion is that the runner chose the live path and spawned no engine.
	// A live measurement needs a certain route decision, so the connected
	// gateway answers DNS for the probe names.
	svc.runtime = &fakeRuntime{state: "CONNECTED"}
	svc.Config().Server.DNSPort = startFakeDNS(t, net.IPv4(203, 0, 113, 9))
	shared := testShared{servingLink: link}
	res := svc.runLinkTest(ctx, testTarget{link: link, id: "default:serving"}, shared)
	if res.Path == nil || res.Path.Kind != "live" {
		t.Fatalf("serving link did not use the live path: %+v", res)
	}
	if res.Status == TestStatusOK {
		t.Fatalf("unreachable live path reported ok: %+v", res)
	}
}

// TestGeneratedTestConfigPassesIsolationAudit pins the contract between the
// engine config generator (used by bench/test instances) and the isolated
// config audit. Before internal/tunnel.IsolateConfig existed, the generator's
// always-present direct outbound made every isolated test Inconclusive with
// CONFIG_NOT_ISOLATED on a live gateway (found on the lab, 2026-11-11).
func TestGeneratedTestConfigPassesIsolationAudit(t *testing.T) {
	link := &profile.Link{
		Remark:     "Relay-Lab",
		Protocol:   "shadowsocks",
		Address:    "10.20.30.200",
		Port:       18389,
		Security:   "2022-blake3-aes-256-gcm",
		UUID:       "lab-password",
		ListenPort: 19001,
	}
	cg := tunnel.NewConfigGenerator(t.TempDir())
	configFile, err := cg.Generate(&engine.Engine{Name: "sing-box"}, link)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	raw, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := auditIsolatedConfig(raw); err == nil {
		t.Fatal("generator output passed the audit unmodified; the fixture no longer reproduces the bug")
	}
	isolated, err := tunnel.IsolateConfig(raw)
	if err != nil {
		t.Fatalf("isolate: %v", err)
	}
	if err := auditIsolatedConfig(isolated); err != nil {
		t.Fatalf("isolated config failed the audit: %v", err)
	}
}

func TestUplinkInterfaceOnlyForNativeTunGateway(t *testing.T) {
	base := func() *config.Config {
		c := &config.Config{}
		c.Gateway.Enabled = true
		c.Gateway.NativeTUN = true
		c.Gateway.Interface = "eth0"
		return c
	}
	if got := uplinkInterface(base()); got != "eth0" {
		t.Fatalf("gateway iface: got %q", got)
	}
	c := base()
	c.Gateway.NativeTUN = false
	if got := uplinkInterface(c); got != "" {
		t.Fatalf("tun2socks mode must stay unbound: got %q", got)
	}
	c = base()
	c.Gateway.Enabled = false
	if got := uplinkInterface(c); got != "" {
		t.Fatalf("proxy-only mode must stay unbound: got %q", got)
	}
	c = base()
	c.Gateway.Interface = "auto"
	if got := uplinkInterface(c); got != "" {
		t.Fatalf("auto interface must stay unbound: got %q", got)
	}
	if got := uplinkInterface(nil); got != "" {
		t.Fatalf("nil config: got %q", got)
	}
}

// The uplink probe must not emit DNS: a resolver query would follow the host
// resolver, which under a strict native-TUN gateway is the tunneled path itself.
func TestUplinkTraceEndpointsNeedNoDNS(t *testing.T) {
	if len(uplinkTraceEndpoints) == 0 {
		t.Fatal("no uplink trace endpoints configured")
	}
	for _, raw := range uplinkTraceEndpoints {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("bad endpoint %q: %v", raw, err)
		}
		if net.ParseIP(u.Hostname()) == nil {
			t.Fatalf("endpoint %q is not an IP literal, so it needs DNS", raw)
		}
	}
}

func TestParseTraceIP(t *testing.T) {
	cases := map[string]string{
		"fl=20f694\nh=1.1.1.1\nip=203.0.113.7\nts=1.0\n": "203.0.113.7",
		"ip=2001:db8::7\n":  "2001:db8::7",
		"fl=1\nh=1.1.1.1\n": "",
		"ip=not-an-ip\n":    "",
		"":                  "",
	}
	for body, want := range cases {
		if got := parseTraceIP([]byte(body)); got != want {
			t.Fatalf("parseTraceIP(%q) = %q, want %q", body, got, want)
		}
	}
}

func TestParseEchoIPAcceptsBareAddressAndTrace(t *testing.T) {
	cases := map[string]string{
		"203.0.113.7\n": "203.0.113.7",
		"2001:db8::7":   "2001:db8::7",
		"fl=1\nh=www.cloudflare.com\nip=198.51.100.9\nts=1\n": "198.51.100.9",
		"":     "",
		"204 ": "",
	}
	for body, want := range cases {
		got, err := parseEchoIP([]byte(body))
		if want == "" {
			if err == nil {
				t.Fatalf("parseEchoIP(%q) = %q, want an error", body, got)
			}
			continue
		}
		if err != nil || got != want {
			t.Fatalf("parseEchoIP(%q) = %q, %v; want %q", body, got, err, want)
		}
	}
}

// The live-path control must fail closed and must only pass when a
// DIRECT-routed request actually exits through the observed uplink.
func TestNegativeControlVerdict(t *testing.T) {
	const uplink = "188.121.134.78"
	cases := []struct {
		name       string
		route      string
		uplink     string
		controlIP  string
		err        error
		wantState  string
		wantReason string
	}{
		{"direct exits through uplink", "DIRECT", uplink, uplink, nil, negativeControlPass, ""},
		{"direct exits elsewhere", "DIRECT", uplink, "91.107.181.141", nil, negativeControlFailed, ReasonControlFailed},
		{"control body unreadable", "DIRECT", uplink, "", errors.New("unexpected echo response"), negativeControlFailed, ReasonControlFailed},
		{"uplink unknown", "DIRECT", "", uplink, nil, negativeControlFailed, ReasonControlFailed},
		{"control routed through tunnel", "PROXY", uplink, "", nil, negativeControlNotApplicable, ""},
	}
	for _, tc := range cases {
		state, reason, detail := negativeControlVerdict(tc.route, tc.uplink, tc.controlIP, tc.err)
		if state != tc.wantState || reason != tc.wantReason {
			t.Fatalf("%s: got (%q, %q), want (%q, %q)", tc.name, state, reason, tc.wantState, tc.wantReason)
		}
		if state == negativeControlFailed && detail == "" {
			t.Fatalf("%s: a failed control must carry a detail", tc.name)
		}
	}
}

// The control endpoint changed from cp.cloudflare.com (204, empty body) to the
// trace endpoint. Both must keep the same DIRECT suffix, and an empty body must
// never be read as an observed address.
func TestNegativeControlEndpointEchoesTheObservedAddress(t *testing.T) {
	u, err := url.Parse(negativeControlURL)
	if err != nil {
		t.Fatalf("negative control URL %q: %v", negativeControlURL, err)
	}
	if u.Scheme != "https" || u.Hostname() != negativeControlHost {
		t.Fatalf("control %q is not https on the control host %q", negativeControlURL, negativeControlHost)
	}
	if !strings.HasSuffix(u.Path, "/cdn-cgi/trace") {
		t.Fatalf("control %q is not a trace endpoint, so it cannot echo an address", negativeControlURL)
	}
	for _, body := range [][]byte{nil, []byte(""), []byte(" ")} {
		if ip, err := parseEchoIP(body); err == nil {
			t.Fatalf("an empty body was read as %q; a 204-style answer is not an address", ip)
		}
	}
	trace := []byte("fl=abc\nh=www.cloudflare.com\nip=198.51.100.9\nts=1\n")
	ip, err := parseEchoIP(trace)
	if err != nil || ip != "198.51.100.9" {
		t.Fatalf("trace body parsed as %q, %v; want 198.51.100.9", ip, err)
	}
	if state, _, _ := negativeControlVerdict("DIRECT", "198.51.100.9", ip, err); state != negativeControlPass {
		t.Fatalf("trace address equal to the uplink did not pass the control: %q", state)
	}
	if state, reason, _ := negativeControlVerdict("DIRECT", "198.51.100.9", "203.0.113.4", nil); state != negativeControlFailed || reason != ReasonControlFailed {
		t.Fatalf("a DIRECT request that exited elsewhere was accepted: (%q, %q)", state, reason)
	}
}

// A serving gateway runs one benchmark session at a time by default; the cap is
// explicit and never exceeds the S0.3 budget.
func TestTestSessionCapSerialOnServingGateway(t *testing.T) {
	serving := &config.Config{}
	serving.Gateway.Enabled = true
	if got := testSessionCap(serving); got != 1 {
		t.Fatalf("default serving cap: got %d, want 1", got)
	}
	if got := testParallelFor(TestKindLatency, 3, serving, 13); got != 1 {
		t.Fatalf("latency parallelism on a serving gateway: got %d, want 1", got)
	}
	serving.Tests.MaxSessions = 2
	if got := testSessionCap(serving); got != 2 {
		t.Fatalf("explicit cap: got %d, want 2", got)
	}
	serving.Tests.MaxSessions = 99
	if got := testSessionCap(serving); got != testMaxParallel {
		t.Fatalf("hard cap: got %d, want %d", got, testMaxParallel)
	}
	if got := testParallelFor(TestKindSpeed, 3, serving, 13); got != 1 {
		t.Fatalf("speed must stay serial: got %d", got)
	}

	lab := &config.Config{}
	if got := testSessionCap(lab); got != testMaxParallel {
		t.Fatalf("lab daemon cap: got %d, want %d", got, testMaxParallel)
	}
	if got := testParallelFor(TestKindLatency, 0, lab, 13); got != testDefaultParallel {
		t.Fatalf("lab default parallelism: got %d, want %d", got, testDefaultParallel)
	}
}
