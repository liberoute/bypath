package app

import (
	"context"
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
