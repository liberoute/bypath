package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/liberoute/bypath/internal/bench"
	"github.com/liberoute/bypath/internal/profile"
)

// The operational layer: a carried HTTPS request is a measurement even when the
// exit identity is shared or blocked. These tests pin both halves of the rule --
// numbers are kept for a real answer, and nothing is measured when the traffic
// did not demonstrably leave through the tested instance.

func fixtureLink() *profile.Link {
	return &profile.Link{
		Group: "lab", Remark: "shared-exit", Protocol: "vless",
		Address: "example.net", Port: 443,
		UUID: "33333333-3333-3333-3333-333333333333",
	}
}

// stubIsolatedSeams replaces the engine session, probe, identity and sample
// seams so measureIsolated runs fully offline. Each test overrides what it
// needs after this returns.
func stubIsolatedSeams(t *testing.T) {
	t.Helper()
	cfg := []byte(auditProxyConfig)
	file := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(file, cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	session := &bench.Session{Engine: "sing-box", Port: 19001, Config: cfg, ConfigFile: file, EngineOwned: true}
	prevOpen, prevProbe, prevExit, prevSample, prevDiag := openTestSession, pickTestProbe, readTestExit, sampleTestSession, diagnoseEndpoint
	t.Cleanup(func() {
		openTestSession, pickTestProbe, readTestExit, sampleTestSession, diagnoseEndpoint = prevOpen, prevProbe, prevExit, prevSample, prevDiag
	})
	openTestSession = func(context.Context, *profile.Link, bench.Options) (*bench.Session, error) { return session, nil }
	pickTestProbe = func(context.Context, int) (string, error) { return "https://probe.example/", nil }
	sampleTestSession = func(*bench.Session, context.Context, string, int64) (time.Duration, []byte, error) {
		return 64 * time.Millisecond, []byte("ok"), nil
	}
	diagnoseEndpoint = func(context.Context, *profile.Link, bench.Options) error { return nil }
}

func agreeOn(ip string) (string, []EchoResult, error) {
	return ip, []EchoResult{{Service: "echo-a", IP: ip}, {Service: "echo-b", IP: ip}}, nil
}

func runIsolated(t *testing.T, shared testShared) TestResult {
	t.Helper()
	svc, _ := newTestLocal(t)
	link := fixtureLink()
	res, _, _ := svc.measureIsolated(context.Background(),
		testTarget{id: "lab:shared-exit", link: link}, shared, TestKindLatency, nil, 0)
	return res
}

func TestMeasuredHTTPSWithUnprovenExitKeepsNumbers(t *testing.T) {
	cases := []struct {
		name       string
		isolation  bool
		exit       string
		exitErr    error
		uplink     string
		serving    string
		wantReason string
	}{
		{"identity services blocked", true, "", errors.New("all identity services timed out"), "198.51.100.9", "", ReasonExitUnknown},
		{"exit shared with the serving connection", true, "198.51.100.7", nil, "198.51.100.9", "198.51.100.7", ReasonExitEqualsServing},
		{"isolation not verified on this host", false, "203.0.113.9", nil, "198.51.100.9", "", ReasonIsolationUnverified},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stubIsolatedSeams(t)
			readTestExit = func(context.Context, int, string, string) (string, []EchoResult, error) {
				if tc.exitErr != nil {
					return "", nil, tc.exitErr
				}
				return agreeOn(tc.exit)
			}
			res := runIsolated(t, testShared{uplink: tc.uplink, servingExit: tc.serving, isolation: tc.isolation})

			if res.Status != TestStatusMeasured || res.Evidence != EvidenceOperational {
				t.Fatalf("status=%q evidence=%q reason=%q, want measured/operational", res.Status, res.Evidence, res.Reason)
			}
			if res.Category != CategoryExitUnverified {
				t.Fatalf("category = %q, want %q", res.Category, CategoryExitUnverified)
			}
			if res.Reason != tc.wantReason {
				t.Fatalf("reason = %q, want %q (%s)", res.Reason, tc.wantReason, res.Detail)
			}
			if !res.HTTPSProven || res.Path == nil || !res.Path.TunneledHTTPS {
				t.Fatalf("HTTPS answer was not recorded: %+v", res)
			}
			if res.P50MS != 64 || res.LatencyMS != 64 || res.P90MS != 64 {
				t.Fatalf("latency was not kept: %+v", res)
			}
			if VerifiedTestResult(res) {
				t.Fatal("an operational result was certified as a proven path")
			}
			if res.Detail == "" {
				t.Fatal("a measured result must explain what is unproven")
			}
		})
	}
}

func TestExitEqualsUplinkIsStillAHardRefusal(t *testing.T) {
	stubIsolatedSeams(t)
	readTestExit = func(context.Context, int, string, string) (string, []EchoResult, error) {
		return agreeOn("203.0.113.9")
	}
	res := runIsolated(t, testShared{uplink: "203.0.113.9", servingExit: "198.51.100.7", isolation: true})
	if res.Status != TestStatusInconclusive || res.Reason != ReasonExitEqualsUplink {
		t.Fatalf("direct-path traffic was accepted: %+v", res)
	}
	if res.P50MS != 0 || res.LatencyMS != 0 || res.MBps != 0 || res.Bytes != 0 {
		t.Fatalf("refused row kept a measurement: %+v", res)
	}
}

func TestProbeFailureIsFailedNotMeasured(t *testing.T) {
	stubIsolatedSeams(t)
	pickTestProbe = func(context.Context, int) (string, error) {
		return "", errors.New("probe endpoint refused the connection")
	}
	readTestExit = func(context.Context, int, string, string) (string, []EchoResult, error) {
		t.Fatal("identity was read after the HTTPS probe failed")
		return "", nil, nil
	}
	res := runIsolated(t, testShared{uplink: "198.51.100.9", isolation: true})
	if res.Status != TestStatusFailed || res.Category != CategoryInfrastructure {
		t.Fatalf("probe failure = %q/%q, want failed/%q", res.Status, res.Category, CategoryInfrastructure)
	}
	if res.HTTPSProven || res.P50MS != 0 {
		t.Fatalf("a failed probe produced a measurement: %+v", res)
	}
	if strings.Contains(res.Detail, "refused") {
		t.Fatalf("engine error text leaked into the detail: %q", res.Detail)
	}
}

func TestSampleTimeoutProducesNoMeasurement(t *testing.T) {
	stubIsolatedSeams(t)
	readTestExit = func(context.Context, int, string, string) (string, []EchoResult, error) {
		return agreeOn("203.0.113.9")
	}
	sampleTestSession = func(*bench.Session, context.Context, string, int64) (time.Duration, []byte, error) {
		return 0, nil, context.DeadlineExceeded
	}
	res := runIsolated(t, testShared{uplink: "198.51.100.9", isolation: true})
	if res.Status != TestStatusFailed {
		t.Fatalf("timed-out samples = %q, want failed", res.Status)
	}
	if res.Evidence == EvidenceVerified || res.P50MS != 0 || VerifiedTestResult(res) {
		t.Fatalf("timeout produced a certified measurement: %+v", res)
	}
}

// A speed job must be serial, stop on the bytes it actually spent, and mark a
// budget stop as skipped rather than failed.
func TestSpeedBatchStopsOnActualSpend(t *testing.T) {
	svc, _ := newTestLocal(t)
	stubHostLoad(t, false, "")
	svc.Config().Tests.SpeedPerLinkMB = 10
	svc.Config().Tests.SpeedPerBatchMB = 20
	ctx := context.Background()
	for _, uri := range []string{
		"vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&type=ws#node-a",
		"vless://22222222-2222-2222-2222-222222222222@example.net:443?security=tls&type=ws#node-b",
		"vless://33333333-3333-3333-3333-333333333333@example.org:443?security=tls&type=ws#node-c",
	} {
		if _, err := svc.ImportURI(ctx, "default", uri); err != nil {
			t.Fatal(err)
		}
	}
	probeSuppressor(svc)
	const spent = int64(10 << 20)
	svc.testMeasure = func(tgt testTarget) (TestResult, int64) {
		return TestResult{
			ConnectionID: tgt.id, Group: tgt.link.Group, Remark: tgt.link.Remark,
			Kind: TestKindSpeed, Status: TestStatusMeasured, Evidence: EvidenceOperational,
			HTTPSProven: true, MBps: 40, Bytes: spent, Seconds: 4, P50MS: 30,
			TestedAt: proofTimestamp(),
		}, spent
	}
	job, err := svc.StartTestJob(ctx, TestRequest{Kind: TestKindSpeed, Scope: TestScope{Kind: TestScopeAll}})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if job.PlannedLinks != 2 || job.BudgetSkipped != 1 || job.PlannedBytes != 20<<20 {
		t.Fatalf("plan = %d links, %d skipped, %d bytes", job.PlannedLinks, job.BudgetSkipped, job.PlannedBytes)
	}
	waitJobState(t, svc, job.ID, TestJobDone)
	done, _ := svc.GetTestJob(ctx, job.ID)
	if len(done.Results) != 3 {
		t.Fatalf("results = %d, want 3 (measured and skipped rows)", len(done.Results))
	}
	measured, skipped := 0, 0
	for _, res := range done.Results {
		switch res.Status {
		case TestStatusMeasured:
			measured++
			if res.Bytes != spent || res.MBps <= 0 || res.Seconds <= 0 {
				t.Fatalf("measured row lost its numbers: %+v", res)
			}
		case TestStatusSkipped:
			skipped++
			if res.Reason != ReasonBudgetReached || res.Bytes != 0 || res.MBps != 0 {
				t.Fatalf("budget stop leaked numbers: %+v", res)
			}
		default:
			t.Fatalf("unexpected status after the budget stop: %+v", res)
		}
	}
	if measured != 2 || skipped != 1 {
		t.Fatalf("measured=%d skipped=%d, want 2 and 1", measured, skipped)
	}
}

// The batch is charged by real spend, so a cheaper run may cover more
// connections than the worst-case plan promised.
func TestSpeedBatchUsesActualSpendBeyondPlan(t *testing.T) {
	svc, _ := newTestLocal(t)
	stubHostLoad(t, false, "")
	svc.Config().Tests.SpeedPerLinkMB = 10
	svc.Config().Tests.SpeedPerBatchMB = 25
	ctx := context.Background()
	for _, uri := range []string{
		"vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&type=ws#node-a",
		"vless://22222222-2222-2222-2222-222222222222@example.net:443?security=tls&type=ws#node-b",
		"vless://33333333-3333-3333-3333-333333333333@example.org:443?security=tls&type=ws#node-c",
	} {
		if _, err := svc.ImportURI(ctx, "default", uri); err != nil {
			t.Fatal(err)
		}
	}
	probeSuppressor(svc)
	svc.testMeasure = func(tgt testTarget) (TestResult, int64) {
		return TestResult{
			ConnectionID: tgt.id, Group: tgt.link.Group, Remark: tgt.link.Remark,
			Kind: TestKindSpeed, Status: TestStatusMeasured, Evidence: EvidenceOperational,
			HTTPSProven: true, MBps: 12, Bytes: 5 << 20, Seconds: 1, P50MS: 40,
			TestedAt: proofTimestamp(),
		}, 5 << 20
	}
	job, err := svc.StartTestJob(ctx, TestRequest{Kind: TestKindSpeed, Scope: TestScope{Kind: TestScopeAll}})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if job.PlannedLinks != 2 {
		t.Fatalf("planned links = %d, want the worst-case 2", job.PlannedLinks)
	}
	waitJobState(t, svc, job.ID, TestJobDone)
	done, _ := svc.GetTestJob(ctx, job.ID)
	if done.Completed != 3 {
		t.Fatalf("completed = %d, want 3 actual-spend measurements", done.Completed)
	}
	for _, res := range done.Results {
		if res.Status != TestStatusMeasured {
			t.Fatalf("cheap run skipped a connection the actual spend allowed: %+v", res)
		}
	}
}

// probeSuppressor installs an injected link test so runTestJob performs no live
// uplink or serving probes; the speed path must not call it.
func probeSuppressor(svc *Local) {
	svc.testLink = func(context.Context, testTarget, testShared) TestResult {
		return TestResult{Status: TestStatusSkipped}
	}
}

func TestSpeedPreflightAcceptsOperationalAnswerOnly(t *testing.T) {
	svc, _ := newTestLocal(t)
	id := "lab:shared-exit"
	tcpOnly := TestResult{
		ConnectionID: id, Group: "lab", Remark: "shared-exit", Kind: TestKindLatency,
		Status: TestStatusInconclusive, Reason: ReasonExitUnknown,
		Path: &PathProof{Kind: "isolated"}, TestedAt: proofTimestamp(),
	}
	if operationalHTTPS(tcpOnly) {
		t.Fatal("a row without an HTTPS answer qualified for a speed run")
	}
	svc.saveTestResult(id, tcpOnly)
	if ok, _ := svc.speedPreflight(id); ok {
		t.Fatal("preflight accepted a TCP-only row")
	}

	legacy := TestResult{
		ConnectionID: id, Group: "lab", Remark: "shared-exit", Kind: TestKindLatency,
		Status: TestStatusInconclusive, Reason: ReasonExitUnknown, P50MS: 70,
		Path: &PathProof{Kind: "isolated", TunneledHTTPS: true}, TestedAt: proofTimestamp(),
	}
	if !operationalHTTPS(legacy) {
		t.Fatal("a pre-operational row with a tunneled HTTPS probe did not qualify")
	}

	shared := TestResult{
		ConnectionID: id, Group: "lab", Remark: "shared-exit", Kind: TestKindLatency,
		Status: TestStatusMeasured, Evidence: EvidenceOperational, HTTPSProven: true,
		P50MS: 55, Reason: ReasonExitEqualsServing, TestedAt: proofTimestamp(),
	}
	svc.saveTestResult(id, shared)
	if ok, why := svc.speedPreflight(id); !ok {
		t.Fatalf("a shared exit blocked the speed preflight: %s", why)
	}
}

func TestMeasuredRowsParticipateInSupersession(t *testing.T) {
	older := TestResult{ConnectionID: "lab:x", Status: TestStatusMeasured, TestedAt: "2026-01-01T00:00:00Z"}
	newer := TestResult{ConnectionID: "lab:x", Status: TestStatusFailed, TestedAt: "2026-01-01T00:01:00Z"}
	results := []TestResult{older, newer}
	InvalidateSupersededResults(results)
	if !results[0].Superseded || results[1].Superseded {
		t.Fatalf("an older measured row survived a later failure: %+v", results)
	}

	older = TestResult{ConnectionID: "lab:y", Status: TestStatusFailed, TestedAt: "2026-01-01T00:00:00Z"}
	newer = TestResult{ConnectionID: "lab:y", Status: TestStatusMeasured, TestedAt: "2026-01-01T00:01:00Z"}
	results = []TestResult{older, newer}
	InvalidateSupersededResults(results)
	if results[0].Superseded || results[1].Superseded {
		t.Fatalf("a later measured row was superseded by an older failure: %+v", results)
	}
}

func TestWorkerMeasuredRowNeedsAnHTTPSAnswer(t *testing.T) {
	job := WorkerJob{ConnectionID: "lab:x", Group: "lab", Remark: "x", Kind: TestKindLatency, DaemonNetNS: "netns-daemon"}
	proof := WorkerProof{SelfNetNS: "netns-host", InitNetNS: "netns-host", DaemonNetNS: "netns-daemon", Isolation: true}
	good := WorkerResult{
		Proof: proof,
		Result: TestResult{
			ConnectionID: "lab:x", Group: "lab", Remark: "x", Kind: TestKindLatency,
			Status: TestStatusMeasured, Evidence: EvidenceOperational, HTTPSProven: true, P50MS: 25,
		},
	}
	if err := validateWorkerResult(job, good); err != nil {
		t.Fatalf("a measured row with an HTTPS answer was refused: %v", err)
	}
	noHTTPS := good
	noHTTPS.Result.HTTPSProven = false
	if err := validateWorkerResult(job, noHTTPS); err == nil {
		t.Fatal("a measured row without an HTTPS answer was accepted")
	}
	noNumbers := good
	noNumbers.Result.P50MS = 0
	if err := validateWorkerResult(job, noNumbers); err == nil {
		t.Fatal("a measured row without a number was accepted")
	}
}
