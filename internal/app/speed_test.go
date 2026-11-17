package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/liberoute/bypath/internal/profile"
)

// stubHostLoad pins the host-load guard so a busy CI runner cannot change the
// outcome of a test that is about something else.
func stubHostLoad(t *testing.T, under bool, why string) {
	t.Helper()
	prev := hostUnderLoad
	hostUnderLoad = func() (bool, string) { return under, why }
	t.Cleanup(func() { hostUnderLoad = prev })
}

func TestSpeedTargetURLRules(t *testing.T) {
	rejected := []string{
		"",
		"http://dl.google.com/file",
		"ftp://dl.google.com/file",
		"file:///etc/passwd",
		"https://dl.google.com:8080/file",
		"https://dl.google.com:22/file",
		"https://user:pass@dl.google.com/file",
		"https://evil.example@127.0.0.1/",
		"https://127.0.0.1/",
		"https://[::1]/",
		"https://localhost/",
		"https://2130706433/",
		"https://0x7f.1/",
		"https://017700000001/",
		"https://dl.google.com./file",
		"https://intranet/file",
		"https://printer.local/",
		"https://nas.internal/",
		"https://router.lan/",
		"https://home.home/",
		"https://dl.google.com/file#frag",
		"https://dl.google.com/ file",
		"https://" + strings.Repeat("a", 600) + ".example/",
		"https://bücher.example/",
	}
	for _, raw := range rejected {
		if _, _, err := validateSpeedTargetURL(raw); err == nil {
			t.Errorf("accepted forbidden target %q", raw)
		}
	}
	accepted := []string{
		"https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb",
		"https://speed.example.net/payload.bin?region=eu",
	}
	for _, raw := range accepted {
		if _, _, err := validateSpeedTargetURL(raw); err != nil {
			t.Errorf("rejected valid target %q: %v", raw, err)
		}
	}
}

func TestDeniedAddressUnwraps(t *testing.T) {
	denied := []string{
		"0.0.0.0", "127.0.0.1", "10.0.0.1", "172.16.5.4", "192.168.1.1",
		"100.64.0.1", "169.254.169.254", "192.0.2.5", "198.18.0.1",
		"198.51.100.7", "203.0.113.9", "240.0.0.1",
		"::", "::1", "fe80::1", "fc00::1", "2001:db8::1",
		"::ffff:10.0.0.1", "::ffff:127.0.0.1",
		"64:ff9b::a00:1", "2002:0a00:0001::",
	}
	for _, raw := range denied {
		ip := net.ParseIP(raw)
		if ip == nil {
			t.Fatalf("bad test address %q", raw)
		}
		if deniedAddress(ip, nil) == "" {
			t.Errorf("allowed forbidden address %s", raw)
		}
	}
	allowed := []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"}
	for _, raw := range allowed {
		if why := deniedAddress(net.ParseIP(raw), nil); why != "" {
			t.Errorf("denied public address %s: %s", raw, why)
		}
	}
	// The host's own interface addresses are dynamic denials even when public.
	local := []*net.IPNet{{IP: net.ParseIP("9.9.9.9"), Mask: net.CIDRMask(32, 32)}}
	if why := deniedAddress(net.ParseIP("9.9.9.9"), local); why == "" {
		t.Fatal("an interface address was not denied")
	}
}

func TestDownloadStopsAtCap(t *testing.T) {
	const capBytes = 1 << 20
	var written atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") == "" {
			t.Error("request did not ask for a range")
		}
		w.WriteHeader(http.StatusPartialContent)
		buf := make([]byte, 32<<10)
		for written.Load() < 4<<20 {
			n, err := w.Write(buf)
			written.Add(int64(n))
			if err != nil {
				return
			}
		}
	}))
	defer server.Close()

	start := time.Now()
	res, err := downloadBounded(context.Background(), server.Client(), server.URL+"/payload", capBytes, 5*time.Second)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if res.Bytes != capBytes {
		t.Fatalf("counted %d bytes, want exactly %d", res.Bytes, capBytes)
	}
	if !res.SupportsRange {
		t.Fatal("206 response was not reported as range support")
	}
	if written.Load() >= 4<<20 {
		t.Fatalf("server streamed the whole body (%d bytes); the client never cut it", written.Load())
	}
	t.Logf("counted=%d server_written=%d elapsed=%s", res.Bytes, written.Load(), time.Since(start))
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	var hits int32
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer second.Close()
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, second.URL+"/elsewhere", http.StatusFound)
	}))
	defer first.Close()

	client := first.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	_, err := downloadBounded(context.Background(), client, first.URL+"/payload", 1024, time.Second)
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("redirect was not refused: %v", err)
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatal("the redirect target was contacted")
	}
}

func TestPipelineRefusesCompressedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte{0x1f, 0x8b})
	}))
	defer server.Close()
	_, err := downloadBounded(context.Background(), server.Client(), server.URL+"/x", 1024, time.Second)
	if err == nil || !strings.Contains(err.Error(), "compressed") {
		t.Fatalf("compressed response accepted: %v", err)
	}
}

func TestBudgetStopsRemainingLinks(t *testing.T) {
	cases := []struct {
		links             int
		perLink, perBatch int64
		want              int
	}{
		{10, 10 << 20, 40 << 20, 4},
		{2, 10 << 20, 40 << 20, 2},
		{3, 10 << 20, 10 << 20, 1},
		{3, 0, 40 << 20, 3},
	}
	for _, tc := range cases {
		if got := budgetLinkCount(tc.links, tc.perLink, tc.perBatch); got != tc.want {
			t.Errorf("budgetLinkCount(%d, %d, %d) = %d, want %d", tc.links, tc.perLink, tc.perBatch, got, tc.want)
		}
	}
	svc, _ := newTestLocal(t)
	skipped := svc.skippedResult(testTarget{id: "g:x", link: &profile.Link{Group: "g", Remark: "x"}}, ReasonBudgetReached, "traffic budget reached")
	if skipped.Status != TestStatusSkipped || skipped.Reason != ReasonBudgetReached {
		t.Fatalf("budget stop must be skipped, not failed: %+v", skipped)
	}
}

func TestSpeedJobRejectsUpload(t *testing.T) {
	svc, _ := newTestLocal(t)
	_, err := svc.StartTestJob(context.Background(), TestRequest{
		Kind:   TestKindSpeed,
		Scope:  TestScope{Kind: TestScopeAll},
		Upload: true,
	})
	if err == nil || CodeOf(err) != CodeInvalid {
		t.Fatalf("upload was not rejected: %v", err)
	}
}

func TestSpeedJobNeedsProvenRelay(t *testing.T) {
	svc, _ := newTestLocal(t)
	stubHostLoad(t, false, "")
	// A unit test must not probe the network. A non-nil link measurement also
	// makes the runner skip its uplink and serving-exit probes; the speed path
	// has to refuse before it measures anything at all.
	svc.testLink = func(context.Context, testTarget, testShared) TestResult {
		t.Errorf("a speed run must not execute a relay measurement")
		return TestResult{}
	}
	ctx := context.Background()
	if _, err := svc.ImportURI(ctx, "default", testVLESS); err != nil {
		t.Fatal(err)
	}
	job, err := svc.StartTestJob(ctx, TestRequest{Kind: TestKindSpeed, Scope: TestScope{Kind: TestScopeAll}})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	waitJobState(t, svc, job.ID, TestJobDone)
	done, err := svc.GetTestJob(ctx, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(done.Results) != 1 {
		t.Fatalf("unexpected results: %+v", done)
	}
	res := done.Results[0]
	if res.Status != TestStatusUnavailable || res.Reason != ReasonNoProvenResult {
		t.Fatalf("speed without a proven relay result was not refused: %+v", res)
	}
	if res.MBps != 0 || res.Bytes != 0 {
		t.Fatalf("refused speed result carried numbers: %+v", res)
	}
}

func TestTestParallelRespectsBudget(t *testing.T) {
	if got := testParallelFor(TestKindSpeed, 8, nil, 5); got != 1 {
		t.Fatalf("speed parallel = %d, want 1", got)
	}
	if got := testParallelFor(TestKindLatency, 8, nil, 5); got != testMaxParallel {
		t.Fatalf("latency parallel = %d, want %d", got, testMaxParallel)
	}
	if got := testParallelFor(TestKindLatency, 0, nil, 1); got != 1 {
		t.Fatalf("parallel must not exceed the link count: %d", got)
	}
}

func TestTestsNeverWriteProfileFiles(t *testing.T) {
	svc, p := newTestLocal(t)
	ctx := context.Background()
	if _, err := svc.ImportURI(ctx, "default", testVLESS); err != nil {
		t.Fatal(err)
	}
	before := hashDir(t, p.ProfileDir)
	svc.testLink = func(ctx context.Context, target testTarget, shared testShared) TestResult {
		return TestResult{
			ConnectionID: target.id, Group: target.link.Group, Remark: target.link.Remark,
			Kind: TestKindLatency, Status: TestStatusOK, LatencyMS: 9, P50MS: 9, P90MS: 12,
			TestedAt: time.Now().UTC().Format(time.RFC3339),
		}
	}
	job, err := svc.StartTestJob(ctx, TestRequest{Scope: TestScope{Kind: TestScopeAll}})
	if err != nil {
		t.Fatal(err)
	}
	waitJobState(t, svc, job.ID, TestJobDone)
	after := hashDir(t, p.ProfileDir)
	if len(before) == 0 {
		t.Fatal("no profile files to compare")
	}
	for name, sum := range after {
		if strings.HasPrefix(name, ".layer") {
			continue
		}
		if before[name] != sum {
			t.Fatalf("test run modified profile file %s", name)
		}
	}
	if len(after) != len(before) {
		t.Fatalf("test run added files outside .layer: before=%v after=%v", before, after)
	}
}

func hashDir(t *testing.T, dir string) map[string][32]byte {
	t.Helper()
	out := map[string][32]byte{}
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out[rel] = sha256.Sum256(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestRepeatedCancelledAttemptsChargeObservedBytes pins the budget rule: a
// cancelled transfer keeps its numbers out of the ranking but the payload it
// already received is real traffic and must still be charged. Repeating the
// cancellation used to add zero bytes each time and under-count the month.
func TestRepeatedCancelledAttemptsChargeObservedBytes(t *testing.T) {
	svc, _ := newTestLocal(t)
	const observed = int64(64 << 10)
	before, err := svc.layer.Usage()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		res := speedFailure(TestResult{Kind: TestKindSpeed}, TargetCheck{Host: "dl.google.com"}, context.Canceled)
		if res.Status != TestStatusCancelled || res.Bytes != 0 || res.MBps != 0 {
			t.Fatalf("cancelled row leaked a measurement: %+v", res)
		}
		svc.chargeSpeedAttempt(downloadResult{Bytes: observed / 2, Spent: observed})
	}
	after, err := svc.layer.Usage()
	if err != nil {
		t.Fatal(err)
	}
	if want := before.Bytes + 3*observed; after.Bytes != want {
		t.Fatalf("monthly bytes = %d, want %d after three cancellations", after.Bytes, want)
	}
}

// TestDownloadBoundedCountsBytesBeforeCancel proves the partial transfer is
// observable when the context is cancelled mid-body, which is the input the
// charging rule above needs. The transport is a stub so the fixture cannot
// race the cancellation.
func TestDownloadBoundedCountsBytesBeforeCancel(t *testing.T) {
	// One small chunk is served, then the body reports cancellation. The
	// window stays below downloadBounded's read buffer so the fixture cannot
	// deliver more bytes than the assertion expects.
	const chunk = 16 << 10
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Length": []string{"10485760"}},
			Body:       &cancelledBody{left: chunk},
		}, nil
	})}
	res, err := downloadBounded(context.Background(), client, "https://dl.google.com/file", 10<<20, time.Minute)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("downloadBounded error = %v, want context.Canceled", err)
	}
	if res.Bytes != chunk {
		t.Fatalf("observed bytes = %d, want %d", res.Bytes, chunk)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func okResponse(body io.ReadCloser) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: body}
}

// TestDownloadRateExcludesConnectionSetup pins the separation between setup and
// transfer. A slow handshake used to be counted as transfer time, so a 700 ms
// setup halved the reported rate of every small sample.
func TestDownloadRateExcludesConnectionSetup(t *testing.T) {
	const bodySize = 512 << 10
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		time.Sleep(600 * time.Millisecond) // connect + TLS + first byte
		return okResponse(&pacedBody{chunk: 32 << 10, interval: time.Millisecond, left: bodySize}), nil
	})}
	res, err := downloadBounded(context.Background(), client, "https://dl.google.com/file", bodySize, 5*time.Second)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if res.Bytes != bodySize || res.Received != bodySize {
		t.Fatalf("counted %d bytes, want %d", res.Bytes, bodySize)
	}
	if res.TTFB < 500*time.Millisecond {
		t.Fatalf("first response took %s; the fixture did not delay setup", res.TTFB)
	}
	if res.Duration > 300*time.Millisecond {
		t.Fatalf("rate window %s includes the setup delay", res.Duration)
	}
	if res.Total < res.TTFB {
		t.Fatalf("total %s is shorter than the setup %s", res.Total, res.TTFB)
	}
	if res.Mbps <= 0 {
		t.Fatalf("no rate was computed for a complete sample (bytes=%d window=%s total=%s)", res.Bytes, res.Duration, res.Total)
	}
}

// TestDownloadRateSkipsWarmupOnLongTransfers pins the second half of the same
// rule: a body that ran long enough to include TCP slow start ranks only its
// steady window, while every byte received is still reported for charging.
func TestDownloadRateSkipsWarmupOnLongTransfers(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return okResponse(&pacedBody{chunk: 32 << 10, interval: 25 * time.Millisecond, left: 120 * 32 << 10}), nil
	})}
	res, err := downloadBounded(context.Background(), client, "https://dl.google.com/file", 8<<20, 10*time.Second)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if res.Received != 120*32<<10 {
		t.Fatalf("received %d bytes, want the whole paced body", res.Received)
	}
	if res.Bytes >= res.Received {
		t.Fatalf("ranked %d of %d bytes; the warm-up was not discarded", res.Bytes, res.Received)
	}
	if res.Duration >= res.Total {
		t.Fatalf("rate window %s was not shortened within %s", res.Duration, res.Total)
	}
}

// TestMidBodyResetKeepsProgressInDetail proves a truncated transfer is still a
// failure, but one whose detail names the phase and the progress instead of
// repeating the request URL.
func TestMidBodyResetKeepsProgressInDetail(t *testing.T) {
	reset := errors.New("read tcp 127.0.0.1:52360->127.0.0.1:51607: wsarecv: An existing connection was forcibly closed by the remote host")
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return okResponse(&failingBody{chunk: 64 << 10, err: reset}), nil
	})}
	raw, err := downloadBounded(context.Background(), client, "https://dl.google.com/file", 4<<20, 10*time.Second)
	var transfer *transferError
	if !errors.As(err, &transfer) || transfer.phase != "body" {
		t.Fatalf("error = %v, want a body transferError", err)
	}
	if raw.Received != 32<<10 {
		t.Fatalf("received = %d, want %d", raw.Received, 32<<10)
	}
	out := speedFailure(TestResult{Kind: TestKindSpeed}, TargetCheck{Host: "dl.google.com"}, err)
	if out.Status != TestStatusFailed {
		t.Fatalf("status = %q, a truncated transfer is not a measurement", out.Status)
	}
	if out.Bytes != 0 || out.MBps != 0 || out.Seconds != 0 {
		t.Fatalf("failed transfer was ranked: %+v", out)
	}
	for _, want := range []string{"interrupted", "32 KiB", "dl.google.com"} {
		if !strings.Contains(out.Detail, want) {
			t.Fatalf("detail %q does not mention %q", out.Detail, want)
		}
	}
	if strings.Contains(out.Detail, "https://") {
		t.Fatalf("detail repeats the target URL: %q", out.Detail)
	}
}

// TestTargetStatusIsInconclusive keeps a target-side refusal out of the link's
// failure record: the link answered, the registered target did not.
func TestTargetStatusIsInconclusive(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusNotFound, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(nil))}, nil
	})}
	_, err := downloadBounded(context.Background(), client, "https://dl.google.com/moved", 1<<20, time.Second)
	out := speedFailure(TestResult{Kind: TestKindSpeed}, TargetCheck{Host: "dl.google.com"}, err)
	if out.Status != TestStatusInconclusive || out.Reason != ReasonTargetRejected {
		t.Fatalf("status/reason = %q/%q, want inconclusive/TARGET_REJECTED", out.Status, out.Reason)
	}
	if !strings.Contains(out.Detail, "HTTP 404") {
		t.Fatalf("detail %q does not name the status", out.Detail)
	}
}

// TestBudgetExpiryKeepsProgressInDetail covers the slow-link case: the transfer
// window ended while the body was still trickling, and the detail must say how
// far it got instead of collapsing to "the transfer timed out".
func TestBudgetExpiryKeepsProgressInDetail(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return okResponse(&pacedBody{chunk: 8 << 10, interval: 20 * time.Millisecond, left: 2 << 20}), nil
	})}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	raw, err := downloadBounded(ctx, client, "https://dl.google.com/file", 2<<20, time.Minute)
	if raw.Received == 0 {
		t.Fatal("no progress was recorded before the budget expired")
	}
	var transfer *transferError
	if !errors.As(err, &transfer) || transfer.phase != "body" {
		t.Fatalf("error = %v, want a body transferError", err)
	}
	out := speedFailure(TestResult{Kind: TestKindSpeed}, TargetCheck{Host: "dl.google.com"}, err)
	if out.Status != TestStatusFailed {
		t.Fatalf("status = %q, want failed", out.Status)
	}
	if !strings.Contains(out.Detail, "timed out") || !strings.Contains(out.Detail, "payload") {
		t.Fatalf("detail %q does not describe the stalled transfer", out.Detail)
	}
}

type pacedBody struct {
	chunk    int
	interval time.Duration
	left     int
}

func (b *pacedBody) Read(p []byte) (int, error) {
	if b.left <= 0 {
		return 0, io.EOF
	}
	time.Sleep(b.interval)
	n := b.chunk
	if n > len(p) {
		n = len(p)
	}
	if n > b.left {
		n = b.left
	}
	b.left -= n
	for i := 0; i < n; i++ {
		p[i] = 0x5a
	}
	return n, nil
}

func (b *pacedBody) Close() error { return nil }

type failingBody struct {
	chunk int
	sent  bool
	err   error
}

func (b *failingBody) Read(p []byte) (int, error) {
	if b.sent {
		return 0, b.err
	}
	b.sent = true
	n := b.chunk
	if n > len(p) {
		n = len(p)
	}
	return n, nil
}

func (b *failingBody) Close() error { return nil }

// cancelledBody yields one chunk and then reports cancellation, the way a
// stopped transfer ends.
type cancelledBody struct {
	left int
}

func (b *cancelledBody) Read(p []byte) (int, error) {
	if b.left <= 0 {
		return 0, context.Canceled
	}
	n := len(p)
	if n > b.left {
		n = b.left
	}
	if n > 64<<10 {
		n = 64 << 10
	}
	b.left -= n
	return n, nil
}

func (b *cancelledBody) Close() error { return nil }

// TestSpeedJobRefusesUnderHostLoad keeps the production overload protection
// covered now that the measurement can be pinned by a test.
func TestSpeedJobRefusesUnderHostLoad(t *testing.T) {
	svc, _ := newTestLocal(t)
	stubHostLoad(t, true, "load average 5.2 exceeds 4 CPUs")
	ctx := context.Background()
	if _, err := svc.ImportURI(ctx, "default", testVLESS); err != nil {
		t.Fatal(err)
	}
	_, err := svc.StartTestJob(ctx, TestRequest{Kind: TestKindSpeed, Scope: TestScope{Kind: TestScopeAll}})
	if err == nil || CodeOf(err) != CodeConflict {
		t.Fatalf("start error = %v, want a conflict refusal", err)
	}
	for _, want := range []string{"too busy", "load average 5.2 exceeds 4 CPUs"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal message = %q, want it to contain %q", err, want)
		}
	}
}

// TestMonthlyBudgetRefusalNeverShowsNegativeRemainder covers a cap that usage
// already exceeds: the run must still be refused, but the message may not print
// a negative remainder.
func TestMonthlyBudgetRefusalNeverShowsNegativeRemainder(t *testing.T) {
	svc, _ := newTestLocal(t)
	stubHostLoad(t, false, "")
	ctx := context.Background()
	if _, err := svc.ImportURI(ctx, "default", testVLESS); err != nil {
		t.Fatal(err)
	}
	svc.Config().Tests.MonthlyBudgetMB = 1
	month := time.Now().UTC().Format("2006-01")
	if _, err := svc.layer.AddUsage(month, 2<<20); err != nil {
		t.Fatal(err)
	}
	_, err := svc.StartTestJob(ctx, TestRequest{Kind: TestKindSpeed, Scope: TestScope{Kind: TestScopeAll}})
	if err == nil || CodeOf(err) != CodeConflict {
		t.Fatalf("start error = %v, want a conflict refusal", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "only 0 MB remain") {
		t.Fatalf("refusal message = %q, want a clamped remainder", msg)
	}
	if strings.Contains(msg, "-1 MB") || strings.Contains(msg, "-2 MB") {
		t.Fatalf("refusal message shows a negative remainder: %q", msg)
	}
}
