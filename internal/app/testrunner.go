package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/liberoute/bypath/internal/bench"
	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/credential"
	"github.com/liberoute/bypath/internal/profile"
)

const (
	testDefaultParallel = 2
	testMaxParallel     = 3
	testPerLinkTimeout  = 25 * time.Second
	// speedTransferBudget is the extra wall-clock window a speed transfer gets
	// beyond the per-link setup timeout. Engine startup, the probe and the exit
	// checks share testPerLinkTimeout; the download must not be killed by a
	// deadline that already ran out while the tunnel was being prepared.
	speedTransferBudget = 45 * time.Second
	// delayProbeTimeout keeps the fast delay test fast: a link that cannot
	// answer a header-only request in five seconds reports no delay instead of
	// holding the batch.
	delayProbeTimeout = 5 * time.Second
	// Echo endpoints are fixed constants, not user input. Two independent
	// operators make a single provider's anycast quirk visible. A blocked or
	// geo-fenced endpoint (ifconfig.me answers 403 on the target network class)
	// must not fail a measurement the others can prove, so the runner falls
	// back across the list and only reports ambiguity when two answers disagree.
	echoServiceA = "https://api.ipify.org"
	echoServiceB = "https://icanhazip.com"
	// checkip.amazonaws.com is the third operator because ipinfo.io reported a
	// different source address than every other service for plain direct
	// traffic on the target network class, which made a working path look
	// ambiguous. Any replacement must agree with A and B on a direct sample.
	echoServiceC = "https://checkip.amazonaws.com"
	// negativeControlHost is a Cloudflare name the optional IP-check profile
	// routes DIRECT. When the live policy does not route it DIRECT the control
	// is recorded as not applicable rather than assumed.
	negativeControlHost = "cp.cloudflare.com"
)

type testJob struct {
	mu    sync.Mutex
	job   TestJob
	seq   int
	event []TestEvent
	subs  map[chan TestEvent]struct{}
	done  chan struct{}
}

func (j *testJob) snapshot() TestJob {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := j.job
	out.Results = append([]TestResult(nil), j.job.Results...)
	return out
}

func (j *testJob) set(stage string) {
	j.mu.Lock()
	j.job.Stage = stage
	j.mu.Unlock()
}

func (j *testJob) addResult(res TestResult) {
	j.mu.Lock()
	j.job.Completed++
	j.job.Results = append(j.job.Results, res)
	j.seq++
	ev := TestEvent{
		Seq: j.seq, JobID: j.job.ID, State: j.job.State, Stage: j.job.Stage,
		Completed: j.job.Completed, Total: j.job.Total, Result: &res,
	}
	j.event = append(j.event, ev)
	subs := make([]chan TestEvent, 0, len(j.subs))
	for ch := range j.subs {
		subs = append(subs, ch)
	}
	j.mu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

func (j *testJob) finish(state, msg string) {
	j.mu.Lock()
	j.job.State = state
	j.job.Error = Redact(msg)
	j.job.FinishedAt = proofTimestamp()
	j.seq++
	ev := TestEvent{
		Seq: j.seq, JobID: j.job.ID, State: state, Stage: j.job.Stage,
		Completed: j.job.Completed, Total: j.job.Total, Error: j.job.Error,
	}
	j.event = append(j.event, ev)
	subs := make([]chan TestEvent, 0, len(j.subs))
	for ch := range j.subs {
		subs = append(subs, ch)
	}
	close(j.done)
	j.subs = nil
	j.mu.Unlock()
	for _, ch := range subs {
		// Never block completion on a stalled stream: a dropped terminal event
		// is recoverable through GetTestJob and the backlog in subscribe.
		select {
		case ch <- ev:
		default:
		}
		close(ch)
	}
}

// subscribe returns events after seq and a channel for subsequent events. The
// channel is closed when the job finishes; backlog is replayed first.
func (j *testJob) subscribe(after int) ([]TestEvent, <-chan TestEvent, func()) {
	j.mu.Lock()
	defer j.mu.Unlock()
	var backlog []TestEvent
	for _, ev := range j.event {
		if ev.Seq > after {
			backlog = append(backlog, ev)
		}
	}
	ch := make(chan TestEvent, 32)
	if j.job.State == TestJobDone || j.job.State == TestJobFailed || j.job.State == TestJobCancelled {
		close(ch)
		return backlog, ch, func() {}
	}
	if j.subs == nil {
		j.subs = make(map[chan TestEvent]struct{})
	}
	j.subs[ch] = struct{}{}
	return backlog, ch, func() {
		j.mu.Lock()
		delete(j.subs, ch)
		j.mu.Unlock()
	}
}

// StartTestJob validates the request, resolves the scope and starts the job on
// its own context. The request context only controls admission.
func (s *Local) StartTestJob(ctx context.Context, req TestRequest) (TestJob, error) {
	kind := strings.ToLower(strings.TrimSpace(req.Kind))
	if kind == "" {
		kind = TestKindLatency
	}
	if kind != TestKindLatency && kind != TestKindSpeed {
		return TestJob{}, errorf(CodeInvalid, "unsupported test kind %q", req.Kind)
	}
	if req.Upload {
		return TestJob{}, errorf(CodeInvalid, "upload testing is disabled")
	}
	targets, scope, err := s.resolveTestTargets(req)
	if err != nil {
		return TestJob{}, err
	}
	if len(targets) == 0 {
		return TestJob{}, errorf(CodeNotFound, "no connections matched the selected scope")
	}
	cfg := s.Config()
	parallel := testParallelFor(kind, req.Parallel, cfg, len(targets))
	var plannedLinks int
	var plannedBytes int64
	// Throughput is strictly serial: one link at a time, one job at a time.
	// Parallel transfers would share the uplink and distort each other.
	if kind == TestKindSpeed {
		if under, why := hostUnderLoad(); under {
			return TestJob{}, errorf(CodeConflict, "the host is too busy to start a speed test: %s", why)
		}
		perLink, perBatch, monthly := speedBudget(cfg)
		// The plan reserves the per-link cap for every connection it starts, so
		// the monthly refusal stays a worst case the run can never exceed.
		plannedLinks = budgetLinkCount(len(targets), perLink, perBatch)
		plannedBytes = int64(plannedLinks) * perLink
		if monthly > 0 && s.layer != nil {
			usage, _ := s.layer.Usage()
			if usage.Month != time.Now().UTC().Format("2006-01") {
				usage.Bytes = 0
			}
			if usage.Bytes+plannedBytes > monthly {
				remaining := monthly - usage.Bytes
				if remaining < 0 {
					// Usage can exceed the cap after a cap decrease or a
					// cancelled run; the refusal stays, the display never
					// shows a negative remainder.
					remaining = 0
				}
				return TestJob{}, errorf(CodeConflict,
					"this run could use %d MB but only %d MB remain in this month's budget",
					plannedBytes>>20, remaining>>20)
			}
		}
	}

	s.testMu.Lock()
	if s.testJobs == nil {
		s.testJobs = make(map[string]*testJob)
	}
	// One job at a time: extra instances would exceed the S0.3 budget and
	// compete with the serving tunnel for CPU.
	if s.activeTest != "" {
		if active := s.testJobs[s.activeTest]; active != nil {
			st := active.snapshot()
			if st.State == TestJobQueued || st.State == TestJobRunning {
				s.testMu.Unlock()
				return TestJob{}, errorf(CodeConflict, "a test job is already running (%s)", st.ID)
			}
		}
	}
	id := newJobID()
	jobCtx, cancel := context.WithCancel(context.Background())
	job := &testJob{
		job: TestJob{
			ID:            id,
			Kind:          kind,
			Scope:         scope,
			State:         TestJobRunning,
			Stage:         "preflight",
			Total:         len(targets),
			StartedAt:     proofTimestamp(),
			PlannedBytes:  plannedBytes,
			PlannedLinks:  plannedLinks,
			BudgetSkipped: len(targets) - plannedLinks,
		},
		subs: make(map[chan TestEvent]struct{}),
		done: make(chan struct{}),
	}
	s.testJobs[id] = job
	s.activeTest = id
	s.testMu.Unlock()

	go s.runTestJob(jobCtx, cancel, job, targets, parallel)
	return job.snapshot(), nil
}

// testParallelFor clamps the requested parallelism to the S0.3 budget. A speed
// job is always serial; a latency job defaults to 2 and never exceeds 3.
func testParallelFor(kind string, requested int, cfg *config.Config, links int) int {
	if kind == TestKindSpeed {
		return 1
	}
	parallel := requested
	if parallel <= 0 {
		parallel = testDefaultParallel
		if cfg != nil && cfg.Tests.Parallel > 0 {
			parallel = cfg.Tests.Parallel
		}
	}
	if parallel > testMaxParallel {
		parallel = testMaxParallel
	}
	if parallel > links {
		parallel = links
	}
	if parallel < 1 {
		parallel = 1
	}
	return parallel
}

// GetTestJob returns the current state of a job, including finished ones.
func (s *Local) GetTestJob(ctx context.Context, id string) (TestJob, error) {
	job, err := s.testJob(id)
	if err != nil {
		return TestJob{}, err
	}
	return job.snapshot(), nil
}

// CancelTestJob cancels a running job. Engines stop through their context.
func (s *Local) CancelTestJob(ctx context.Context, id string) error {
	if _, err := s.testJob(id); err != nil {
		return err
	}
	s.testMu.Lock()
	cancel := s.testCancels[id]
	s.testMu.Unlock()
	if cancel == nil {
		return errorf(CodeConflict, "job %s is not running", id)
	}
	cancel()
	return nil
}

func (s *Local) testJob(id string) (*testJob, error) {
	s.testMu.Lock()
	defer s.testMu.Unlock()
	job := s.testJobs[id]
	if job == nil {
		return nil, errorf(CodeNotFound, "no test job %q", id)
	}
	return job, nil
}

// SubscribeTestEvents is used by the SSE handler. It replays events after seq.
func (s *Local) SubscribeTestEvents(id string, after int) ([]TestEvent, <-chan TestEvent, func(), error) {
	job, err := s.testJob(id)
	if err != nil {
		return nil, nil, nil, err
	}
	backlog, ch, stop := job.subscribe(after)
	return backlog, ch, stop, nil
}

// TestResults returns the stored history for one connection, with staleness
// computed at read time.
func (s *Local) TestResults(ctx context.Context, connectionID string) ([]TestResult, error) {
	if connectionID == "" {
		return nil, errorf(CodeInvalid, "connection id is required")
	}
	if s.layer == nil {
		return nil, errorf(CodeUnavailable, "test result store is unavailable")
	}
	raw, err := s.layer.TestResults(connectionID)
	if err != nil {
		return nil, asAppError(err, CodeInternal, "reading test results")
	}
	out := make([]TestResult, 0, len(raw))
	for _, item := range raw {
		var res TestResult
		if err := json.Unmarshal(item, &res); err != nil {
			continue
		}
		res.Stale = resultStale(res.TestedAt)
		if link, _, err := s.findLink(connectionID); err == nil && res.Status == TestStatusOK {
			if res.Path == nil || res.Path.ProfileSHA256 != profileProofBinding(link) {
				res.Stale = true
			}
		}
		if res.Status == TestStatusOK && !VerifiedTestResult(res) {
			res.Stale = true
		}
		out = append(out, res)
	}
	InvalidateSupersededResults(out)
	return out, nil
}

// resultStale marks a result older than 24 h; after 7 days callers exclude it
// from ranking (the data is still returned for history).
func resultStale(testedAt string) bool {
	t, err := time.Parse(time.RFC3339, testedAt)
	if err != nil {
		return true
	}
	return time.Since(t) > 24*time.Hour || t.After(time.Now().Add(time.Minute))
}

// resolveTestTargets maps the request scope onto stored links. Hidden links
// stay out of group/all scopes unless explicitly included.
func (s *Local) resolveTestTargets(req TestRequest) ([]testTarget, TestScope, error) {
	scope := req.Scope
	kind := strings.ToLower(strings.TrimSpace(scope.Kind))
	if kind == "" {
		kind = TestScopeAll
	}
	scope.Kind = kind
	var targets []testTarget
	addGroup := func(name string) error {
		g, err := s.profiles.GetGroup(name)
		if err != nil {
			return errorf(CodeNotFound, "no group %q", name)
		}
		for _, link := range g.Links {
			if !req.IncludeHidden {
				if s.layer != nil {
					if e, ok := s.layer.EntryForLink(link.Group, link.Remark); ok && e.Hidden {
						continue
					}
				}
			}
			targets = append(targets, testTarget{link: link, id: s.testConnectionID(link)})
		}
		return nil
	}
	switch kind {
	case TestScopeLink:
		if strings.TrimSpace(scope.ConnectionID) == "" {
			return nil, scope, errorf(CodeInvalid, "connection_id is required for a link scope")
		}
		link, _, err := s.findLink(scope.ConnectionID)
		if err != nil {
			return nil, scope, err
		}
		targets = append(targets, testTarget{link: link, id: s.testConnectionID(link)})
	case TestScopeGroup:
		if strings.TrimSpace(scope.Group) == "" {
			return nil, scope, errorf(CodeInvalid, "group is required for a group scope")
		}
		if err := addGroup(scope.Group); err != nil {
			return nil, scope, err
		}
	case TestScopeAll:
		for _, name := range s.profiles.ListGroups() {
			if err := addGroup(name); err != nil {
				return nil, scope, err
			}
		}
	default:
		return nil, scope, errorf(CodeInvalid, "unknown scope kind %q", scope.Kind)
	}
	return targets, scope, nil
}

type testTarget struct {
	id   string
	link *profile.Link
}

// testConnectionID prefers the stable layer id and falls back to the legacy
// group:remark id before migration.
func (s *Local) testConnectionID(link *profile.Link) string {
	if id := s.stableIDFor(link); id != "" {
		return id
	}
	if link == nil {
		return ""
	}
	return ConnectionID(link.Group, link.Remark)
}

// testShared is the job-wide context every link measurement reuses.
type testShared struct {
	uplink      string
	servingExit string
	servingLink *profile.Link
	isolation   bool
	policyRev   string
	// resolver pins a tested server's address through the configured LAN
	// bootstrap; nil means the host's pre-takeover resolvers. bootstrap labels
	// where the pin came from and travels in every replayed proof.
	resolver  *net.Resolver
	bootstrap string
}

// testEngineDir and testProfileDir resolve the same directories the daemon
// itself uses. A configured directory wins over the installation default, so a
// bench instance and the worker find the engines and links the daemon serves.
func (s *Local) testEngineDir() string {
	if cfg := s.Config(); cfg != nil && cfg.Engines.Directory != "" {
		return cfg.Engines.Directory
	}
	return s.paths.EngineDir
}

func (s *Local) testProfileDir() string {
	if cfg := s.Config(); cfg != nil && cfg.Profiles.Directory != "" {
		return cfg.Profiles.Directory
	}
	return s.paths.ProfileDir
}

// testBootstrapResolver returns the resolver that pins a tested endpoint's
// address and a label recording where it came from. A configured list wins;
// otherwise the host's pre-takeover DHCP resolvers are used, as before.
func testBootstrapResolver(cfg *config.Config) (*net.Resolver, string) {
	if cfg == nil || len(cfg.Tests.BootstrapDNS) == 0 {
		return nil, "host"
	}
	resolver, err := bench.ResolverFromServers(cfg.Tests.BootstrapDNS)
	if err != nil {
		// Config validation rejects these entries; an unreadable document is
		// handled by the caller's own config error path.
		return nil, "host"
	}
	return resolver, "lan:" + strings.Join(cfg.Tests.BootstrapDNS, ",")
}

func (s *Local) runTestJob(ctx context.Context, cancel context.CancelFunc, job *testJob, targets []testTarget, parallel int) {
	s.testMu.Lock()
	if s.testCancels == nil {
		s.testCancels = make(map[string]context.CancelFunc)
	}
	s.testCancels[job.job.ID] = cancel
	s.testMu.Unlock()

	defer func() {
		cancel()
		s.testMu.Lock()
		delete(s.testCancels, job.job.ID)
		if s.activeTest == job.job.ID {
			s.activeTest = ""
		}
		s.testMu.Unlock()
	}()

	cfg := s.Config()
	shared := testShared{}
	// The uplink probe is a comparison value only. With an injected link test
	// (tests) the runner performs no live network calls at all; the guards then
	// see empty values and skip comparison instead of guessing.
	if s.testLink == nil {
		shared.uplink = directUplinkIP(ctx, uplinkInterface(cfg))
		if s.runtime != nil {
			rs := s.runtime.Status()
			if rs.State == "CONNECTED" {
				shared.servingLink = s.profiles.GetActiveLink()
				if cfg != nil {
					shared.servingExit = servingExitIP(ctx, cfg.Server.SOCKSPort)
				}
			}
		}
	}
	if cfg != nil {
		shared.isolation = cfg.Tests.IsolationVerified
		shared.policyRev = routingRevision(cfg)
		shared.resolver, shared.bootstrap = testBootstrapResolver(cfg)
	}

	job.set("testing")
	if job.job.Kind == TestKindSpeed {
		s.runSerialSpeed(ctx, job, targets, shared)
	} else {
		sem := make(chan struct{}, parallel)
		var wg sync.WaitGroup
		for _, tgt := range targets {
			wg.Add(1)
			go func(t testTarget) {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					job.addResult(s.cancelledResult(t, TestKindLatency))
					return
				}
				defer func() { <-sem }()
				run := s.runLinkTest
				if s.testLink != nil {
					run = s.testLink
				}
				res := run(ctx, t, shared)
				job.addResult(res)
			}(tgt)
		}
		wg.Wait()
	}

	switch {
	case ctx.Err() != nil:
		job.finish(TestJobCancelled, "job cancelled")
	default:
		job.finish(TestJobDone, "")
	}
}

// runSerialSpeed measures links one at a time. Before each connection it
// reserves that connection's per-link cap against the batch budget, and after
// each attempt it charges what was really transferred, so a cheap run can
// cover more connections than the worst-case plan promised. A stopped link is
// Skipped ("budget reached"), never Failed: nothing about the link was
// measured.
func (s *Local) runSerialSpeed(ctx context.Context, job *testJob, targets []testTarget, shared testShared) {
	cfg := s.Config()
	perLink, perBatch, _ := speedBudget(cfg)
	targetsList, err := s.listSpeedTargets()
	if err != nil || len(targetsList) == 0 {
		for _, t := range targets {
			job.addResult(s.skippedResult(t, ReasonTargetRejected, "no speed target is registered"))
		}
		return
	}
	target := targetsList[0]
	var spent int64
	for _, tgt := range targets {
		if ctx.Err() != nil {
			job.addResult(s.cancelledResult(tgt, TestKindSpeed))
			continue
		}
		if perLink > 0 && perBatch > 0 && spent+perLink > perBatch {
			job.addResult(s.skippedResult(tgt, ReasonBudgetReached,
				"the batch traffic budget is spent; this connection was not measured"))
			continue
		}
		var res TestResult
		var linkSpent int64
		if s.testMeasure != nil {
			res, linkSpent = s.testMeasure(tgt)
		} else {
			res, linkSpent = s.measureLink(ctx, tgt, shared, TestKindSpeed, &target, perLink)
		}
		if linkSpent > 0 {
			spent += linkSpent
		}
		job.addResult(res)
	}
}

func (s *Local) skippedResult(t testTarget, reason, detail string) TestResult {
	return TestResult{
		ConnectionID: t.id,
		Group:        t.link.Group,
		Remark:       t.link.Remark,
		Protocol:     t.link.Protocol,
		Kind:         TestKindSpeed,
		Status:       TestStatusSkipped,
		Reason:       reason,
		Detail:       detail,
		TestedAt:     proofTimestamp(),
	}
}

func (s *Local) cancelledResult(t testTarget, kind string) TestResult {
	return TestResult{
		ConnectionID: t.id,
		Group:        t.link.Group,
		Remark:       t.link.Remark,
		Protocol:     t.link.Protocol,
		Kind:         kind,
		Status:       TestStatusCancelled,
		TestedAt:     proofTimestamp(),
	}
}

// runLinkTest measures one link's latency in its own isolated instance.
func (s *Local) runLinkTest(ctx context.Context, t testTarget, shared testShared) TestResult {
	res, _ := s.measureLink(ctx, t, shared, TestKindLatency, nil, 0)
	return res
}

// measureLink measures one link and records the proof that produced the
// verdict. The serving connection is measured on its own live path; every other
// link runs in an isolated instance, either here or in the host worker when
// this process lives inside the gateway network namespace. The returned byte
// count is what the attempt actually transferred, including failed transfers.
func (s *Local) measureLink(ctx context.Context, t testTarget, shared testShared, kind string, target *SpeedTarget, capBytes int64) (result TestResult, spent int64) {
	defer func() {
		finishAttempt(&result, ctx)
		if result.Status != TestStatusSkipped {
			s.saveTestResult(t.id, result)
		}
	}()
	link := t.link
	if kind == TestKindSpeed {
		if ok, why := s.speedPreflight(t.id); !ok {
			return TestResult{
				ConnectionID: t.id,
				Group:        link.Group,
				Remark:       link.Remark,
				Protocol:     link.Protocol,
				Kind:         kind,
				Status:       TestStatusUnavailable,
				Reason:       ReasonNoProvenResult,
				Detail:       why,
				TestedAt:     proofTimestamp(),
			}, 0
		}
	}
	// The serving connection is measured on its own live path. Starting a second
	// instance for it would compete with the tunnel that carries user traffic.
	// That path needs a routing decision for every probe host, so when the live
	// policy cannot be evaluated (proxy-only mode, or a host without route
	// explain) the link is measured in its own instance like any other instead
	// of being reported as unmeasurable.
	if shared.servingLink != nil && shared.servingLink.Group == link.Group && shared.servingLink.Remark == link.Remark && s.livePathReady(ctx) {
		before := s.countedBytes()
		res := s.measureLiveLink(ctx, t, shared, kind, target, capBytes)
		if after := s.countedBytes(); after > before {
			return res, after - before
		}
		return res, 0
	}

	if required, daemonNS := isolatedWorkerRequired(); required {
		res, workerSpent, final, err := s.runWorkerMeasurement(ctx, t, shared, kind, target, capBytes, daemonNS)
		s.chargeSpeedAttempt(downloadResult{Spent: workerSpent})
		if err != nil {
			return TestResult{
				ConnectionID: t.id,
				Group:        link.Group,
				Remark:       link.Remark,
				Protocol:     link.Protocol,
				Kind:         kind,
				Status:       TestStatusUnavailable,
				Reason:       ReasonWorkerUnavailable,
				Detail:       Redact(err.Error()),
				TestedAt:     proofTimestamp(),
			}, 0
		}
		_ = final // all terminal attempts are saved by the deferred recorder
		return res, workerSpent
	}

	res, isoSpent, final := s.measureIsolated(ctx, t, shared, kind, target, capBytes)
	s.chargeSpeedAttempt(downloadResult{Spent: isoSpent})
	_ = final
	return res, isoSpent
}

// measureIsolated measures one link in its own isolated instance, in this
// process. It returns the payload the attempt spent so the caller can charge
// the budget even when the result is not kept.
func (s *Local) measureIsolated(ctx context.Context, t testTarget, shared testShared, kind string, target *SpeedTarget, capBytes int64) (res TestResult, spent int64, final bool) {
	defer func() { finishAttempt(&res, ctx); final = res.Status != TestStatusSkipped }()
	link := t.link
	res = TestResult{
		ConnectionID: t.id,
		Group:        link.Group,
		Remark:       link.Remark,
		Protocol:     link.Protocol,
		Kind:         kind,
		TestedAt:     proofTimestamp(),
	}
	unavailable := func(format string, args ...interface{}) (TestResult, int64, bool) {
		res.Status = TestStatusUnavailable
		res.Detail = fmt.Sprintf(format, args...)
		return res, 0, false
	}

	if !bench.Benchable(link) {
		return unavailable("this connection has no testable server address")
	}
	if link.Protocol == "ssh" {
		return unavailable("SSH links are not covered by the job runner yet")
	}
	if shared.servingLink != nil && link.Protocol == "openvpn" && shared.servingLink.Protocol == "openvpn" &&
		credential.KeyFor(link) == credential.KeyFor(shared.servingLink) {
		return unavailable("would open a second OpenVPN session on the serving account")
	}
	if s.credentialsMissing(link) {
		return unavailable("missing credentials")
	}

	sessionWindow := testPerLinkTimeout
	if kind == TestKindSpeed {
		sessionWindow += speedTransferBudget
	}
	lctx, cancel := context.WithTimeout(ctx, sessionWindow)
	defer cancel()
	// Setup stages keep their own bound so a hung engine start, probe or exit
	// lookup cannot consume the window the transfer needs. The engine is bound
	// to lctx, which covers the whole measurement.
	setupCtx, setupDone := context.WithTimeout(lctx, testPerLinkTimeout)
	defer setupDone()

	opts := bench.Options{
		TmpDir:           s.paths.TmpDir,
		EngineDir:        s.testEngineDir(),
		ProfileDir:       s.testProfileDir(),
		EndpointResolver: shared.resolver,
	}
	if cfg := s.Config(); cfg != nil {
		opts.HostKeyPolicy = cfg.Server.SSHHostKey
		opts.PreferredEngine = cfg.Engines.PreferredEngine
		opts.EngineOrder = cfg.Engines.Fallback.Order
		opts.FallbackEnabled = cfg.Engines.Fallback.Enabled
	}
	session, err := openTestSession(lctx, link, opts)
	if err != nil {
		failAttempt(&res, err, ctx)
		return res, spent, false
	}
	defer session.Close()
	res.Engine = session.Engine

	proof := &PathProof{
		Kind:              "isolated",
		Level:             "L1+L2",
		ConfigAudit:       "pass",
		IsolationVerified: shared.isolation,
		UplinkIP:          shared.uplink,
		ServingExitIP:     shared.servingExit,
		PolicyRevision:    shared.policyRev,
		NegativeControl:   "n/a (isolated instance)",
		Bootstrap:         shared.bootstrap,
	}
	res.Path = proof

	if err := auditIsolatedConfig(session.Config); err != nil {
		proof.ConfigAudit = "fail"
		res.Status = TestStatusInconclusive
		res.Reason = ReasonConfigNotIsolated
		res.Detail = Redact(err.Error())
		return res, spent, false
	}

	if err := bindSessionProof(proof, session, link); err != nil {
		res.Status, res.Category, res.Reason = TestStatusInconclusive, CategoryInfrastructure, ReasonConfigNotIsolated
		res.Detail = err.Error()
		return res, spent, false
	}
	// Relay startup is not liveness. First prove real HTTPS through the exact
	// isolated owned configuration; blocked identity services are a separate stage.
	probeURL, perr := pickTestProbe(setupCtx, session.Port)
	if perr != nil {
		// The engine started, so its own error is not observable here. Probe the
		// endpoint directly to separate a dead server from a TLS/SNI mismatch;
		// anything else stays an infrastructure failure rather than a guess.
		if diagnosed := diagnoseEndpoint(lctx, link, opts); diagnosed != nil {
			failAttempt(&res, diagnosed, ctx)
		} else {
			// The endpoint accepted TCP and a TLS handshake, so the failure
			// happened after the transport: name the HTTPS stage instead of
			// blaming the server's reachability.
			failAttempt(&res, &bench.AttemptError{Category: CategoryHTTPS, Err: perr}, ctx)
		}
		return res, spent, false
	}
	proof.TunneledHTTPS = true
	res.HTTPSProven = true

	// The exit identity is operational context, not a precondition. Identity
	// services can be blocked, and a subscription can share one exit address
	// across every link; neither makes a carried HTTPS request a dead link.
	exitBefore, echoes, idErr := readTestExit(setupCtx, session.Port, echoServiceA, echoServiceB)
	proof.ExitBefore = exitBefore
	proof.Echoes = echoes
	unverified, unverifiedDetail := "", ""
	switch {
	case idErr != nil || exitBefore == "":
		unverified = ReasonExitUnknown
		unverifiedDetail = "HTTPS answered through the tested connection, but the independent exit identity is unverified"
	case len(echoes) == 2 && echoes[0].IP != echoes[1].IP:
		unverified = ReasonExitAmbiguous
		unverifiedDetail = fmt.Sprintf("echo services disagree: %s vs %s; HTTPS was measured, exit ownership is unproven",
			echoes[0].Service, echoes[1].Service)
	case shared.uplink != "" && exitBefore == shared.uplink:
		// The same address this host presents without a proxy: the traffic did
		// not demonstrably leave through the tunnel, so a throughput number
		// would describe a DIRECT path and is refused.
		res.Status = TestStatusInconclusive
		res.Reason = ReasonExitEqualsUplink
		res.Detail = "traffic left directly instead of through the tunnel; nothing was measured"
		return res, spent, false
	case shared.servingExit != "" && exitBefore == shared.servingExit:
		unverified = ReasonExitEqualsServing
		unverifiedDetail = "shares the exit address with the serving connection; a shared exit is not a failed connection"
	}

	var measured bool
	if kind == TestKindSpeed {
		if target == nil {
			res.Status = TestStatusUnavailable
			res.Detail = "no speed target is registered"
			return res, spent, false
		}
		// One small timed request records the HTTPS latency of the same path
		// the download is about to use. The fast delay is recorded separately:
		// it stops at the response headers, so it stays comparable across links
		// even when the download itself is slow or fails.
		res.DelayMS = measureDelayMS(setupCtx, session.Port, probeURL)
		if elapsed, _, err := sampleTestSession(session, setupCtx, probeURL, 4096); err == nil {
			res.LatencyMS = int64(elapsed / time.Millisecond)
			res.P50MS = res.LatencyMS
		}
		dres, check, err := s.speedThrough(lctx, session.Port, false, *target, capBytes)
		spent = dres.Spent
		if err != nil {
			return speedFailure(res, check, err), spent, false
		}
		res.MBps = dres.Mbps
		res.Bytes = dres.Bytes
		res.Seconds = dres.Duration.Seconds()
		res.Target = target.Host
		res.SupportsRange = dres.SupportsRange
		proof.RouteDecisions = []RouteDecision{{Host: check.Host, IPs: check.ResolvedIPs, Decision: check.Route}}
		measured = true
	} else {
		res.DelayMS = measureDelayMS(setupCtx, session.Port, probeURL)
		samples := make([]time.Duration, 0, 3)
		for i := 0; i < 3; i++ {
			elapsed, _, err := sampleTestSession(session, setupCtx, probeURL, 4096)
			if err != nil {
				continue
			}
			samples = append(samples, elapsed)
		}
		if len(samples) < 2 {
			res.Status = TestStatusFailed
			res.Category = CategoryHTTPS
			res.Detail = "the full HTTPS sample failed through the tested instance"
			if res.DelayMS > 0 {
				res.Detail = fmt.Sprintf("the fast delay answered in %d ms, but the full HTTPS sample failed through the tested instance", res.DelayMS)
			}
			return res, spent, false
		}
		res.LatencyMS = int64(median(samples) / time.Millisecond)
		res.P50MS = res.LatencyMS
		res.P90MS = int64(percentile(samples, 0.9) / time.Millisecond)
		measured = true
	}
	if !measured {
		res.Status = TestStatusFailed
		res.Detail = "nothing was measured"
		return res, spent, false
	}

	if exitBefore != "" {
		if exitAfter, _, err := readTestExit(lctx, session.Port, echoServiceA, ""); err == nil && exitAfter != "" {
			proof.ExitAfter = exitAfter
			if exitAfter != exitBefore && unverified == "" {
				unverified = ReasonExitChanged
				unverifiedDetail = "the exit changed during the measurement; the numbers describe the interval, not a stable path"
			}
		} else if unverified == "" {
			unverified = ReasonExitUnknown
			unverifiedDetail = "the exit could not be re-verified after the measurement"
		}
	}

	switch {
	case unverified == "" && shared.isolation:
		res.Status = TestStatusOK
		res.Evidence = EvidenceVerified
	case unverified == "":
		res.Status = TestStatusMeasured
		res.Evidence = EvidenceOperational
		res.Reason = ReasonIsolationUnverified
		res.Detail = "HTTPS was measured through the tested connection; isolated-test isolation is not verified on this host"
	default:
		res.Status = TestStatusMeasured
		res.Evidence = EvidenceOperational
		res.Reason = unverified
		res.Detail = unverifiedDetail
	}
	return res, spent, true
}

// runLiveLinkTest measures the serving connection's latency on its live path.
func (s *Local) runLiveLinkTest(ctx context.Context, t testTarget, shared testShared) TestResult {
	return s.measureLiveLink(ctx, t, shared, TestKindLatency, nil, 0)
}

// livePathReady reports whether a measurement on the serving link's live path
// could be attributed to the tunnel. The live path applies the gateway routing
// policy, so every probe host must get a certain route decision first; the
// answer is the same for every host because certainty depends on whether the
// policy can evaluate the default probe name.
func (s *Local) livePathReady(ctx context.Context) bool {
	cfg := s.Config()
	if cfg == nil || cfg.Server.SOCKSPort <= 0 {
		return false
	}
	exp, err := s.ExplainRoute(ctx, "api.ipify.org")
	return err == nil && exp.Certain
}

// measureDelayMS runs the fast delay probe under its own short bound. A failed
// delay leaves the field empty; the full HTTPS exchange decides the row.
func measureDelayMS(ctx context.Context, port int, probeURL string) int64 {
	delayCtx, cancel := context.WithTimeout(ctx, delayProbeTimeout)
	defer cancel()
	elapsed, err := measureTestDelay(delayCtx, port, probeURL)
	if err != nil {
		return 0
	}
	ms := int64(elapsed / time.Millisecond)
	if ms == 0 {
		ms = 1
	}
	return ms
}

// measureLiveLink measures the serving connection through the live SOCKS port,
// which applies the gateway's routing rules. Every destination is route-checked
// first: a DIRECT decision means the number would not describe the tunnel.
func (s *Local) measureLiveLink(ctx context.Context, t testTarget, shared testShared, kind string, target *SpeedTarget, capBytes int64) (res TestResult) {
	defer func() { finishAttempt(&res, ctx) }()
	link := t.link
	res = TestResult{
		ConnectionID: t.id,
		Group:        link.Group,
		Remark:       link.Remark,
		Protocol:     link.Protocol,
		Kind:         kind,
		TestedAt:     proofTimestamp(),
	}
	unavailable := func(format string, args ...interface{}) TestResult {
		res.Status = TestStatusUnavailable
		res.Detail = fmt.Sprintf(format, args...)
		return res
	}
	cfg := s.Config()
	if cfg == nil || cfg.Server.SOCKSPort <= 0 {
		return unavailable("the serving connection has no SOCKS port to measure")
	}
	port := cfg.Server.SOCKSPort
	proof := &PathProof{
		Kind:            "live",
		Level:           "L1+L2",
		ConfigAudit:     "n/a (live path)",
		UplinkIP:        shared.uplink,
		ServingExitIP:   shared.servingExit,
		PolicyRevision:  shared.policyRev,
		NegativeControl: "n/a",
		Note:            "Measured on the live tunnel",
	}
	res.Path = proof

	sessionWindow := testPerLinkTimeout
	if kind == TestKindSpeed {
		sessionWindow += speedTransferBudget
	}
	lctx, cancel := context.WithTimeout(ctx, sessionWindow)
	defer cancel()
	// Route checks, the negative control and the exit reads are setup. A hung
	// probe must not eat the transfer window that follows.
	setupCtx, setupDone := context.WithTimeout(lctx, testPerLinkTimeout)
	defer setupDone()

	decide := func(host string) (RouteDecision, bool) {
		exp, err := s.ExplainRoute(setupCtx, host)
		if err != nil || !exp.Certain {
			res.Status = TestStatusInconclusive
			res.Reason = ReasonRouteExplainMissing
			res.Detail = fmt.Sprintf("could not evaluate the routing policy for %s", host)
			return RouteDecision{}, false
		}
		return RouteDecision{Host: host, IPs: exp.Addresses, Decision: exp.Outcome}, true
	}

	for _, host := range []string{"api.ipify.org", "icanhazip.com", "checkip.amazonaws.com", "www.gstatic.com", "connectivitycheck.gstatic.com", "1.1.1.1"} {
		dec, ok := decide(host)
		if !ok {
			return res
		}
		proof.RouteDecisions = append(proof.RouteDecisions, dec)
		if dec.Decision != "PROXY" {
			res.Status = TestStatusInconclusive
			res.Reason = ReasonPathDirectTarget
			res.Detail = fmt.Sprintf("%s is routed %s, so the measurement would not describe the tunnel", host, dec.Decision)
			return res
		}
	}

	// Negative control: prove this harness can tell DIRECT from tunnel on this
	// gateway by requesting a DIRECT-routed name and expecting the uplink IP.
	if dec, ok := decide(negativeControlHost); ok {
		proof.RouteDecisions = append(proof.RouteDecisions, dec)
		switch dec.Decision {
		case "DIRECT":
			controlIP, err := fetchEchoIP(setupCtx, port, "https://"+negativeControlHost)
			switch {
			case err != nil:
				proof.NegativeControl = "failed"
				res.Status = TestStatusInconclusive
				res.Reason = ReasonControlFailed
				res.Detail = "the negative-control request failed, so DIRECT detection is unproven"
				return res
			case shared.uplink != "" && controlIP == shared.uplink:
				proof.NegativeControl = "pass"
			default:
				proof.NegativeControl = "failed"
				res.Status = TestStatusInconclusive
				res.Reason = ReasonControlFailed
				res.Detail = "a DIRECT-routed name did not exit through the uplink; route decisions are not trustworthy"
				return res
			}
		default:
			// A name the policy routes through the tunnel cannot serve as a
			// DIRECT control.
			proof.NegativeControl = "n/a"
		}
	}

	probeURL, perr := bench.PickProbeURL(setupCtx, port)
	if perr != nil {
		failAttempt(&res, perr, ctx)
		return res
	}
	// Explain the actual chosen HTTPS endpoint, not a stale fixed list.
	dec, ok := decide(echoLabel(probeURL))
	if !ok {
		return res
	}
	if dec.Decision != "PROXY" {
		res.Status, res.Reason = TestStatusInconclusive, ReasonPathDirectTarget
		return res
	}
	proof.RouteDecisions = append(proof.RouteDecisions, dec)
	proof.TunneledHTTPS = true
	res.HTTPSProven = true
	// Identity is best-effort on the live path too: a shared or unreadable
	// exit is a fact about ownership, not a reason to leave the serving
	// connection unmeasured.
	note, noteDetail := "", ""
	exitBefore, echoes, err := echoThrough(setupCtx, port, echoServiceA, echoServiceB)
	proof.ExitBefore = exitBefore
	proof.Echoes = echoes
	switch {
	case err != nil || exitBefore == "":
		note = ReasonExitUnknown
		noteDetail = "HTTPS answered on the live tunnel, but the exit identity is unverified"
	case len(echoes) == 2 && echoes[0].IP != echoes[1].IP:
		note = ReasonExitAmbiguous
		noteDetail = fmt.Sprintf("echo services disagree: %s vs %s", echoes[0].Service, echoes[1].Service)
	case shared.uplink != "" && exitBefore == shared.uplink:
		res.Status = TestStatusInconclusive
		res.Reason = ReasonExitEqualsUplink
		res.Detail = "traffic left directly instead of through the tunnel; nothing was measured"
		return res
	case shared.servingExit != "" && exitBefore != shared.servingExit:
		note = ReasonExitChanged
		noteDetail = "the serving exit changed since the job started"
	}

	if kind == TestKindSpeed {
		if target == nil {
			res.Status = TestStatusUnavailable
			res.Detail = "no speed target is registered"
			return res
		}
		// One small timed request records the HTTPS latency of the same path
		// the download is about to use.
		res.DelayMS = measureDelayMS(setupCtx, port, probeURL)
		start := time.Now()
		if _, err := profile.FetchThroughProxy(setupCtx, port, probeURL, 4096); err == nil {
			res.LatencyMS = int64(time.Since(start) / time.Millisecond)
			res.P50MS = res.LatencyMS
		}
		dres, check, err := s.speedThrough(lctx, port, true, *target, capBytes)
		s.chargeSpeedAttempt(dres)
		if err != nil {
			return speedFailure(res, check, err)
		}
		res.MBps = dres.Mbps
		res.Bytes = dres.Bytes
		res.Seconds = dres.Duration.Seconds()
		res.Target = target.Host
		res.SupportsRange = dres.SupportsRange
		proof.RouteDecisions = append(proof.RouteDecisions,
			RouteDecision{Host: check.Host, IPs: check.ResolvedIPs, Decision: check.Route})
	} else {
		res.DelayMS = measureDelayMS(setupCtx, port, probeURL)
		samples := make([]time.Duration, 0, 5)
		for i := 0; i < 5; i++ {
			if i > 0 {
				select {
				case <-time.After(400 * time.Millisecond):
				case <-setupCtx.Done():
					return res
				}
			}
			start := time.Now()
			if _, err := profile.FetchThroughProxy(setupCtx, port, probeURL, 4096); err != nil {
				continue
			}
			samples = append(samples, time.Since(start))
		}
		if len(samples) < 3 {
			res.Status = TestStatusFailed
			res.Detail = "the full HTTPS sample failed through the live tunnel"
			if res.DelayMS > 0 {
				res.Detail = fmt.Sprintf("the fast delay answered in %d ms, but the full HTTPS sample failed through the live tunnel", res.DelayMS)
			}
			return res
		}
		res.LatencyMS = int64(median(samples) / time.Millisecond)
		res.P50MS = res.LatencyMS
		res.P90MS = int64(percentile(samples, 0.9) / time.Millisecond)
	}

	if exitBefore != "" {
		if exitAfter, _, err := echoThrough(lctx, port, echoServiceA, ""); err == nil && exitAfter != "" {
			proof.ExitAfter = exitAfter
			if exitAfter != exitBefore && note == "" {
				note = ReasonExitChanged
				noteDetail = "the exit changed during the measurement"
			}
		}
	}

	if after := routingRevision(cfg); after != shared.policyRev {
		proof.PolicyAfter = after
		if note == "" {
			note = ReasonPolicyChanged
			noteDetail = "the routing policy changed during the measurement"
		}
	} else {
		proof.PolicyAfter = shared.policyRev
	}

	// Live policy decisions alone do not bind to an isolated engine-owned
	// config, so this is operational evidence even when every identity check
	// agreed.
	res.Status = TestStatusMeasured
	res.Evidence = EvidenceOperational
	res.Reason = ReasonConfigNotIsolated
	res.Detail = "measured on the live serving tunnel; a live measurement is operational evidence, not an isolated engine-owned proof"
	if note != "" {
		res.Reason = note
		if noteDetail != "" {
			res.Detail = noteDetail + "; " + res.Detail
		}
	}
	return res
}

func (s *Local) saveTestResult(connectionID string, res TestResult) {
	if s.layer == nil {
		return
	}
	data, err := json.Marshal(res)
	if err != nil {
		return
	}
	_ = s.layer.SaveTestResult(connectionID, json.RawMessage(data))
}

// echoThrough asks the echo services through the proxy and returns the observed
// exit plus the observations that produced it. Services are tried in preference
// order; a blocked endpoint is skipped instead of failing the measurement. Two
// answers that disagree are returned as-is so the caller can report
// EXIT_AMBIGUOUS; a single answer is accepted on its own.
func echoThrough(ctx context.Context, port int, serviceA, serviceB string) (string, []EchoResult, error) {
	order := []string{serviceA, serviceB, echoServiceA, echoServiceB, echoServiceC}
	seen := map[string]bool{}
	var firstIP string
	var echoes []EchoResult
	for _, url := range order {
		if url == "" || seen[url] {
			continue
		}
		seen[url] = true
		ip, ferr := fetchEchoIP(ctx, port, url)
		if ferr != nil {
			continue
		}
		echo := EchoResult{Service: echoLabel(url), IP: ip}
		if firstIP == "" {
			firstIP = ip
			echoes = append(echoes, echo)
			if serviceB == "" {
				break
			}
			continue
		}
		echoes = append(echoes, echo)
		break
	}
	if firstIP == "" || (serviceB != "" && len(echoes) < 2) {
		return firstIP, echoes, fmt.Errorf("independent identity proof unavailable")
	}
	return firstIP, echoes, nil
}

func echoLabel(rawURL string) string {
	s := strings.TrimPrefix(rawURL, "https://")
	s = strings.TrimPrefix(s, "http://")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return s
}

func fetchEchoIP(ctx context.Context, port int, url string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	body, err := bench.FetchHTTPSThroughProxy(ctx, port, url, 128)
	if err != nil {
		return "", err
	}
	ip := net.ParseIP(strings.TrimSpace(string(body)))
	if ip == nil {
		return "", fmt.Errorf("unexpected echo response")
	}
	return ip.String(), nil
}

// uplinkInterface names the physical interface the direct-uplink probe must
// use while the gateway TUN owns the default route. Empty means unbound.
func uplinkInterface(cfg *config.Config) string {
	if cfg == nil || !cfg.Gateway.Enabled || !cfg.Gateway.NativeTUN {
		return ""
	}
	iface := strings.TrimSpace(cfg.Gateway.Interface)
	if iface == "" || strings.EqualFold(iface, "auto") {
		return ""
	}
	return iface
}

// uplinkTraceEndpoints are echoed back as key=value lines by Cloudflare and are
// addressed by IP literal on purpose: resolving a name would query a resolver,
// and in gateway mode the host resolver may itself be the strict DNS path that
// runs through the tunnel. An IP-literal request keeps the uplink probe free of
// DNS traffic while the interface binding keeps its TCP on the physical link.
var uplinkTraceEndpoints = []string{
	"https://1.1.1.1/cdn-cgi/trace",
	"https://1.0.0.1/cdn-cgi/trace",
}

// parseTraceIP extracts the CLIENT address (ip=) from a cdn-cgi/trace body.
func parseTraceIP(body []byte) string {
	for _, line := range strings.Split(string(body), "\n") {
		value, ok := strings.CutPrefix(strings.TrimSpace(line), "ip=")
		if !ok {
			continue
		}
		if ip := net.ParseIP(strings.TrimSpace(value)); ip != nil {
			return ip.String()
		}
	}
	return ""
}

// directUplinkIP asks a public echo what this host looks like without any
// proxy. It is a comparison value only; a failure leaves it empty and the
// EXIT_EQUALS_UPLINK guard is skipped rather than guessed.
func directUplinkIP(ctx context.Context, iface string) string {
	ip, _ := probeUplinkIP(ctx, iface)
	return ip
}

// probeUplinkIP sends an IP-literal trace request bound to the physical
// interface. In gateway mode the default route belongs to the TUN, so an
// unbound request would report the tunnel exit as the "uplink".
func probeUplinkIP(ctx context.Context, iface string) (string, error) {
	dialer := &net.Dialer{Timeout: 5 * time.Second, Control: bindDeviceControl(iface)}
	transport := &http.Transport{Proxy: nil, DialContext: dialer.DialContext}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: 8 * time.Second, Transport: transport}
	var last error
	for _, target := range uplinkTraceEndpoints {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			last = err
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			last = err
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if err != nil {
			last = err
			continue
		}
		if ip := parseTraceIP(body); ip != "" {
			return ip, nil
		}
		last = fmt.Errorf("trace answer carried no client address")
	}
	if last == nil {
		last = fmt.Errorf("no uplink trace endpoint answered")
	}
	return "", last
}

// uplinkIdentityFetcher adapts the bound uplink probe to the gateway identity
// fetcher signature. The oracle name in target is ignored: every sample is an
// IP-literal trace request, so the direct side never depends on hostname DNS.
func uplinkIdentityFetcher(ctx context.Context, iface string, _ string) (string, error) {
	return probeUplinkIP(ctx, iface)
}

// servingExitIP reads the exit address of the running tunnel without changing
// anything. An error leaves it empty; the proof then cannot compare.
func servingExitIP(ctx context.Context, socksPort int) string {
	if socksPort <= 0 {
		return ""
	}
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	body, err := profile.FetchThroughProxy(probeCtx, socksPort, echoServiceA, 128)
	if err != nil {
		return ""
	}
	ip := net.ParseIP(strings.TrimSpace(string(body)))
	if ip == nil {
		return ""
	}
	return ip.String()
}

func median(d []time.Duration) time.Duration {
	if len(d) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), d...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return sorted[len(sorted)/2]
}

func percentile(d []time.Duration, p float64) time.Duration {
	if len(d) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), d...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	idx := int(float64(len(sorted))*p+0.999999) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func newJobID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "job-" + fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return "job-" + hex.EncodeToString(b)
}
