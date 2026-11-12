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
	// Throughput is strictly serial: one link at a time, one job at a time.
	// Parallel transfers would share the uplink and distort each other.
	if kind == TestKindSpeed {
		if under, why := hostUnderLoad(); under {
			return TestJob{}, errorf(CodeConflict, "the host is too busy to start a speed test: %s", why)
		}
		perLink, perBatch, monthly := speedBudget(cfg)
		worst := int64(len(targets)) * perLink
		if worst > perBatch {
			worst = perBatch
		}
		if monthly > 0 && s.layer != nil {
			usage, _ := s.layer.Usage()
			if usage.Month != time.Now().UTC().Format("2006-01") {
				usage.Bytes = 0
			}
			if usage.Bytes+worst > monthly {
				remaining := monthly - usage.Bytes
				if remaining < 0 {
					// Usage can exceed the cap after a cap decrease or a
					// cancelled run; the refusal stays, the display never
					// shows a negative remainder.
					remaining = 0
				}
				return TestJob{}, errorf(CodeConflict,
					"this run could use %d MB but only %d MB remain in this month's budget",
					worst>>20, remaining>>20)
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
			ID:        id,
			Kind:      kind,
			Scope:     scope,
			State:     TestJobRunning,
			Stage:     "preflight",
			Total:     len(targets),
			StartedAt: proofTimestamp(),
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
		shared.uplink = directUplinkIP(ctx)
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

// runSerialSpeed measures links one at a time and stops the batch when the
// per-batch byte budget is spent. A stopped link is Skipped ("budget reached"),
// never Failed: nothing about the link was measured.
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
	allowed := budgetLinkCount(len(targets), perLink, perBatch)
	for i, tgt := range targets {
		if ctx.Err() != nil {
			job.addResult(s.cancelledResult(tgt, TestKindSpeed))
			continue
		}
		if i >= allowed {
			job.addResult(s.skippedResult(tgt, ReasonBudgetReached, "traffic budget reached"))
			continue
		}
		res := s.measureLink(ctx, tgt, shared, TestKindSpeed, &target, perLink)
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
	return s.measureLink(ctx, t, shared, TestKindLatency, nil, 0)
}

// measureLink measures one link and records the proof that produced the
// verdict. The serving connection is measured on its own live path; every other
// link runs in an isolated instance, either here or in the host worker when
// this process lives inside the gateway network namespace.
func (s *Local) measureLink(ctx context.Context, t testTarget, shared testShared, kind string, target *SpeedTarget, capBytes int64) (result TestResult) {
	defer func() {
		finishAttempt(&result, ctx)
		if result.Status != TestStatusSkipped {
			s.saveTestResult(t.id, result)
		}
	}()
	link := t.link
	if kind == TestKindSpeed {
		if ok, why := s.provenRelay(t.id); !ok {
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
			}
		}
	}
	// The serving connection is measured on its own live path. Starting a second
	// instance for it would compete with the tunnel that carries user traffic.
	if shared.servingLink != nil && shared.servingLink.Group == link.Group && shared.servingLink.Remark == link.Remark {
		return s.measureLiveLink(ctx, t, shared, kind, target, capBytes)
	}

	if required, daemonNS := isolatedWorkerRequired(); required {
		res, spent, final, err := s.runWorkerMeasurement(ctx, t, shared, kind, target, capBytes, daemonNS)
		s.chargeSpeedAttempt(downloadResult{Spent: spent})
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
			}
		}
		_ = final // all terminal attempts are saved by the deferred recorder
		return res
	}

	res, spent, final := s.measureIsolated(ctx, t, shared, kind, target, capBytes)
	s.chargeSpeedAttempt(downloadResult{Spent: spent})
	_ = final
	return res
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

	lctx, cancel := context.WithTimeout(ctx, testPerLinkTimeout)
	defer cancel()

	opts := bench.Options{
		TmpDir:     s.paths.TmpDir,
		EngineDir:  s.testEngineDir(),
		ProfileDir: s.testProfileDir(),
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
	probeURL, perr := pickTestProbe(lctx, session.Port)
	if perr != nil {
		// The engine started, so its own error is not observable here. Probe the
		// endpoint directly to separate a dead server from a TLS/SNI mismatch;
		// anything else stays an infrastructure failure rather than a guess.
		if diagnosed := bench.DiagnoseEndpoint(lctx, link, opts); diagnosed != nil {
			failAttempt(&res, diagnosed, ctx)
		} else {
			failAttempt(&res, perr, ctx)
		}
		return res, spent, false
	}
	proof.TunneledHTTPS = true
	exitBefore, echoes, err := readTestExit(lctx, session.Port, echoServiceA, echoServiceB)
	if err != nil {
		res.Status, res.Category, res.Reason = TestStatusInconclusive, CategoryExitUnverified, ReasonExitUnknown
		res.Detail = "HTTPS answered, but independent exit identity services did not verify the exit"
		return res, spent, false
	}
	proof.ExitBefore = exitBefore
	proof.Echoes = echoes
	if len(echoes) == 2 && echoes[0].IP != echoes[1].IP {
		res.Status = TestStatusInconclusive
		res.Reason = ReasonExitAmbiguous
		res.Detail = fmt.Sprintf("echo services disagree: %s vs %s", echoes[0].Service, echoes[1].Service)
		return res, spent, false
	}
	if exitBefore == "" {
		res.Status = TestStatusInconclusive
		res.Reason = ReasonExitUnknown
		return res, spent, false
	}
	if shared.uplink != "" && exitBefore == shared.uplink {
		res.Status = TestStatusInconclusive
		res.Reason = ReasonExitEqualsUplink
		return res, spent, false
	}
	if shared.servingExit != "" && exitBefore == shared.servingExit {
		// Without per-outbound counters this build cannot prove the bytes
		// left through the tested link rather than the serving exit.
		res.Status = TestStatusInconclusive
		res.Reason = ReasonExitEqualsServing
		proof.Note = "shares exit address with the serving connection"
		return res, spent, false
	}

	var measured bool
	if kind == TestKindSpeed {
		if target == nil {
			res.Status = TestStatusUnavailable
			res.Detail = "no speed target is registered"
			return res, spent, false
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
		samples := make([]time.Duration, 0, 3)
		for i := 0; i < 3; i++ {
			elapsed, _, err := sampleTestSession(session, lctx, probeURL, 4096)
			if err != nil {
				continue
			}
			samples = append(samples, elapsed)
		}
		if len(samples) < 2 {
			res.Status = TestStatusFailed
			res.Detail = "latency probe failed through the tested instance"
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

	exitAfter, _, err := readTestExit(lctx, session.Port, echoServiceA, "")
	if err != nil || exitAfter != exitBefore {
		proof.ExitAfter = exitAfter
		res.Status = TestStatusInconclusive
		res.Reason = ReasonExitChanged
		zeroMeasurement(&res)
		return res, spent, false
	}
	proof.ExitAfter = exitAfter

	if !shared.isolation {
		res.Status = TestStatusInconclusive
		res.Reason = ReasonIsolationUnverified
	} else {
		res.Status = TestStatusOK
	}
	return res, spent, true
}

// runLiveLinkTest measures the serving connection's latency on its live path.
func (s *Local) runLiveLinkTest(ctx context.Context, t testTarget, shared testShared) TestResult {
	return s.measureLiveLink(ctx, t, shared, TestKindLatency, nil, 0)
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

	lctx, cancel := context.WithTimeout(ctx, testPerLinkTimeout)
	defer cancel()

	decide := func(host string) (RouteDecision, bool) {
		exp, err := s.ExplainRoute(lctx, host)
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
			controlIP, err := fetchEchoIP(lctx, port, "https://"+negativeControlHost)
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

	probeURL, perr := bench.PickProbeURL(lctx, port)
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
	exitBefore, echoes, err := echoThrough(lctx, port, echoServiceA, echoServiceB)
	if err != nil {
		res.Status, res.Category, res.Reason = TestStatusInconclusive, CategoryExitUnverified, ReasonExitUnknown
		res.Detail = "HTTPS answered, but independent exit identity is unverified"
		return res
	}
	proof.ExitBefore = exitBefore
	proof.Echoes = echoes
	if len(echoes) == 2 && echoes[0].IP != echoes[1].IP {
		res.Status = TestStatusInconclusive
		res.Reason = ReasonExitAmbiguous
		res.Detail = fmt.Sprintf("echo services disagree: %s vs %s", echoes[0].Service, echoes[1].Service)
		return res
	}
	if exitBefore == "" {
		res.Status = TestStatusInconclusive
		res.Reason = ReasonExitUnknown
		return res
	}
	if shared.uplink != "" && exitBefore == shared.uplink {
		res.Status = TestStatusInconclusive
		res.Reason = ReasonExitEqualsUplink
		return res
	}
	if shared.servingExit != "" && exitBefore != shared.servingExit {
		res.Status = TestStatusInconclusive
		res.Reason = ReasonExitChanged
		res.Detail = "the serving exit changed since the job started"
		return res
	}

	if kind == TestKindSpeed {
		if target == nil {
			res.Status = TestStatusUnavailable
			res.Detail = "no speed target is registered"
			return res
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
		samples := make([]time.Duration, 0, 5)
		for i := 0; i < 5; i++ {
			if i > 0 {
				select {
				case <-time.After(400 * time.Millisecond):
				case <-lctx.Done():
					return res
				}
			}
			start := time.Now()
			if _, err := profile.FetchThroughProxy(lctx, port, probeURL, 4096); err != nil {
				continue
			}
			samples = append(samples, time.Since(start))
		}
		if len(samples) < 3 {
			res.Status = TestStatusFailed
			res.Detail = "latency probe failed through the live tunnel"
			return res
		}
		res.LatencyMS = int64(median(samples) / time.Millisecond)
		res.P50MS = res.LatencyMS
		res.P90MS = int64(percentile(samples, 0.9) / time.Millisecond)
	}

	exitAfter, _, err := echoThrough(lctx, port, echoServiceA, "")
	if err != nil || exitAfter != exitBefore {
		proof.ExitAfter = exitAfter
		res.Status = TestStatusInconclusive
		res.Reason = ReasonExitChanged
		zeroMeasurement(&res)
		return res
	}
	proof.ExitAfter = exitAfter

	if after := routingRevision(cfg); after != shared.policyRev {
		proof.PolicyAfter = after
		res.Status = TestStatusInconclusive
		res.Reason = ReasonPolicyChanged
		zeroMeasurement(&res)
		res.Bytes = 0
		return res
	}
	proof.PolicyAfter = shared.policyRev

	// Live policy decisions alone do not bind to an isolated engine-owned config.
	res.Status, res.Category, res.Reason = TestStatusInconclusive, CategoryExitUnverified, ReasonConfigNotIsolated
	res.Detail = "live HTTPS measurement is not an isolated engine-owned proof"
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

// directUplinkIP asks a public echo what this host looks like without any
// proxy. It is a comparison value only; a failure leaves it empty and the
// EXIT_EQUALS_UPLINK guard is skipped rather than guessed.
func directUplinkIP(ctx context.Context) string {
	resolver, err := bench.HostBootstrapResolver()
	if err != nil {
		return ""
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second, Resolver: resolver}).DialContext}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: 8 * time.Second, Transport: transport}
	for _, url := range []string{echoServiceA, echoServiceB, echoServiceC} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 128))
		resp.Body.Close()
		if err != nil {
			continue
		}
		if ip := net.ParseIP(strings.TrimSpace(string(body))); ip != nil {
			return ip.String()
		}
	}
	return ""
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
