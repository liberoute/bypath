package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/liberoute/bypath/internal/credential"
)

// WorkerJob is the bounded request a daemon sends to a host-side test worker.
// It names a stored connection instead of carrying profile secrets, so the job
// pipe never contains credentials.
type WorkerJob struct {
	ConnectionID string       `json:"connection_id,omitempty"`
	Kind         string       `json:"kind"`
	Group        string       `json:"group"`
	Remark       string       `json:"remark"`
	CapBytes     int64        `json:"cap_bytes,omitempty"`
	Target       *SpeedTarget `json:"target,omitempty"`

	ServingGroup    string `json:"serving_group,omitempty"`
	ServingRemark   string `json:"serving_remark,omitempty"`
	ServingProtocol string `json:"serving_protocol,omitempty"`
	ServingCredKey  string `json:"serving_cred_key,omitempty"`
	ServingExit     string `json:"serving_exit,omitempty"`
	PolicyRevision  string `json:"policy_revision,omitempty"`

	DaemonNetNS string `json:"daemon_netns"`
}

// WorkerProof records the runtime facts that let a result be certified as
// isolated. It is produced by the worker and checked again by the daemon.
type WorkerProof struct {
	SelfNetNS   string `json:"self_netns"`
	InitNetNS   string `json:"init_netns"`
	DaemonNetNS string `json:"daemon_netns"`
	Isolation   bool   `json:"isolation"`
	Detail      string `json:"detail,omitempty"`
}

// WorkerResult is the only message a worker may print.
type WorkerResult struct {
	Result     TestResult  `json:"result"`
	SpentBytes int64       `json:"spent_bytes"`
	Final      bool        `json:"final"`
	Proof      WorkerProof `json:"proof"`
	Error      string      `json:"error,omitempty"`
}

// workerIsolationProof decides whether this process is outside the daemon's
// network namespace and in the host namespace, which is the property an
// isolated instance needs (no live redirect or routing rule applies there).
func workerIsolationProof(job WorkerJob, selfNS, initNS string) (bool, string) {
	if selfNS == "" || initNS == "" {
		return false, "the worker cannot read its network namespace"
	}
	if selfNS != initNS {
		return false, "the worker is not in the host network namespace"
	}
	if job.DaemonNetNS == "" {
		return false, "the daemon network namespace is unknown"
	}
	if selfNS == job.DaemonNetNS {
		return false, "the worker shares the gateway network namespace"
	}
	return true, "host network namespace verified"
}

// RunWorkerJob executes one job in this process and returns the message to
// print. It never saves results or charges the budget: the daemon owns the
// profile store and the monthly counter, and charges from SpentBytes.
func (s *Local) RunWorkerJob(ctx context.Context, job WorkerJob, selfNS, initNS string) WorkerResult {
	out := WorkerResult{Proof: WorkerProof{SelfNetNS: selfNS, InitNetNS: initNS, DaemonNetNS: job.DaemonNetNS}}
	isolated, detail := workerIsolationProof(job, selfNS, initNS)
	out.Proof.Isolation = isolated
	out.Proof.Detail = detail

	id := job.ConnectionID
	if id == "" {
		id = ConnectionID(job.Group, job.Remark)
	}
	link, _, err := s.findLink(id)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	if link.Protocol == "ssh" {
		out.Error = "SSH links are not covered by the job runner"
		return out
	}
	if job.ServingGroup == link.Group && job.ServingRemark == link.Remark {
		out.Error = "the serving connection is measured on its live path only"
		return out
	}
	if link.Protocol == "openvpn" && job.ServingProtocol == "openvpn" && job.ServingCredKey != "" &&
		credential.KeyFor(link) == job.ServingCredKey {
		out.Error = "would open a second OpenVPN session on the serving account"
		return out
	}
	if s.credentialsMissing(link) {
		out.Error = "missing credentials"
		return out
	}

	var target *SpeedTarget
	if job.Kind == TestKindSpeed {
		if job.Target == nil {
			out.Error = "no speed target is registered"
			return out
		}
		host, _, err := validateSpeedTargetURL(job.Target.URL)
		if err != nil {
			out.Error = "the speed target is not acceptable: " + err.Error()
			return out
		}
		if job.Target.Host != "" && job.Target.Host != host {
			out.Error = "the speed target host does not match its URL"
			return out
		}
		perLink, _, _ := speedBudget(s.Config())
		capBytes := job.CapBytes
		if capBytes <= 0 || capBytes > perLink {
			capBytes = perLink
		}
		t := *job.Target
		t.Host = host
		target = &t
		job.CapBytes = capBytes
	}

	uplink := directUplinkIP(ctx)
	if isolated && uplink == "" {
		// Without the address this host presents directly, an exit can never
		// be proven different from the uplink; unknown proof is not Healthy.
		isolated = false
		out.Proof.Isolation = false
		out.Proof.Detail = "the worker could not measure its direct uplink"
	}
	res, spent, final := s.measureIsolated(ctx, testTarget{id: id, link: link},
		testShared{
			uplink:      uplink,
			servingExit: job.ServingExit,
			isolation:   isolated,
			policyRev:   job.PolicyRevision,
		}, job.Kind, target, job.CapBytes)
	out.Result = res
	out.SpentBytes = spent
	out.Final = final
	if res.Path != nil {
		res.Path.NegativeControl = "n/a (host worker)"
		if isolated {
			res.Path.Note = appendNote(res.Path.Note, "host test worker: "+detail)
		} else {
			res.Path.Note = appendNote(res.Path.Note, "worker proof failed: "+detail)
		}
	}
	return out
}

func appendNote(existing, add string) string {
	if existing == "" {
		return add
	}
	return existing + "; " + add
}

// validateWorkerResult re-checks the worker's claims before the daemon trusts
// or stores them. A result that cannot be tied to this job, this namespace
// pair and a complete proof is refused rather than downgraded silently.
func validateWorkerResult(job WorkerJob, out WorkerResult) error {
	if out.Error != "" {
		return errors.New(out.Error)
	}
	p := out.Proof
	if p.SelfNetNS == "" || p.InitNetNS == "" || p.SelfNetNS != p.InitNetNS {
		return errors.New("the worker did not prove it runs in the host network namespace")
	}
	if job.DaemonNetNS == "" || p.DaemonNetNS != job.DaemonNetNS || p.SelfNetNS == job.DaemonNetNS {
		return errors.New("the worker did not prove it is outside the gateway network namespace")
	}
	if job.ConnectionID != "" && out.Result.ConnectionID != job.ConnectionID {
		return errors.New("the worker answered a different canonical connection id")
	}
	if out.Result.Group != job.Group || out.Result.Remark != job.Remark || out.Result.Kind != job.Kind {
		return errors.New("the worker answered a different job")
	}
	if out.SpentBytes < 0 || out.SpentBytes > 1<<30 {
		return errors.New("the worker reported an impossible byte count")
	}
	// The namespace binding is what makes the worker trustworthy at all. An
	// uncertified isolation result is acceptable only as a non-OK row.
	if out.Result.Status == TestStatusOK {
		if !p.Isolation {
			return fmt.Errorf("the worker returned a certified result without isolation: %s", p.Detail)
		}
		if !VerifiedTestResult(out.Result) {
			return errors.New("the worker returned a certified result without an isolated path proof")
		}
	}
	return nil
}

// workerMeasurement runs one job through the host worker. The platform file
// decides how the worker is started; a host that cannot start one reports
// exactly that instead of measuring inside the gateway namespace.
func (s *Local) runWorkerMeasurement(ctx context.Context, t testTarget, shared testShared, kind string, target *SpeedTarget, capBytes int64, daemonNS string) (TestResult, int64, bool, error) {
	job := WorkerJob{
		ConnectionID:   t.id,
		Kind:           kind,
		Group:          t.link.Group,
		Remark:         t.link.Remark,
		CapBytes:       capBytes,
		Target:         target,
		ServingExit:    shared.servingExit,
		PolicyRevision: shared.policyRev,
		DaemonNetNS:    daemonNS,
	}
	if shared.servingLink != nil {
		job.ServingGroup = shared.servingLink.Group
		job.ServingRemark = shared.servingLink.Remark
		job.ServingProtocol = shared.servingLink.Protocol
		if shared.servingLink.Protocol == "openvpn" {
			job.ServingCredKey = credential.KeyFor(shared.servingLink)
		}
	}
	out, err := s.runWorkerProcess(ctx, job)
	if errors.Is(err, errWorkerCancelled) {
		return TestResult{
			ConnectionID: t.id,
			Group:        t.link.Group,
			Remark:       t.link.Remark,
			Protocol:     t.link.Protocol,
			Kind:         kind,
			Status:       TestStatusCancelled,
			TestedAt:     time.Now().UTC().Format(time.RFC3339),
		}, 0, false, nil
	}
	if err != nil {
		return TestResult{}, 0, false, err
	}
	if err := validateWorkerResult(job, out); err != nil {
		return TestResult{}, 0, false, err
	}
	return out.Result, out.SpentBytes, out.Final, nil
}

// workerGrace is how long the daemon waits for a signalled worker to report the
// bytes it already transferred before it kills the process.
const workerGrace = 10 * time.Second
