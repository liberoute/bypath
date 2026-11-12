package app

import (
	"strings"
	"testing"
)

func TestWorkerIsolationProof(t *testing.T) {
	cases := []struct {
		name   string
		daemon string
		self   string
		init   string
		want   bool
		reason string
	}{
		{"host namespace", "net:[4026532000]", "net:[4026531992]", "net:[4026531992]", true, ""},
		{"inside the gateway namespace", "net:[4026532000]", "net:[4026532000]", "net:[4026531992]", false, "host"},
		{"worker and daemon share a namespace", "net:[4026531992]", "net:[4026531992]", "net:[4026531992]", false, "gateway"},
		{"daemon namespace unknown", "", "net:[4026531992]", "net:[4026531992]", false, "unknown"},
		{"unreadable self", "net:[4026532000]", "", "net:[4026531992]", false, "namespace"},
		{"unreadable init", "net:[4026532000]", "net:[4026531992]", "", false, "namespace"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, detail := workerIsolationProof(WorkerJob{DaemonNetNS: tc.daemon}, tc.self, tc.init)
			if got != tc.want {
				t.Fatalf("workerIsolationProof = %v (%q), want %v", got, detail, tc.want)
			}
			if !got && detail == "" {
				t.Fatal("a failed proof must explain itself")
			}
		})
	}
}

func TestValidateWorkerResult(t *testing.T) {
	job := WorkerJob{Kind: TestKindLatency, Group: "g", Remark: "r", DaemonNetNS: "net:[4026532000]"}
	good := WorkerResult{
		Result: TestResult{Group: "g", Remark: "r", Kind: TestKindLatency, Status: TestStatusOK,
			Category: CategoryVerified, TestedAt: proofTimestamp(), P50MS: 42,
			Path: &PathProof{
				ProofVersion: "P5", Kind: "isolated", Level: "L1+L2", ConfigAudit: "pass",
				IsolationVerified: true, EngineOwned: true, TunneledHTTPS: true,
				ConfigSHA256: strings.Repeat("a", 64), ProfileSHA256: strings.Repeat("b", 64),
				UplinkIP: "192.0.2.10", ExitBefore: "198.51.100.7", ExitAfter: "198.51.100.7",
				Echoes: []EchoResult{{Service: "ipify", IP: "198.51.100.7"}, {Service: "ipwho", IP: "198.51.100.7"}},
			}},
		Proof: WorkerProof{SelfNetNS: "net:[4026531992]", InitNetNS: "net:[4026531992]",
			DaemonNetNS: "net:[4026532000]", Isolation: true},
		Final: true,
	}
	if err := validateWorkerResult(job, good); err != nil {
		t.Fatalf("valid worker result refused: %v", err)
	}

	missing := good
	missing.Proof.Isolation = false
	if err := validateWorkerResult(job, missing); err == nil {
		t.Fatal("an OK result without isolation was accepted")
	}

	noproof := good
	noproof.Result.Path = nil
	if err := validateWorkerResult(job, noproof); err == nil {
		t.Fatal("an OK result without a path proof was accepted")
	}

	inconclusive := good
	inconclusive.Result = TestResult{Group: "g", Remark: "r", Kind: TestKindLatency,
		Status: TestStatusInconclusive, Reason: ReasonIsolationUnverified}
	inconclusive.Proof.Isolation = false
	if err := validateWorkerResult(job, inconclusive); err != nil {
		t.Fatalf("an honestly inconclusive worker result was refused: %v", err)
	}

	wrongNS := good
	wrongNS.Proof.DaemonNetNS = "net:[4026539999]"
	if err := validateWorkerResult(job, wrongNS); err == nil {
		t.Fatal("a result from a different daemon namespace was accepted")
	}

	sameNS := good
	sameNS.Proof.DaemonNetNS = sameNS.Proof.SelfNetNS
	if err := validateWorkerResult(job, sameNS); err == nil {
		t.Fatal("a worker sharing the gateway namespace was accepted")
	}

	otherJob := good
	otherJob.Result.Remark = "other"
	if err := validateWorkerResult(job, otherJob); err == nil {
		t.Fatal("a result for a different connection was accepted")
	}

	huge := good
	huge.SpentBytes = 1 << 31
	if err := validateWorkerResult(job, huge); err == nil {
		t.Fatal("an impossible byte count was accepted")
	}

	failed := good
	failed.Error = "missing credentials"
	if err := validateWorkerResult(job, failed); err == nil {
		t.Fatal("a worker error was accepted as a result")
	}
}
