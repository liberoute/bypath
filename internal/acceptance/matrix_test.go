package acceptance_test

import (
	"os"
	"testing"

	"github.com/liberoute/bypath/internal/acceptance"
	"github.com/liberoute/bypath/internal/engine"
	"github.com/liberoute/bypath/internal/profile"
	"github.com/liberoute/bypath/internal/tunnel"
)

func encryptedLink() *profile.Link {
	return &profile.Link{
		Protocol:   "vless",
		Remark:     "encrypted",
		Address:    "vpn.example.net",
		Port:       443,
		Encryption: "mlkem768x25519plus.native.0rtt.auth-secret-not-logged",
	}
}

func openvpnLink() *profile.Link {
	return &profile.Link{Protocol: "openvpn", Remark: "ovpn", Address: "vpn.example.net", Port: 443}
}

// result maps an error to the only status a deterministic case can report.
func result(id string, err error, onErr acceptance.Status) acceptance.Result {
	status := acceptance.Success
	if err != nil {
		status = onErr
	}
	return acceptance.Result{Case: id, Status: status}
}

func TestDeterministicCasesMatchProductionPredicates(t *testing.T) {
	m := acceptance.Standard()

	cases := []struct {
		name   string
		result acceptance.Result
	}{
		{
			name: "sing-box refuses encrypted VLESS",
			result: result("vless.modern-encryption.sing-box",
				tunnel.ValidateEngineSupport(&engine.Engine{Name: "sing-box"}, encryptedLink()),
				acceptance.Unsupported),
		},
		{
			name: "xray accepts encrypted VLESS",
			result: result("vless.modern-encryption.xray",
				tunnel.ValidateEngineSupport(&engine.Engine{Name: "xray"}, encryptedLink()),
				acceptance.Failed),
		},
		{
			name: "encrypted selection refuses a plain fallback",
			result: acceptance.Result{
				Case:   "vless.encrypted-fallback",
				Status: boolStatus(engine.FallbackCompatible(encryptedLink(), &profile.Link{Protocol: "vless", Remark: "plain"}), acceptance.Failed),
			},
		},
		{
			name: "xray refuses OpenVPN",
			result: result("openvpn.xray",
				tunnel.ValidateEngineSupport(&engine.Engine{Name: "xray"}, openvpnLink()),
				acceptance.Unsupported),
		},
		{
			name: "unpinned platform fails closed",
			result: func() acceptance.Result {
				_, err := engine.ArtifactFor("xray", "darwin", "amd64")
				return result("engine.unpinned-platform", err, acceptance.Unsupported)
			}(),
		},
	}

	for _, tc := range cases {
		c, ok := m.Case(tc.result.Case)
		if !ok {
			t.Fatalf("%s: case %q is not in the matrix", tc.name, tc.result.Case)
		}
		if err := c.Evaluate(tc.result); err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

func boolStatus(ok bool, whenFalse acceptance.Status) acceptance.Status {
	if ok {
		return acceptance.Success
	}
	return whenFalse
}

// deterministicResults are the matrix rows that production predicates decide
// without any network access. They deliberately exclude the connectivity rows,
// which can only be proven by live evidence.
func deterministicResults(t *testing.T) []acceptance.Result {
	t.Helper()
	plain := &profile.Link{Protocol: "vless", Remark: "plain"}
	return []acceptance.Result{
		result("vless.modern-encryption.sing-box",
			tunnel.ValidateEngineSupport(&engine.Engine{Name: "sing-box"}, encryptedLink()),
			acceptance.Unsupported),
		{
			Case:   "vless.encrypted-fallback",
			Status: boolStatus(engine.FallbackCompatible(encryptedLink(), plain), acceptance.Failed),
		},
		result("openvpn.xray",
			tunnel.ValidateEngineSupport(&engine.Engine{Name: "xray"}, openvpnLink()),
			acceptance.Unsupported),
		func() acceptance.Result {
			_, err := engine.ArtifactFor("xray", "darwin", "amd64")
			return result("engine.unpinned-platform", err, acceptance.Unsupported)
		}(),
	}
}

// suiteWithDeterministicCases records what can be proven offline and states why
// the remaining rows are untested instead of omitting them.
func suiteWithDeterministicCases(t *testing.T) *acceptance.Suite {
	t.Helper()
	s := acceptance.NewSuite(acceptance.Standard())
	for _, r := range deterministicResults(t) {
		if err := s.Record(r); err != nil {
			t.Fatal(err)
		}
	}
	live := map[string]string{
		"vless.modern-encryption.xray": "no encrypted VLESS subscription was exercised in this run",
		"openvpn.sing-box-endpoint":    "no OpenVPN profile was exercised in this run",
		"network.proxy-only-isolation": "proxy-only host-inertness evidence was not collected in this run",
		"network.ipv6-dual-stack":      "no dual-stack egress evidence collected in this run",
	}
	for id, reason := range live {
		if err := s.Limit(id, reason); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func TestPartialRunIsReportableButNotAcceptanceGrade(t *testing.T) {
	s := suiteWithDeterministicCases(t)
	if err := s.Evaluate(); err != nil {
		t.Fatalf("deterministic results violate the matrix: %v", err)
	}
	if err := s.Grade(); err == nil {
		t.Fatal("a run without live evidence was graded as acceptance")
	}
	limitations := len(s.Limitations())
	if limitations != 4 {
		t.Fatalf("Limitations() has %d entries, want the four live cases: %v", limitations, s.Limitations())
	}
	if missing := s.Missing(); len(missing) != 0 {
		t.Fatalf("every case should be explicit, still missing: %v", missing)
	}
}

// TestFullAcceptanceMatrix assembles the whole matrix from deterministic
// predicates plus evidence written by live probes (BYPATH_ACCEPTANCE_EVIDENCE).
// Without that evidence it reports the limitations and does not claim
// acceptance; with BYPATH_ACCEPTANCE_STRICT=1 every row must reach an
// acceptance-grade status.
func TestFullAcceptanceMatrix(t *testing.T) {
	s := suiteWithDeterministicCases(t)

	strict := os.Getenv("BYPATH_ACCEPTANCE_STRICT") == "1"
	if strict && os.Getenv(acceptance.EvidenceCommitEnv) == "" {
		t.Fatalf("strict acceptance requires %s so every evidence file is bound to a commit", acceptance.EvidenceCommitEnv)
	}
	dir := os.Getenv(acceptance.EvidenceDirEnv)
	if dir != "" {
		results, err := acceptance.LoadEvidenceDir(dir)
		if err != nil {
			t.Fatalf("reading acceptance evidence: %v", err)
		}
		for _, r := range results {
			// Evidence supersedes the limitation recorded for that case.
			if _, ok := acceptance.Standard().Case(r.Case); ok {
				if err := s.Record(r); err != nil {
					t.Fatalf("evidence for %s: %v", r.Case, err)
				}
			}
		}
	}

	results := s.Results()
	for _, r := range results {
		t.Logf("%-34s %-18s %s", r.Case, r.Status, r.Detail)
	}
	for _, limitation := range s.Limitations() {
		t.Logf("limitation: %s", limitation)
	}

	if !strict {
		t.Skip("acceptance-grade run requires BYPATH_ACCEPTANCE_STRICT=1 and live evidence; limitations reported above")
	}
	if err := s.Grade(); err != nil {
		t.Fatalf("acceptance grade failed: %v", err)
	}
}
