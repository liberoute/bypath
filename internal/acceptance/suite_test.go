package acceptance_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liberoute/bypath/internal/acceptance"
)

func allowedResults(t *testing.T, m acceptance.Matrix) []acceptance.Result {
	t.Helper()
	out := make([]acceptance.Result, 0, len(m.Cases()))
	for _, c := range m.Cases() {
		status := c.Allowed[0]
		if c.Required {
			status = acceptance.Success
		}
		out = append(out, acceptance.Result{Case: c.ID, Status: status})
	}
	return out
}

func TestSuiteRejectsUnknownAndDuplicateCases(t *testing.T) {
	s := acceptance.NewSuite(acceptance.Standard())
	if err := s.Record(acceptance.Result{Case: "no.such-case", Status: acceptance.Success}); err == nil {
		t.Fatal("unknown case was accepted")
	}
	known := "vless.encrypted-fallback"
	if err := s.Record(acceptance.Result{Case: known, Status: acceptance.Failed}); err != nil {
		t.Fatal(err)
	}
	if err := s.Record(acceptance.Result{Case: known, Status: acceptance.Failed}); err == nil {
		t.Fatal("duplicate result silently overwrote the first one")
	}
	if err := s.Record(acceptance.Result{Case: "vless.modern-encryption.sing-box", Status: "PASS"}); err == nil {
		t.Fatal("unknown status was accepted")
	}
}

func TestSuiteMissingCasesAreExplicitNotTested(t *testing.T) {
	m := acceptance.Standard()
	s := acceptance.NewSuite(m)
	if err := s.Record(acceptance.Result{Case: "vless.encrypted-fallback", Status: acceptance.Failed}); err != nil {
		t.Fatal(err)
	}
	if err := s.Limit("openvpn.sing-box-endpoint", "no live OpenVPN credentials in this run"); err != nil {
		t.Fatal(err)
	}

	results := s.Results()
	if len(results) != len(m.Cases()) {
		t.Fatalf("Results() returned %d rows, want one per case (%d)", len(results), len(m.Cases()))
	}
	for _, r := range results {
		if r.Case == "openvpn.sing-box-endpoint" {
			if r.Status != acceptance.NotTested || !strings.Contains(r.Detail, "credentials") {
				t.Fatalf("limited case = %+v, want NOT_TESTED with the limitation", r)
			}
		}
	}
	if missing := s.Missing(); len(missing) != len(m.Cases())-2 {
		t.Fatalf("Missing() = %v, want every case without evidence", missing)
	}
	if err := s.Evaluate(); err != nil {
		t.Fatalf("partial run should still validate its recorded results: %v", err)
	}
	if err := s.Grade(); err == nil {
		t.Fatal("Grade accepted a partial run")
	}
}

func TestSuiteRequiredFailureFailsGrade(t *testing.T) {
	m := acceptance.Standard()
	s := acceptance.NewSuite(m)
	for _, r := range allowedResults(t, m) {
		// A required case blocked by the network is matrix-valid but not
		// acceptance-grade.
		if r.Case == "vless.modern-encryption.xray" {
			r.Status = acceptance.BlockedByNetwork
		}
		if err := s.Record(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Evaluate(); err != nil {
		t.Fatalf("blocked required case should still be allowed by the matrix: %v", err)
	}
	if err := s.Grade(); err == nil || !strings.Contains(err.Error(), "vless.modern-encryption.xray") {
		t.Fatalf("Grade = %v, want a required-case failure", err)
	}
}

func TestSuiteAllAllowedResultsGraduate(t *testing.T) {
	m := acceptance.Standard()
	s := acceptance.NewSuite(m)
	for _, r := range allowedResults(t, m) {
		if err := s.Record(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Grade(); err != nil {
		t.Fatalf("Grade rejected a complete matrix: %v", err)
	}
}

func TestEvidenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	want := acceptance.Result{Case: "openvpn.sing-box-endpoint", Status: acceptance.Success, Detail: "https ok; secret-free detail"}
	if err := acceptance.WriteEvidence(dir, want); err != nil {
		t.Fatal(err)
	}
	got, err := acceptance.LoadEvidenceDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("LoadEvidenceDir = %+v, want %+v", got, want)
	}

	if err := acceptance.WriteEvidence(dir, acceptance.Result{Case: "x", Status: "PASS"}); err == nil {
		t.Fatal("invalid status was written as evidence")
	}
	if err := os.WriteFile(filepath.Join(dir, "bad.json"), []byte(`{"case":"x","status":"PASS"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := acceptance.LoadEvidenceDir(dir); err == nil {
		t.Fatal("invalid status was loaded from evidence")
	}
}
