package acceptance

import (
	"strings"
	"testing"
)

func TestStatusVocabulary(t *testing.T) {
	for _, s := range []Status{Success, Failed, Unsupported, BlockedByNetwork, NotTested} {
		if !s.Valid() {
			t.Errorf("%q is not accepted", s)
		}
	}
	for _, s := range []Status{"", "ok", "PASS", "success"} {
		if s.Valid() {
			t.Errorf("%q is not part of the taxonomy but was accepted", s)
		}
	}
}

func TestStandardMatrixIsInternallyConsistent(t *testing.T) {
	m := Standard()
	seen := map[string]bool{}
	required := 0
	for _, c := range m.cases {
		if c.ID == "" || c.Requirement == "" {
			t.Errorf("case %q has an empty id or requirement", c.ID)
		}
		if seen[c.ID] {
			t.Errorf("duplicate case %q", c.ID)
		}
		seen[c.ID] = true
		if len(c.Allowed) == 0 {
			t.Errorf("case %q allows no status", c.ID)
		}
		for _, s := range c.Allowed {
			if !s.Valid() {
				t.Errorf("case %q allows unknown status %q", c.ID, s)
			}
		}
		if c.Required {
			required++
			allowed := false
			for _, s := range c.Allowed {
				if s == Success {
					allowed = true
				}
			}
			if !allowed {
				t.Errorf("required case %q does not allow SUCCESS", c.ID)
			}
		}
	}
	if required == 0 {
		t.Fatal("matrix has no required case")
	}
}

func TestEvaluateAllRejectsMissingCase(t *testing.T) {
	m := Standard()
	var results []Result
	for _, c := range m.cases[1:] {
		results = append(results, Result{Case: c.ID, Status: c.Allowed[0]})
	}
	if err := m.EvaluateAll(results); err == nil || !strings.Contains(err.Error(), m.cases[0].ID) {
		t.Fatalf("missing case not reported: %v", err)
	}
}

func TestEvaluateAllRejectsUnexpectedStatus(t *testing.T) {
	m := Standard()
	results := make([]Result, 0, len(m.cases))
	for _, c := range m.cases {
		results = append(results, Result{Case: c.ID, Status: c.Allowed[0]})
	}
	// A single endpoint passing must not be reported as VLESS encryption
	// working when the encrypted-fallback case says otherwise.
	results[0].Status = NotTested
	if err := m.EvaluateAll(results); err == nil || !strings.Contains(err.Error(), m.cases[0].ID) {
		t.Fatalf("unexpected status not reported: %v", err)
	}
}

func TestAcceptanceGradeRequiresSuccess(t *testing.T) {
	m := Standard()
	results := make([]Result, 0, len(m.cases))
	for _, c := range m.cases {
		results = append(results, Result{Case: c.ID, Status: c.Allowed[0]})
	}
	// vless.modern-encryption.xray allows BLOCKED_BY_NETWORK, so this stays
	// matrix-valid while still failing the acceptance grade.
	for i := range results {
		if results[i].Case == "vless.modern-encryption.xray" {
			results[i].Status = BlockedByNetwork
		}
	}
	if err := m.EvaluateAll(results); err != nil {
		t.Fatalf("blocked case should still be matrix-valid: %v", err)
	}
	if err := m.AcceptanceGrade(results); err == nil {
		t.Fatal("AcceptanceGrade accepted a run with a blocked required case")
	}

	for i := range results {
		if c, _ := m.Case(results[i].Case); c.Required {
			results[i].Status = Success
		}
	}
	if err := m.AcceptanceGrade(results); err != nil {
		t.Fatalf("AcceptanceGrade rejected an all-success run: %v", err)
	}
}
