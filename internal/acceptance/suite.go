package acceptance

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Suite collects one result per matrix case from deterministic probes and from
// recorded live evidence. Cases that were never exercised are reported as
// NOT_TESTED with an explicit limitation instead of being silently omitted.
type Suite struct {
	matrix      Matrix
	results     map[string]Result
	limitations map[string]string
}

// NewSuite returns an empty suite for the given matrix.
func NewSuite(m Matrix) *Suite {
	return &Suite{matrix: m, results: make(map[string]Result), limitations: make(map[string]string)}
}

// Record stores the result for a known case. Recording an unknown case or the
// same case twice is an error: evidence must never be silently overwritten.
func (s *Suite) Record(r Result) error {
	if _, ok := s.matrix.Case(r.Case); !ok {
		return fmt.Errorf("result for unknown case %q", r.Case)
	}
	if _, dup := s.results[r.Case]; dup {
		return fmt.Errorf("case %q already has a result", r.Case)
	}
	if !r.Status.Valid() {
		return fmt.Errorf("case %q reported unknown status %q", r.Case, r.Status)
	}
	// Evidence supersedes an earlier limitation for the same case.
	delete(s.limitations, r.Case)
	s.results[r.Case] = r
	return nil
}

// Limit records why a case could not be exercised. A limitation is not a
// result: the case stays NOT_TESTED and can never satisfy Grade.
func (s *Suite) Limit(caseID, reason string) error {
	if _, ok := s.matrix.Case(caseID); !ok {
		return fmt.Errorf("limitation for unknown case %q", caseID)
	}
	if _, done := s.results[caseID]; done {
		return fmt.Errorf("case %q already has a result", caseID)
	}
	if strings.TrimSpace(reason) == "" {
		return fmt.Errorf("case %q has an empty limitation", caseID)
	}
	s.limitations[caseID] = reason
	return nil
}

// Results returns one result per matrix case in matrix order. Untested cases
// are reported NOT_TESTED so every row always has an explicit outcome.
func (s *Suite) Results() []Result {
	out := make([]Result, 0, len(s.matrix.cases))
	for _, c := range s.matrix.cases {
		if r, ok := s.results[c.ID]; ok {
			out = append(out, r)
			continue
		}
		out = append(out, Result{Case: c.ID, Status: NotTested, Detail: s.limitations[c.ID]})
	}
	return out
}

// Limitations returns one "<case>: <reason>" line per unexercised case.
func (s *Suite) Limitations() []string {
	var out []string
	for _, c := range s.matrix.cases {
		if reason, ok := s.limitations[c.ID]; ok {
			out = append(out, fmt.Sprintf("%s: %s", c.ID, reason))
		}
	}
	return out
}

// Missing returns the cases with neither a result nor a limitation.
func (s *Suite) Missing() []string {
	var out []string
	for _, c := range s.matrix.cases {
		if _, ok := s.results[c.ID]; !ok {
			if _, limited := s.limitations[c.ID]; !limited {
				out = append(out, c.ID)
			}
		}
	}
	return out
}

// Evaluate validates the results that were recorded. Cases without evidence are
// reported by Missing/Limitations and do not fail Evaluate, so a partial run
// stays honestly reportable; Grade is the acceptance gate.
func (s *Suite) Evaluate() error {
	var errs []error
	for _, c := range s.matrix.cases {
		if r, ok := s.results[c.ID]; ok {
			if err := c.Evaluate(r); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// Grade is acceptance-grade: every case must have a result, every result must
// be allowed by the matrix, and every required case must be SUCCESS. A single
// passing endpoint can never satisfy it.
func (s *Suite) Grade() error {
	if missing := s.Missing(); len(missing) > 0 {
		return fmt.Errorf("cases without evidence: %s", strings.Join(missing, ", "))
	}
	return s.matrix.AcceptanceGrade(s.Results())
}

// EvidenceDirEnv names the environment variable that points at the directory
// where live probes record their matrix results.
const EvidenceDirEnv = "BYPATH_ACCEPTANCE_EVIDENCE"

// EvidenceCommitEnv names the environment variable that binds evidence to the
// exact commit it was collected against. When it is set, evidence recorded at a
// different commit is rejected, so a stale result can never be assembled into a
// fresh acceptance run.
const EvidenceCommitEnv = "BYPATH_ACCEPTANCE_COMMIT"

// evidenceRecord is the on-disk form of one matrix result.
type evidenceRecord struct {
	Case   string `json:"case"`
	Status Status `json:"status"`
	Detail string `json:"detail,omitempty"`
	Commit string `json:"commit,omitempty"`
}

// WriteEvidence atomically records one live result as <dir>/<case>.json so a
// separate process can assemble the full matrix without sharing memory.
func WriteEvidence(dir string, r Result) error {
	if !r.Status.Valid() {
		return fmt.Errorf("case %q reported unknown status %q", r.Case, r.Status)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(evidenceRecord{
		Case:   r.Case,
		Status: r.Status,
		Detail: r.Detail,
		Commit: strings.TrimSpace(os.Getenv(EvidenceCommitEnv)),
	}, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".evidence-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, filepath.Join(dir, r.Case+".json"))
}

// LoadEvidenceDir reads every <case>.json file written by WriteEvidence.
func LoadEvidenceDir(dir string) ([]Result, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []Result
	wantCommit := strings.TrimSpace(os.Getenv(EvidenceCommitEnv))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		var v evidenceRecord
		if err := json.Unmarshal(data, &v); err != nil {
			return nil, fmt.Errorf("reading %s: %w", entry.Name(), err)
		}
		if !v.Status.Valid() {
			return nil, fmt.Errorf("reading %s: unknown status %q", entry.Name(), v.Status)
		}
		if wantCommit != "" && v.Commit != wantCommit {
			return nil, fmt.Errorf("evidence %s was recorded at commit %q, not %q", entry.Name(), v.Commit, wantCommit)
		}
		out = append(out, Result{Case: v.Case, Status: v.Status, Detail: v.Detail})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Case < out[j].Case })
	return out, nil
}
