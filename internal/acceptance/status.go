// Package acceptance defines the result vocabulary and expected-results matrix
// used for engineering acceptance. A run is only meaningful when every matrix
// case has an explicit result; a single passing endpoint is not acceptance.
package acceptance

import (
	"errors"
	"fmt"
)

// Status is the complete vocabulary for acceptance results.
type Status string

const (
	// Success means the case completed with real evidence (for connectivity:
	// an HTTPS round trip through the tunnel, not just an open port).
	Success Status = "SUCCESS"
	// Failed means the case ran and did not meet its requirement.
	Failed Status = "FAILED"
	// Unsupported means the product deliberately refuses the combination
	// (wrong engine, unpinned platform, unimplemented transport).
	Unsupported Status = "UNSUPPORTED"
	// BlockedByNetwork means the case could not run because of an observed,
	// controlled network condition (no IPv6 address, DNS outage) and never
	// substitutes for evidence of success.
	BlockedByNetwork Status = "BLOCKED_BY_NETWORK"
	// NotTested means no evidence was collected; it can never satisfy a
	// required case.
	NotTested Status = "NOT_TESTED"
)

func (s Status) Valid() bool {
	switch s {
	case Success, Failed, Unsupported, BlockedByNetwork, NotTested:
		return true
	}
	return false
}

// Case is one row of the expected-results matrix.
type Case struct {
	ID          string
	Requirement string
	// Allowed lists the statuses the matrix accepts. A case whose behavior is
	// deterministic allows exactly one status.
	Allowed []Status
	// Required means the case must reach Success for a run to count as
	// acceptance-grade. Refusal cases and evidence-limited cases are not
	// required.
	Required bool
}

// Result is the observed outcome for one matrix case.
type Result struct {
	Case   string
	Status Status
	Detail string
}

// Matrix is the expected-results matrix.
type Matrix struct {
	cases []Case
}

// Standard returns the acceptance matrix for the VLESS/OpenVPN work.
func Standard() Matrix {
	return Matrix{cases: []Case{
		{
			ID:          "vless.modern-encryption.xray",
			Requirement: "VLESS encryption=mlkem768x25519plus is preserved and runs on the pinned Xray engine",
			Allowed:     []Status{Success, BlockedByNetwork},
			Required:    true,
		},
		{
			ID:          "vless.modern-encryption.sing-box",
			Requirement: "sing-box refuses VLESS Encryption instead of silently stripping it",
			Allowed:     []Status{Unsupported},
		},
		{
			ID:          "vless.encrypted-fallback",
			Requirement: "an encrypted VLESS selection never falls back to a plain or OpenVPN profile",
			Allowed:     []Status{Failed},
		},
		{
			ID:          "openvpn.sing-box-endpoint",
			Requirement: "an imported OpenVPN profile completes HTTPS and recovers after restart",
			Allowed:     []Status{Success, BlockedByNetwork},
			Required:    true,
		},
		{
			ID:          "openvpn.xray",
			Requirement: "OpenVPN is refused on engines without the openvpn-client endpoint",
			Allowed:     []Status{Unsupported},
		},
		{
			ID:          "engine.unpinned-platform",
			Requirement: "an engine download without a pinned checksum for the exact platform fails closed",
			Allowed:     []Status{Failed, Unsupported},
		},
		{
			ID:          "network.proxy-only-isolation",
			Requirement: "proxy-only runs leave host DNS, routes, interfaces and firewall untouched",
			Allowed:     []Status{Success},
			Required:    true,
		},
		{
			ID:          "network.ipv6-dual-stack",
			Requirement: "IPv6 egress is only claimed with real dual-stack evidence; otherwise isolated or blocked",
			Allowed:     []Status{Success, BlockedByNetwork, NotTested},
		},
	}}
}

// Cases returns the matrix rows in order.
func (m Matrix) Cases() []Case {
	out := make([]Case, len(m.cases))
	copy(out, m.cases)
	return out
}

// Case looks up one row.
func (m Matrix) Case(id string) (Case, bool) {
	for _, c := range m.cases {
		if c.ID == id {
			return c, true
		}
	}
	return Case{}, false
}

// EvaluateAll requires exactly one result per matrix case and rejects any
// status the matrix does not allow. This is what makes the matrix enforceable:
// a partial run cannot pass as complete.
func (m Matrix) EvaluateAll(results []Result) error {
	seen := make(map[string]bool, len(results))
	var errs []error
	for _, r := range results {
		c, ok := m.Case(r.Case)
		if !ok {
			errs = append(errs, fmt.Errorf("result for unknown case %q", r.Case))
			continue
		}
		if seen[r.Case] {
			errs = append(errs, fmt.Errorf("case %q reported more than once", r.Case))
			continue
		}
		seen[r.Case] = true
		if err := c.Evaluate(r); err != nil {
			errs = append(errs, err)
		}
	}
	for _, c := range m.cases {
		if !seen[c.ID] {
			errs = append(errs, fmt.Errorf("case %q has no result", c.ID))
		}
	}
	return errors.Join(errs...)
}

// AcceptanceGrade applies EvaluateAll and additionally requires every
// Required case to reach Success. A run that is merely complete, or that was
// blocked by the network, is reported honestly but is not acceptance-grade.
func (m Matrix) AcceptanceGrade(results []Result) error {
	if err := m.EvaluateAll(results); err != nil {
		return err
	}
	byID := make(map[string]Result, len(results))
	for _, r := range results {
		byID[r.Case] = r
	}
	var errs []error
	for _, c := range m.cases {
		if c.Required && byID[c.ID].Status != Success {
			errs = append(errs, fmt.Errorf("required case %q is %s, not %s", c.ID, byID[c.ID].Status, Success))
		}
	}
	return errors.Join(errs...)
}

// Evaluate checks one result against its case.
func (c Case) Evaluate(r Result) error {
	if !r.Status.Valid() {
		return fmt.Errorf("case %q reported unknown status %q", c.ID, r.Status)
	}
	for _, allowed := range c.Allowed {
		if r.Status == allowed {
			return nil
		}
	}
	return fmt.Errorf("case %q reported %s; allowed: %v", c.ID, r.Status, c.Allowed)
}
