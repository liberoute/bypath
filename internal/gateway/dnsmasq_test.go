package gateway

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestDnsmasqPriorState_ObserveOnce(t *testing.T) {
	var s dnsmasqPriorState
	s.observe(true, true)
	s.observe(true, false)
	if !s.exists || !s.wasActive {
		t.Fatalf("first observation must stick, got exists=%v wasActive=%v", s.exists, s.wasActive)
	}
}

func TestDnsmasqPriorState_Transitions(t *testing.T) {
	cases := []struct {
		name      string
		exists    bool
		active    bool
		wantStop  bool
		wantStart bool
	}{
		{name: "A active", exists: true, active: true, wantStop: true, wantStart: true},
		{name: "B inactive", exists: true, active: false, wantStop: false, wantStart: false},
		{name: "C absent", exists: false, active: true, wantStop: false, wantStart: false},
		{name: "C absent inactive", exists: false, active: false, wantStop: false, wantStart: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var s dnsmasqPriorState
			s.observe(tc.exists, tc.active)
			if s.shouldStop() != tc.wantStop {
				t.Fatalf("shouldStop=%v want %v", s.shouldStop(), tc.wantStop)
			}
			if s.shouldRestore() != tc.wantStart {
				t.Fatalf("shouldRestore=%v want %v", s.shouldRestore(), tc.wantStart)
			}
		})
	}
}

func withMockSystemctl(t *testing.T, output func([]string) ([]byte, error), run func([]string) error) {
	t.Helper()
	origOut, origRun := systemctlOutput, systemctlRun
	t.Cleanup(func() {
		systemctlOutput, systemctlRun = origOut, origRun
	})
	systemctlOutput = func(args ...string) ([]byte, error) { return output(args) }
	systemctlRun = func(args ...string) error { return run(args) }
}

func TestStopRestoreDnsmasq_CaseA_ActiveRestored(t *testing.T) {
	var ops []string
	withMockSystemctl(t,
		func(args []string) ([]byte, error) {
			if len(args) >= 1 && args[0] == "is-active" {
				return []byte("active\n"), nil
			}
			return nil, nil
		},
		func(args []string) error {
			ops = append(ops, strings.Join(args, " "))
			return nil
		},
	)
	gw := newTestGateway(true, false)
	gw.stopDnsmasq()
	gw.restoreDnsmasq()
	if !containsOp(ops, "stop dnsmasq") {
		t.Fatalf("expected stop, ops=%v", ops)
	}
	if !containsOp(ops, "start dnsmasq") {
		t.Fatalf("expected start restore, ops=%v", ops)
	}
}

func TestStopRestoreDnsmasq_CaseB_InactiveNotStarted(t *testing.T) {
	var ops []string
	withMockSystemctl(t,
		func(args []string) ([]byte, error) {
			if len(args) >= 1 && args[0] == "is-active" {
				return []byte("inactive\n"), errors.New("exit status 3")
			}
			return nil, nil
		},
		func(args []string) error {
			ops = append(ops, strings.Join(args, " "))
			if len(args) >= 1 && args[0] == "cat" {
				return nil
			}
			if len(args) >= 1 && (args[0] == "stop" || args[0] == "start") {
				t.Errorf("must not stop/start inactive dnsmasq: %v", args)
			}
			return nil
		},
	)
	gw := newTestGateway(true, false)
	gw.stopDnsmasq()
	gw.restoreDnsmasq()
	if containsOp(ops, "stop dnsmasq") || containsOp(ops, "start dnsmasq") {
		t.Fatalf("inactive unit must not be stopped or started, ops=%v", ops)
	}
}

func TestStopRestoreDnsmasq_CaseC_AbsentNoOp(t *testing.T) {
	var ops []string
	withMockSystemctl(t,
		func(args []string) ([]byte, error) {
			t.Errorf("is-active should not run when unit is absent: %v", args)
			return nil, errors.New("unexpected")
		},
		func(args []string) error {
			ops = append(ops, strings.Join(args, " "))
			if len(args) >= 1 && args[0] == "cat" {
				return errors.New("Unit dnsmasq.service could not be found")
			}
			t.Errorf("unexpected systemctl %v", args)
			return nil
		},
	)
	gw := newTestGateway(true, false)
	gw.stopDnsmasq()
	gw.restoreDnsmasq()
}

func TestStopRestoreDnsmasq_InactiveCleanupDoesNotStart(t *testing.T) {
	var starts int
	withMockSystemctl(t,
		func(args []string) ([]byte, error) {
			return []byte("failed\n"), errors.New("exit status 3")
		},
		func(args []string) error {
			if len(args) >= 1 && args[0] == "cat" {
				return nil
			}
			if len(args) >= 1 && args[0] == "start" {
				starts++
			}
			return nil
		},
	)
	gw := newTestGateway(true, false)
	gw.stopDnsmasq()
	gw.restoreDnsmasq()
	gw.restoreDnsmasq()
	if starts != 0 {
		t.Fatalf("cleanup must not invoke start when prior state was inactive, starts=%d", starts)
	}
}

func TestStopRestoreDnsmasq_CaptureOnceIgnoresLaterInactive(t *testing.T) {
	active := true
	var starts int
	withMockSystemctl(t,
		func(args []string) ([]byte, error) {
			if active {
				return []byte("active\n"), nil
			}
			return []byte("inactive\n"), errors.New("exit status 3")
		},
		func(args []string) error {
			if len(args) >= 1 && args[0] == "start" {
				starts++
			}
			if len(args) >= 1 && args[0] == "stop" {
				active = false
			}
			return nil
		},
	)
	gw := newTestGateway(true, false)
	gw.stopDnsmasq()
	gw.stopDnsmasq()
	gw.restoreDnsmasq()
	if starts != 1 {
		t.Fatalf("prior ACTIVE must still restore after later inactive observation, starts=%d", starts)
	}
}

func TestInstallShOmitsDnsmasqConflicts(t *testing.T) {
	b, err := os.ReadFile("../../install.sh")
	if err != nil {
		t.Fatalf("read install.sh: %v", err)
	}
	if strings.Contains(string(b), "Conflicts=dnsmasq.service") {
		t.Fatal("install.sh must not generate Conflicts=dnsmasq.service")
	}
}

func containsOp(ops []string, want string) bool {
	for _, op := range ops {
		if op == want {
			return true
		}
	}
	return false
}
