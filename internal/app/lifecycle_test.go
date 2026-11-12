package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/credential"
)

type stubRuntime struct {
	status   RuntimeStatus
	apply    func()
	applyErr error

	stopTunnelCalls  int
	requestStopCalls int
	applyCalls       int
}

func (s *stubRuntime) Status() RuntimeStatus { return s.status }
func (s *stubRuntime) ApplyActiveLink(context.Context) error {
	s.applyCalls++
	if s.applyCalls == 1 && s.applyErr != nil {
		return s.applyErr
	}
	if s.apply != nil {
		s.apply()
	}
	return nil
}
func (s *stubRuntime) StopTunnel(context.Context) error {
	s.stopTunnelCalls++
	return nil
}
func (s *stubRuntime) RequestStop() error {
	s.requestStopCalls++
	return nil
}
func (s *stubRuntime) Engines() []Engine              { return nil }
func (s *stubRuntime) Reload(*config.Config) []string { return nil }

// TestDisconnectStopsOnlyTheTunnel separates the two lifecycle actions: a
// disconnect must keep the management process alive, and only Shutdown asks the
// daemon to exit.
func TestDisconnectStopsOnlyTheTunnel(t *testing.T) {
	svc, _ := newTestLocal(t)
	rt := &stubRuntime{status: RuntimeStatus{State: "CONNECTED"}}
	svc.runtime = rt

	res, err := svc.Disconnect(context.Background())
	if err != nil {
		t.Fatalf("disconnect: %v", err)
	}
	if !res.Applied {
		t.Fatalf("disconnect was not applied: %+v", res)
	}
	if rt.stopTunnelCalls != 1 || rt.requestStopCalls != 0 {
		t.Fatalf("stopTunnel=%d requestStop=%d, want 1/0", rt.stopTunnelCalls, rt.requestStopCalls)
	}
	if !strings.Contains(res.Message, "management service stays available") {
		t.Fatalf("message does not describe the surviving service: %q", res.Message)
	}
}

func TestShutdownStopsTheDaemon(t *testing.T) {
	svc, _ := newTestLocal(t)
	rt := &stubRuntime{status: RuntimeStatus{State: "CONNECTED"}}
	svc.runtime = rt

	res, err := svc.Shutdown(context.Background())
	if err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if !res.Applied {
		t.Fatalf("shutdown was not applied: %+v", res)
	}
	if rt.requestStopCalls != 1 || rt.stopTunnelCalls != 0 || rt.applyCalls != 0 {
		t.Fatalf("stopTunnel=%d requestStop=%d apply=%d, want 0/1/0",
			rt.stopTunnelCalls, rt.requestStopCalls, rt.applyCalls)
	}
}

func TestDisconnectWithoutRuntimeIsNotAnError(t *testing.T) {
	svc, _ := newTestLocal(t)
	res, err := svc.Disconnect(context.Background())
	if err != nil {
		t.Fatalf("disconnect without a runtime: %v", err)
	}
	if res.Applied {
		t.Fatalf("disconnect reported applied with no runtime: %+v", res)
	}
}

func TestConnectReportsFallbackLink(t *testing.T) {
	svc, _ := newTestLocal(t)
	ctx := context.Background()
	if _, err := svc.ImportURI(ctx, "default", testVLESS); err != nil {
		t.Fatalf("import: %v", err)
	}
	rt := &stubRuntime{status: RuntimeStatus{State: "CONNECTED", ActiveLink: "old-link"}}
	rt.apply = func() { rt.status.ActiveLink = "beaver" }
	svc.runtime = rt

	res, err := svc.Connect(ctx, "default:node-a")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if !res.Applied {
		t.Fatalf("fallback connection was not reported as applied: %+v", res)
	}
	if !strings.Contains(res.Message, `Connected through "beaver" instead`) {
		t.Fatalf("message does not report the fallback link: %q", res.Message)
	}
	if strings.Contains(res.Message, `Connected through "node-a"`) {
		t.Fatalf("message claims the requested link is active: %q", res.Message)
	}
}

func TestConnectReportsRequestedLinkWhenItConnects(t *testing.T) {
	svc, _ := newTestLocal(t)
	ctx := context.Background()
	if _, err := svc.ImportURI(ctx, "default", testVLESS); err != nil {
		t.Fatalf("import: %v", err)
	}
	rt := &stubRuntime{status: RuntimeStatus{State: "CONNECTED", ActiveLink: "old-link"}}
	rt.apply = func() { rt.status.ActiveLink = "node-a" }
	svc.runtime = rt

	res, err := svc.Connect(ctx, "default:node-a")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if !strings.Contains(res.Message, `Connected through "node-a".`) {
		t.Fatalf("message does not report the connected link: %q", res.Message)
	}
	if strings.Contains(res.Message, "instead") {
		t.Fatalf("unexpected fallback wording: %q", res.Message)
	}
}

func TestConnectDistinguishesSameRemarkAcrossGroups(t *testing.T) {
	svc, _ := newTestLocal(t)
	ctx := context.Background()
	if _, err := svc.ImportURI(ctx, "default", testVLESS); err != nil {
		t.Fatalf("import default: %v", err)
	}
	// A different link with the same display name in another group.
	const otherVLESS = "vless://22222222-2222-2222-2222-222222222222@other.example.com:443?security=tls&type=ws#node-a"
	if _, err := svc.ImportURI(ctx, "other", otherVLESS); err != nil {
		t.Fatalf("import other: %v", err)
	}
	def, _, err := svc.findLink("default:node-a")
	if err != nil {
		t.Fatalf("find default link: %v", err)
	}
	svc.profiles.SetActiveLink(def)

	applied := false
	rt := &stubRuntime{status: RuntimeStatus{State: "CONNECTED", ActiveLink: "node-a"}}
	rt.apply = func() { applied = true }
	svc.runtime = rt

	res, err := svc.Connect(ctx, "other:node-a")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if !applied {
		t.Fatal("a same-named link in another group was treated as already active")
	}
	if strings.Contains(res.Message, "already") {
		t.Fatalf("message claims the other group's link is active: %q", res.Message)
	}
	if !strings.Contains(res.Message, `Connected through "node-a"`) {
		t.Fatalf("unexpected message: %q", res.Message)
	}
}

// A failed switch must not leave the gateway on the dead profile. The service
// re-applies the connection that was serving before the attempt.
func TestFailedConnectRestoresPreviousConnection(t *testing.T) {
	svc, _ := newTestLocal(t)
	ctx := context.Background()
	if _, err := svc.ImportURI(ctx, "default", testVLESS); err != nil {
		t.Fatalf("import node-a: %v", err)
	}
	const second = "vless://33333333-3333-3333-3333-333333333333@second.example.com:443?security=tls&type=ws#node-b"
	if _, err := svc.ImportURI(ctx, "default", second); err != nil {
		t.Fatalf("import node-b: %v", err)
	}
	first, _, err := svc.findLink("default:node-a")
	if err != nil {
		t.Fatal(err)
	}
	svc.profiles.SetActiveLink(first)

	rt := &stubRuntime{
		status:   RuntimeStatus{State: "CONNECTED", ActiveLink: "node-a", ActiveGroup: "default"},
		applyErr: errors.New("handshake timeout"),
	}
	rt.apply = func() { rt.status.ActiveLink = "node-a" }
	svc.runtime = rt

	if _, err := svc.Connect(ctx, "default:node-b"); err == nil {
		t.Fatal("a failed switch was reported as successful")
	} else {
		var ae *Error
		if !errors.As(err, &ae) {
			t.Fatalf("error is not typed: %T", err)
		}
		if ae.Code != CodeUnavailable {
			t.Fatalf("code = %q, want %q", ae.Code, CodeUnavailable)
		}
		if !strings.Contains(ae.Hint, "rolled back") || !strings.Contains(ae.Hint, "node-a") {
			t.Fatalf("hint does not describe the rollback: %q", ae.Hint)
		}
	}
	if rt.applyCalls != 2 {
		t.Fatalf("apply calls = %d, want 2 (failed switch + rollback)", rt.applyCalls)
	}
	if active := svc.profiles.GetActiveLink(); active == nil || active.Remark != "node-a" {
		t.Fatalf("selection was not restored: %+v", active)
	}
	if got := svc.previous(); got != "default:node-a" {
		t.Fatalf("previous = %q, want default:node-a", got)
	}
	st, err := svc.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.PreviousLink != "node-a" || st.PreviousID != "default:node-a" {
		t.Fatalf("status previous = %q/%q", st.PreviousID, st.PreviousLink)
	}
}

// RestorePrevious goes back through the same serialised apply path.
func TestRestorePreviousConnectsToThePriorLink(t *testing.T) {
	svc, _ := newTestLocal(t)
	ctx := context.Background()
	if _, err := svc.ImportURI(ctx, "default", testVLESS); err != nil {
		t.Fatalf("import node-a: %v", err)
	}
	const second = "vless://44444444-4444-4444-4444-444444444444@second.example.com:443?security=tls&type=ws#node-b"
	if _, err := svc.ImportURI(ctx, "default", second); err != nil {
		t.Fatalf("import node-b: %v", err)
	}
	rt := &stubRuntime{status: RuntimeStatus{State: "CONNECTED", ActiveLink: "node-b", ActiveGroup: "default"}}
	rt.apply = func() {
		if active := svc.profiles.GetActiveLink(); active != nil {
			rt.status.ActiveLink = active.Remark
			rt.status.ActiveGroup = active.Group
		}
	}
	svc.runtime = rt
	second_, _, err := svc.findLink("default:node-b")
	if err != nil {
		t.Fatal(err)
	}
	svc.profiles.SetActiveLink(second_)

	if _, err := svc.Connect(ctx, "default:node-a"); err != nil {
		t.Fatalf("connect node-a: %v", err)
	}
	if got := svc.previous(); got != "default:node-b" {
		t.Fatalf("previous = %q, want default:node-b", got)
	}
	res, err := svc.RestorePrevious(ctx)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if !res.Applied || !strings.Contains(res.Message, "node-b") {
		t.Fatalf("restore result = %+v", res)
	}
	if active := svc.profiles.GetActiveLink(); active == nil || active.Remark != "node-b" {
		t.Fatalf("restored link is not selected: %+v", active)
	}
}

func TestRestorePreviousWithoutHistoryIsRejected(t *testing.T) {
	svc, _ := newTestLocal(t)
	if _, err := svc.RestorePrevious(context.Background()); err == nil {
		t.Fatal("restore without a previous connection was accepted")
	} else if CodeOf(err) != CodeConflict {
		t.Fatalf("code = %q, want %q", CodeOf(err), CodeConflict)
	}
}

// TestConnectRequiresCredentialsBeforePersistingSelection covers S0.4: an
// OpenVPN link that declares auth-user-pass must be refused with a typed
// credentials_required error before .active is written.
func TestConnectRequiresCredentialsBeforePersistingSelection(t *testing.T) {
	svc, _ := newTestLocal(t)
	ctx := context.Background()
	const ovpn = "client\ndev tun\nproto udp\nremote 203.0.113.20 1194\nauth-user-pass\n"
	res, err := svc.ImportOpenVPN(ctx, OVPNImport{
		OVPNSource: OVPNSource{Text: ovpn, Name: "needs-auth"},
		Group:      "lab",
		Username:   "u",
		Password:   "p",
	})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(res.Created) != 1 {
		t.Fatalf("import created %d links", len(res.Created))
	}
	id := res.Created[0].ID
	// Simulate a profile directory copied without its credential store: the
	// link still declares auth-user-pass, but no stored credential resolves.
	link, _, err := svc.findLink(id)
	if err != nil {
		t.Fatal(err)
	}
	key := credential.KeyFor(link)
	if err := svc.creds.DeleteSaved(key); err != nil {
		t.Fatalf("delete saved credential: %v", err)
	}
	_ = svc.creds.DeleteSession(key)

	_, err = svc.Connect(ctx, id)
	var appErr *Error
	if !errors.As(err, &appErr) || appErr.Code != CodeNeedsCreds {
		t.Fatalf("connect error = %v, want code %s", err, CodeNeedsCreds)
	}
	if strings.Contains(err.Error(), "auth-user-pass") || strings.Contains(err.Error(), "203.0.113.20") {
		t.Fatalf("error leaks profile details: %v", err)
	}
	if active := svc.profiles.GetActiveLink(); active != nil {
		t.Fatalf("selection was persisted despite missing credentials: %+v", active)
	}

	if err := svc.SetCredentials(ctx, id, Credentials{Username: "u", Password: "p"}, false); err != nil {
		t.Fatalf("set credentials: %v", err)
	}
	if _, err := svc.Connect(ctx, id); err != nil {
		t.Fatalf("connect after credentials: %v", err)
	}
}
