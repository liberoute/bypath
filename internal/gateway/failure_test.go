package gateway

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/liberoute/bypath/internal/engine"
	"github.com/liberoute/bypath/internal/profile"
)

var fixedFailureTime = time.Date(2026, 11, 9, 14, 30, 0, 0, time.UTC)

func TestLinkFailureNamesSelectedLinkAndEveryFallback(t *testing.T) {
	cause := errors.New("local configuration error for link 'eu-tcp': OpenVPN profile is unreadable")
	f := &linkFailure{
		Selected: "imported:eu-tcp",
		Group:    "imported",
		At:       fixedFailureTime,
		Cause:    cause,
		Fallbacks: []linkAttempt{
			{Link: "imported:us-tcp", Err: errors.New("connect: connection refused")},
			{Link: "imported:us-udp53b", Err: errors.New("no connectivity through the tunnel")},
		},
	}

	msg := f.Error()
	for _, want := range []string{
		"link 'imported:eu-tcp' failed at " + fixedFailureTime.UTC().Format("2006-01-02T15:04:05Z"),
		cause.Error(),
		"fallback links tried",
		"imported:us-tcp → connect: connection refused",
		"imported:us-udp53b → no connectivity through the tunnel",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q missing %q", msg, want)
		}
	}
	// The selected link must be the reported cause, not the last candidate.
	if strings.Index(msg, "eu-tcp") > strings.Index(msg, "us-udp53b") {
		t.Errorf("selected link is reported after a fallback: %q", msg)
	}
}

func TestLinkFailureWithoutCauseStillNamesGroup(t *testing.T) {
	f := &linkFailure{Group: "imported", At: fixedFailureTime}
	if got := f.Error(); got != "no working link found in group 'imported'" {
		t.Fatalf("message = %q", got)
	}
}

func TestLinkFailureIsPermanentOnlyWhenEveryAttemptIsLocal(t *testing.T) {
	local := fmt.Errorf("%w: OpenVPN profile is unreadable", engine.ErrLocalConfig)

	allLocal := &linkFailure{
		Selected: "imported:eu-tcp",
		Group:    "imported",
		At:       fixedFailureTime,
		Cause:    local,
		Fallbacks: []linkAttempt{
			{Link: "imported:us-tcp", Err: local},
		},
	}
	if !allLocal.allLocalConfig() {
		t.Fatal("all-local failure was not recognised")
	}
	if !errors.Is(permanent(allLocal), engine.ErrLocalConfig) {
		t.Fatal("wrapped failure lost the ErrLocalConfig sentinel")
	}

	mixed := &linkFailure{
		Selected: "imported:eu-tcp",
		Group:    "imported",
		At:       fixedFailureTime,
		Cause:    local,
		Fallbacks: []linkAttempt{
			{Link: "imported:us-tcp", Err: errors.New("i/o timeout")},
		},
	}
	if mixed.allLocalConfig() {
		t.Fatal("one network failure must keep the chain retryable")
	}
}

func TestOutcomeErrorNamesLinkWhenProbeFails(t *testing.T) {
	err := outcomeError(&profile.Link{Group: "imported", Remark: "eu-tcp"}, nil)
	if err == nil || !strings.Contains(err.Error(), "imported:eu-tcp") {
		t.Fatalf("err = %v, want the link named", err)
	}
}

// TestFallbackChainReportsSelectedLinkFirst proves the chain no longer reports
// the last candidate as the cause when the selected link is the one that is
// broken. All four OpenVPN links shared the same unreadable profile, but the
// dashboard showed 'us-udp53b' because it was the last fallback tried.
func TestFallbackChainReportsSelectedLinkFirst(t *testing.T) {
	gw, _ := newFallbackTestGateway(t, "2s", "5s")
	selected := gw.getActiveLink()
	local := fmt.Errorf("%w: OpenVPN profile for 'dead-a': artifact not found", engine.ErrLocalConfig)
	stubFallbackProbes(t, func(context.Context, *profile.Link) error { return local }, nil)

	gw.mu.Lock()
	err := gw.startEngineWithLinkFallback(selected)
	gw.mu.Unlock()
	if err == nil {
		t.Fatal("fallback reported success with only broken links")
	}
	if !IsPermanent(err) {
		t.Fatalf("all-local failure must stop the run loop, got %v", err)
	}
	msg := err.Error()
	if !strings.HasPrefix(msg, "link 'default:dead-a' failed at ") {
		t.Fatalf("message must start with the selected link and its timestamp: %q", msg)
	}
	for _, want := range []string{"dead-b", "dead-c", "fallback links tried"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q missing %q", msg, want)
		}
	}
	if !errors.Is(err, engine.ErrLocalConfig) {
		t.Fatal("permanent chain lost the ErrLocalConfig sentinel")
	}
}
