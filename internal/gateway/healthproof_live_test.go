package gateway

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/profile"
)

// TestLiveHealthEvidence runs the real observation code against a live SOCKS
// listener. It is skipped unless BYPATH_LIVE_SOCKS names the port, so the
// normal suite never touches the network. The lab uses it to prove that the
// exit and uplink observations come from independent paths, including the
// EXIT_IS_UPLINK and TUNNEL_DOWN verdicts, without starting a gateway.
func TestLiveHealthEvidence(t *testing.T) {
	raw := os.Getenv("BYPATH_LIVE_SOCKS")
	if raw == "" {
		t.Skip("BYPATH_LIVE_SOCKS unset")
	}
	port, err := strconv.Atoi(raw)
	if err != nil {
		t.Fatalf("BYPATH_LIVE_SOCKS=%q is not a port: %v", raw, err)
	}

	gw := &Gateway{config: &config.Config{}, socksPort: port}
	targets := gw.healthTargets()

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	answered := profile.TestAnyURL(ctx, gw.socksPort, targets)
	cancel()

	obs := HealthObservation{DataPathOK: true, Answered: answered, TargetCount: len(targets)}
	if answered {
		exits, uplink, attempts := gw.observeIdentity(context.Background())
		obs.Exits, obs.Uplink, obs.UplinkAttempts = exits, uplink, attempts
	}
	ev := classifyHealth(obs)
	t.Logf("targets=%v answered=%v exits=%v uplink=%v attempts=%d code=%s detail=%q",
		targets, answered, ev.ExitIPs, ev.Uplink, ev.UplinkAttempts, ev.Code, ev.Detail)

	if want := os.Getenv("BYPATH_LIVE_EXPECT"); want != "" && ev.Code != want {
		t.Fatalf("code = %s (%q), want %s", ev.Code, ev.Detail, want)
	}
}
