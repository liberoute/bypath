package gateway

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

// TestHealthVerdict pins the path-proof rule: a probe response only certifies
// the tunnel when the exit address through the SOCKS port differs from every
// direct observation. This is the case a DIRECT routing rule used to mask.
func TestHealthVerdict(t *testing.T) {
	cases := []struct {
		name     string
		answered bool
		exit     string
		uplink   []string
		want     bool
	}{
		{"no endpoint answered", false, "", nil, false},
		{"exit unknown", true, "", []string{"192.0.2.206"}, false},
		{"uplink unknown", true, "198.51.100.78", []string{""}, false},
		{"no direct sample", true, "198.51.100.78", nil, false},
		{"direct rule masked the probe", true, "192.0.2.206", []string{"192.0.2.206"}, false},
		{"masked with a rotating uplink", true, "192.0.2.206", []string{"192.0.2.206", "192.0.2.82"}, false},
		{"tunnel carried the probe", true, "198.51.100.78", []string{"192.0.2.206"}, true},
		{"tunnel carried with a rotating uplink", true, "198.51.100.78", []string{"192.0.2.206", "192.0.2.82", ""}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := healthVerdict(tc.answered, tc.exit, tc.uplink)
			if got != tc.want {
				t.Fatalf("healthVerdict = %v (%q), want %v", got, reason, tc.want)
			}
			if !got && reason == "" {
				t.Fatal("a refused verdict must carry a reason for the UI")
			}
			if got && reason != "" {
				t.Fatalf("a certified verdict must not carry a reason: %q", reason)
			}
		})
	}
}

// TestClassifyHealthSeparatesForwardingFromIdentity pins the two failure
// families. A dead data path or unanswered tunnel is a forwarding failure; an
// answered tunnel with an unprovable exit is an identity failure. Neither is
// Healthy, and the evidence records that the tunnel did answer.
func TestClassifyHealthSeparatesForwardingFromIdentity(t *testing.T) {
	cases := []struct {
		name           string
		obs            HealthObservation
		wantCode       string
		wantAnswered   bool
		wantHealthy    bool
		wantDetailNote bool
	}{
		{
			name:         "data path down short-circuits the probes",
			obs:          HealthObservation{DataPathOK: false, DataPathDetail: "tun0 is missing"},
			wantCode:     HealthDataPathDown,
			wantAnswered: false,
		},
		{
			name:         "dead tunnel: nothing answered",
			obs:          HealthObservation{DataPathOK: true, Answered: false, TargetCount: 2},
			wantCode:     HealthTunnelDown,
			wantAnswered: false,
		},
		{
			name:           "answered but no oracle identified the exit",
			obs:            HealthObservation{DataPathOK: true, Answered: true, TargetCount: 2, Uplink: []string{"192.0.2.206"}, UplinkAttempts: 4},
			wantCode:       HealthExitUnknown,
			wantAnswered:   true,
			wantDetailNote: true,
		},
		{
			name:           "answered but every identity endpoint failed",
			obs:            HealthObservation{DataPathOK: true, Answered: true, TargetCount: 2, Exits: []string{"198.51.100.78"}, UplinkAttempts: 4},
			wantCode:       HealthUplinkUnverified,
			wantAnswered:   true,
			wantDetailNote: true,
		},
		{
			name:         "exit equals a rotating direct sample",
			obs:          HealthObservation{DataPathOK: true, Answered: true, TargetCount: 2, Exits: []string{"192.0.2.82"}, Uplink: []string{"192.0.2.206", "192.0.2.82"}, UplinkAttempts: 4},
			wantCode:     HealthExitIsUplink,
			wantAnswered: true,
		},
		{
			name:         "healthy tunnel with rotating CGNAT uplink",
			obs:          HealthObservation{DataPathOK: true, Answered: true, TargetCount: 2, Exits: []string{"198.51.100.78"}, Uplink: []string{"192.0.2.206", "192.0.2.82", "198.51.100.99"}, UplinkAttempts: 4},
			wantCode:     HealthVerified,
			wantAnswered: true,
			wantHealthy:  true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := classifyHealth(tc.obs)
			if ev.Code != tc.wantCode {
				t.Fatalf("code = %q (%q), want %q", ev.Code, ev.Detail, tc.wantCode)
			}
			if ev.TunnelAnswered != tc.wantAnswered {
				t.Fatalf("TunnelAnswered = %v, want %v", ev.TunnelAnswered, tc.wantAnswered)
			}
			if ev.Healthy() != tc.wantHealthy {
				t.Fatalf("Healthy() = %v, want %v", ev.Healthy(), tc.wantHealthy)
			}
			if !ev.Healthy() && ev.Detail == "" {
				t.Fatal("a refused verdict must carry a detail for the UI")
			}
			if tc.wantDetailNote && !ev.TunnelAnswered {
				t.Fatal("an identity failure must still record that the tunnel answered")
			}
		})
	}
}

// TestClassifyHealthKeepsDirectResponsesUncertified states the two hard
// invariants explicitly: a DIRECT answer never certifies, and an unknown exit
// is never Healthy, even when the endpoints replied.
func TestClassifyHealthKeepsDirectResponsesUncertified(t *testing.T) {
	direct := []string{"198.51.100.7"}
	if ev := classifyHealth(HealthObservation{DataPathOK: true, Answered: true, TargetCount: 1, Exits: direct, Uplink: direct, UplinkAttempts: 1}); ev.Healthy() {
		t.Fatal("a DIRECT response certified the tunnel")
	}
	if ev := classifyHealth(HealthObservation{DataPathOK: true, Answered: true, TargetCount: 1, Uplink: direct, UplinkAttempts: 1}); ev.Healthy() {
		t.Fatal("an unknown exit was labelled Healthy")
	}
	// An identity outage must not be reported as a forwarding failure.
	ev := classifyHealth(HealthObservation{DataPathOK: true, Answered: true, TargetCount: 2, Exits: []string{"203.0.113.9"}, UplinkAttempts: 4})
	if ev.Code == HealthTunnelDown || ev.Code == HealthDataPathDown {
		t.Fatalf("an identity outage was classified as %q, not an identity code", ev.Code)
	}
}

func fetchMap(m map[string]string, fail map[string]bool) ipFetcher {
	return func(_ context.Context, target string) (string, error) {
		if fail[target] {
			return "", errors.New("unreachable")
		}
		if ip, ok := m[target]; ok {
			return ip, nil
		}
		return "", errors.New("unknown oracle")
	}
}

// TestCollectIdentitySamplesEveryOracle makes sure one unreachable oracle no
// longer invalidates the uplink proof: any answered identity service is enough,
// and a rotating CGNAT uplink keeps every distinct address for the comparison.
func TestCollectIdentitySamplesEveryOracle(t *testing.T) {
	var calls int32
	through := func(_ context.Context, target string) (string, error) {
		atomic.AddInt32(&calls, 1)
		if target == healthIdentityOracles[0] {
			return "198.51.100.78", nil
		}
		return "", errors.New("through-proxy unreachable")
	}
	rotate := []string{"192.0.2.206", "192.0.2.82", "192.0.2.206", ""}
	direct := func(_ context.Context, target string) (string, error) {
		atomic.AddInt32(&calls, 1)
		for i, oracle := range healthIdentityOracles {
			if oracle == target {
				if rotate[i] == "" {
					return "", errors.New("direct unreachable")
				}
				return rotate[i], nil
			}
		}
		return "", errors.New("unknown oracle")
	}

	exits, uplink, attempts := collectIdentity(context.Background(), through, direct)
	if attempts != len(healthIdentityOracles) {
		t.Fatalf("attempts = %d, want %d", attempts, len(healthIdentityOracles))
	}
	if len(exits) != 1 || exits[0] != "198.51.100.78" {
		t.Fatalf("exits = %v, want only the tunnel answer", exits)
	}
	want := []string{"192.0.2.206", "192.0.2.82"}
	if !reflect.DeepEqual(uplink, want) {
		t.Fatalf("uplink = %v, want distinct rotations %v", uplink, want)
	}
	if calls != 2*int32(len(healthIdentityOracles)) {
		t.Fatalf("oracle calls = %d, want every oracle sampled on both paths", calls)
	}
}

// TestCollectIdentityAllDirectOraclesUnreachable is the CGNAT/echo-outage case
// from the field: the tunnel answers, every direct identity endpoint is
// unreachable, and the result must be "uplink unverified", not "tunnel down".
func TestCollectIdentityAllDirectOraclesUnreachable(t *testing.T) {
	through := fetchMap(map[string]string{healthIdentityOracles[1]: "198.51.100.78"}, nil)
	direct := fetchMap(nil, map[string]bool{
		healthIdentityOracles[0]: true,
		healthIdentityOracles[1]: true,
		healthIdentityOracles[2]: true,
		healthIdentityOracles[3]: true,
	})

	exits, uplink, attempts := collectIdentity(context.Background(), through, direct)
	ev := classifyHealth(HealthObservation{
		DataPathOK: true, Answered: true, TargetCount: 2,
		Exits: exits, Uplink: uplink, UplinkAttempts: attempts,
	})
	if ev.Code != HealthUplinkUnverified {
		t.Fatalf("code = %q (%q), want %q", ev.Code, ev.Detail, HealthUplinkUnverified)
	}
	if !ev.TunnelAnswered {
		t.Fatal("the evidence must record that the tunnel answered")
	}
	if ev.Healthy() {
		t.Fatal("an unverified uplink certified the tunnel")
	}
}

// TestCollectIdentityHonoursCancellation keeps the health check bounded when
// every oracle hangs.
func TestCollectIdentityHonoursCancellation(t *testing.T) {
	hang := func(ctx context.Context, _ string) (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	}
	start := time.Now()
	collectIdentity(context.Background(), hang, hang)
	if elapsed := time.Since(start); elapsed > healthIdentityTimeout+2*time.Second {
		t.Fatalf("collectIdentity took %s, want it bounded by %s", elapsed, healthIdentityTimeout)
	}
}
