package engine

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/liberoute/bypath/internal/profile"
)

func TestEngineStartOrderMirrorsGatewayFallback(t *testing.T) {
	cases := []struct {
		name     string
		link     *profile.Link
		prefer   string
		order    []string
		fallback bool
		want     []string
	}{
		{
			name: "default order without fallback",
			link: &profile.Link{Protocol: "vless"},
			want: []string{"sing-box"},
		},
		{
			name:     "configured order with fallback",
			link:     &profile.Link{Protocol: "vless"},
			order:    []string{"sing-box", "xray"},
			fallback: true,
			want:     []string{"sing-box", "xray"},
		},
		{
			name:     "preferred engine moves first",
			link:     &profile.Link{Protocol: "vless"},
			prefer:   "xray",
			order:    []string{"sing-box", "xray"},
			fallback: true,
			want:     []string{"xray", "sing-box"},
		},
		{
			// sing-box cannot carry XHTTP parameters, so falling back to it
			// would silently test a different transport; XHTTP is xray-only.
			name:     "xhttp requires xray regardless of preference",
			link:     &profile.Link{Protocol: "vless", Network: "xhttp"},
			prefer:   "sing-box",
			order:    []string{"sing-box", "xray"},
			fallback: true,
			want:     []string{"xray"},
		},
		{
			name:     "vless encryption is xray only",
			link:     &profile.Link{Protocol: "vless", Encryption: "mlkem768x25519plus.native.0rtt"},
			prefer:   "sing-box",
			order:    []string{"sing-box", "xray"},
			fallback: true,
			want:     []string{"xray"},
		},
		{
			name:     "openvpn is sing-box only",
			link:     &profile.Link{Protocol: "openvpn"},
			order:    []string{"xray", "sing-box"},
			fallback: true,
			want:     []string{"sing-box"},
		},
	}
	for _, c := range cases {
		got := EngineStartOrder(c.link, c.prefer, c.order, c.fallback)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: EngineStartOrder = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestStartBenchmarkReportsMissingEngine(t *testing.T) {
	// The lite test build has no embedded runner; a nonexistent engine must name
	// both discovery paths instead of failing silently on an empty directory.
	_, err := StartBenchmark(context.Background(), "no-such-engine", "", t.TempDir(), 19999, 50*time.Millisecond)
	if err == nil {
		t.Fatal("StartBenchmark of an unavailable engine must fail")
	}
}

func TestFindBinaryPrefersPathOverEngineDir(t *testing.T) {
	// ssh is a system tool present on every supported test host.
	path, ok := FindBinary("ssh", t.TempDir())
	if !ok || path == "" {
		t.Fatal("ssh should resolve from PATH")
	}
	if _, ok := FindBinary("no-such-engine-binary", t.TempDir()); ok {
		t.Fatal("unknown binary must not resolve")
	}
}
