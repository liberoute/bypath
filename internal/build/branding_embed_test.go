//go:build full && embed_tun2socks && linux && (amd64 || arm64 || (arm && arm.7))

package build

import (
	"runtime"
	"strings"
	"testing"

	"github.com/liberoute/bypath/internal/embedbin"
)

func TestEmbeddedVariantIsReported(t *testing.T) {
	if !EmbeddedTun2socks {
		t.Fatal("EmbeddedTun2socks is false in a full+embed build")
	}
	info, ok := embedbin.EmbeddedTun2socksInfo()
	if !ok {
		t.Fatal("no embedded tun2socks asset")
	}
	if info.GOARCH != runtime.GOARCH {
		t.Fatalf("embedded payload is %s, process is %s", info.GOARCH, runtime.GOARCH)
	}

	out := PrintVersionInfo("", false)
	for _, want := range []string{
		"Variant:    full (embedded tun2socks)",
		"Embedded:   tun2socks " + info.Version,
		"embedded " + info.Version + " (linux/" + runtime.GOARCH,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("version report missing %q:\n%s", want, out)
		}
	}
}
