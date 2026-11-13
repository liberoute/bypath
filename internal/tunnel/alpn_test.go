package tunnel

import (
	"reflect"
	"testing"

	"github.com/liberoute/bypath/internal/profile"
)

// A WebSocket upgrade is HTTP/1.1. Offering h2 (the value YO subscriptions
// publish in their links) makes the server negotiate HTTP/2, the upgrade is
// rejected, and every tunnelled request fails with EOF even though the
// endpoint resolves and its certificate verifies. This was reproduced live
// against NL-03: alpn=h2 → EOF, alpn=http/1.1 → HTTP 204.
func TestALPNForTransportRestrictsWebsocketToHTTP11(t *testing.T) {
	cases := []struct {
		name    string
		network string
		alpn    []string
		want    []string
	}{
		{"link advertises h2", "ws", []string{"h2"}, []string{"http/1.1"}},
		{"link advertises both", "ws", []string{"h2", "http/1.1"}, []string{"http/1.1"}},
		{"link already http/1.1", "ws", []string{"http/1.1"}, []string{"http/1.1"}},
		{"link has no alpn", "ws", nil, []string{"http/1.1"}},
		{"grpc keeps h2", "grpc", []string{"h2"}, []string{"h2"}},
		{"http2 transport keeps h2", "h2", []string{"h2"}, []string{"h2"}},
		{"plain tcp unchanged", "", []string{"h2"}, []string{"h2"}},
		{"empty plain tcp stays empty", "", nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := alpnForTransport(tc.network, tc.alpn)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("alpnForTransport(%q, %v) = %v, want %v", tc.network, tc.alpn, got, tc.want)
			}
		})
	}
}

func TestALPNForTransportDoesNotAliasInput(t *testing.T) {
	in := []string{"h2"}
	_ = alpnForTransport("ws", in)
	if !reflect.DeepEqual(in, []string{"h2"}) {
		t.Fatalf("input slice was mutated: %v", in)
	}
}

func TestVLESSWebsocketOutboundNeverOffersH2(t *testing.T) {
	link := &profile.Link{
		Protocol: "vless",
		Address:  "edge.example.test",
		Port:     444,
		UUID:     "00000000-0000-4000-8000-000000000000",
		Network:  "ws",
		TLS:      true,
		SNI:      "edge.example.test",
		Host:     "edge.example.test",
		Path:     "/download",
		ALPN:     []string{"h2"},
	}
	cg := &ConfigGenerator{}
	out := cg.BuildSingboxOutbound(link)
	tls, ok := out["tls"].(map[string]interface{})
	if !ok {
		t.Fatal("outbound has no tls object")
	}
	got, ok := tls["alpn"].([]string)
	if !ok {
		t.Fatalf("outbound tls.alpn missing or wrong type: %#v", tls["alpn"])
	}
	if want := []string{"http/1.1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("outbound tls.alpn = %v, want %v", got, want)
	}
}

func TestVLESSGRPCOutboundKeepsH2ALPN(t *testing.T) {
	link := &profile.Link{
		Protocol: "vless",
		Address:  "edge.example.test",
		Port:     443,
		UUID:     "00000000-0000-4000-8000-000000000000",
		Network:  "grpc",
		TLS:      true,
		SNI:      "edge.example.test",
		ALPN:     []string{"h2"},
	}
	cg := &ConfigGenerator{}
	out := cg.BuildSingboxOutbound(link)
	tls, ok := out["tls"].(map[string]interface{})
	if !ok {
		t.Fatal("outbound has no tls object")
	}
	if got := tls["alpn"]; !reflect.DeepEqual(got, []string{"h2"}) {
		t.Fatalf("outbound tls.alpn = %v, want [h2]", got)
	}
}
