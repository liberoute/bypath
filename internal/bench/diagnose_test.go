package bench

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/liberoute/bypath/internal/profile"
)

func categoryOf(err error) string {
	var attempt *AttemptError
	if errors.As(err, &attempt) {
		return attempt.Category
	}
	return ""
}

func TestDiagnoseEndpointClosedPortIsUnreachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	link := &profile.Link{Protocol: "vless", Address: "127.0.0.1", Port: port, Security: "none"}
	err = DiagnoseEndpoint(context.Background(), link, Options{})
	if got := categoryOf(err); got != "unreachable_server" {
		t.Fatalf("category = %q (%v), want unreachable_server", got, err)
	}
}

func TestDiagnoseEndpointUntrustedCertificateIsHandshakeFailure(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	host, port := hostPort(t, srv.Listener.Addr().String())

	link := &profile.Link{Protocol: "vless", Address: host, Port: port, Security: "tls", SNI: "127.0.0.1"}
	err := DiagnoseEndpoint(context.Background(), link, Options{})
	if got := categoryOf(err); got != "handshake_failure" {
		t.Fatalf("category = %q (%v), want handshake_failure", got, err)
	}
}

func TestDiagnoseEndpointHealthyTLSHasNoVerdict(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	host, port := hostPort(t, srv.Listener.Addr().String())

	link := &profile.Link{Protocol: "vless", Address: host, Port: port, Security: "tls", SNI: "127.0.0.1", Insecure: true}
	if err := DiagnoseEndpoint(context.Background(), link, Options{}); err != nil {
		t.Fatalf("healthy TLS endpoint was diagnosed as broken: %v", err)
	}
}

func TestDiagnoseEndpointRequiredALPNMismatch(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = &tls.Config{NextProtos: []string{"http/1.1"}}
	srv.StartTLS()
	defer srv.Close()
	host, port := hostPort(t, srv.Listener.Addr().String())

	link := &profile.Link{Protocol: "vless", Address: host, Port: port, Security: "tls", SNI: "127.0.0.1",
		Insecure: true, ALPN: []string{"h2"}}
	err := DiagnoseEndpoint(context.Background(), link, Options{})
	if got := categoryOf(err); got != "handshake_failure" {
		t.Fatalf("category = %q (%v), want handshake_failure", got, err)
	}
}

func TestDiagnoseEndpointReachablePlainTCPHasNoVerdict(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	host, port := hostPort(t, ln.Addr().String())

	link := &profile.Link{Protocol: "vless", Address: host, Port: port, Security: "none"}
	if err := DiagnoseEndpoint(context.Background(), link, Options{}); err != nil {
		t.Fatalf("reachable plain endpoint was diagnosed as broken: %v", err)
	}
}

func TestDiagnoseEndpointSkipsUnbenchableLinks(t *testing.T) {
	if err := DiagnoseEndpoint(context.Background(), &profile.Link{Address: "", Port: 443}, Options{}); err != nil {
		t.Fatalf("unbenchable link got a verdict: %v", err)
	}
}

func hostPort(t *testing.T, address string) (string, int) {
	t.Helper()
	host, raw, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(raw)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}
