package profile

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

type socksMode int

const (
	socksConnect socksMode = iota
	socksRejectConnect
	socksStall
	socksNoAcceptableAuth
)

// startTestSocks serves a minimal SOCKS5 proxy so TLS negative cases run
// without any external network or privileged port.
func startTestSocks(t *testing.T, mode socksMode) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveTestSocks(conn, mode)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func serveTestSocks(conn net.Conn, mode socksMode) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		return
	}
	n := int(greeting[1])
	if _, err := io.CopyN(io.Discard, conn, int64(n)); err != nil {
		return
	}
	if mode == socksNoAcceptableAuth {
		conn.Write([]byte{0x05, 0xFF})
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return
	}
	var host string
	switch head[3] {
	case 0x01:
		var b [4]byte
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			return
		}
		host = net.IP(b[:]).String()
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return
		}
		name := make([]byte, l[0])
		if _, err := io.ReadFull(conn, name); err != nil {
			return
		}
		host = string(name)
	case 0x04:
		var b [16]byte
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			return
		}
		host = net.IP(b[:]).String()
	default:
		return
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(conn, portBuf[:]); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf[:])

	if mode == socksRejectConnect {
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	if mode == socksStall {
		time.Sleep(20 * time.Second)
		return
	}

	upstream, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))), 3*time.Second)
	if err != nil {
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer upstream.Close()
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0}); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	go func() { io.Copy(upstream, conn); done <- struct{}{} }()
	go func() { io.Copy(conn, upstream); done <- struct{}{} }()
	<-done
}

func tlsServerPool(t *testing.T, srv *httptest.Server) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return pool
}

func TestTestHTTPSAcceptsTrustedTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	port := startTestSocks(t, socksConnect)
	target := "https://" + srv.Listener.Addr().String() + "/"
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if !testHTTPS(ctx, port, target, &tls.Config{RootCAs: tlsServerPool(t, srv)}) {
		t.Fatal("trusted TLS round trip through SOCKS5 failed")
	}
}

func TestTestHTTPSRejectsUntrustedCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	port := startTestSocks(t, socksConnect)
	target := "https://" + srv.Listener.Addr().String() + "/"
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if testHTTPS(ctx, port, target, nil) {
		t.Fatal("self-signed certificate was accepted; TLS verification is not enforced")
	}
}

func TestTestHTTPSRejectsRejectedConnect(t *testing.T) {
	port := startTestSocks(t, socksRejectConnect)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if testHTTPS(ctx, port, "https://cp.cloudflare.com", nil) {
		t.Fatal("health check passed although SOCKS5 CONNECT was rejected")
	}
}

func TestTestHTTPSRejectsNoAcceptableAuth(t *testing.T) {
	port := startTestSocks(t, socksNoAcceptableAuth)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if testHTTPS(ctx, port, "https://cp.cloudflare.com", nil) {
		t.Fatal("health check passed although the proxy accepted no auth method")
	}
}

func TestTestHTTPSTimesOutOnStalledProxy(t *testing.T) {
	port := startTestSocks(t, socksStall)
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	start := time.Now()
	if testHTTPS(ctx, port, "https://cp.cloudflare.com", nil) {
		t.Fatal("health check passed against a stalled proxy")
	}
	if elapsed := time.Since(start); elapsed > 6*time.Second {
		t.Fatalf("stalled proxy took %v; timeout was not enforced", elapsed)
	}
}

// TestDialSOCKS5ProtocolErrors exercises the wire protocol directly so a
// malformed proxy reply can never be mistaken for a working tunnel.
func TestDialSOCKS5ProtocolErrors(t *testing.T) {
	cases := []struct {
		name      string
		greeting  []byte
		afterAuth []byte
		want      string
	}{
		{"auth method rejected", []byte{0x05, 0xFF}, nil, "auth method"},
		{"connect rejected", []byte{0x05, 0x00}, append([]byte{0x05, 0x05, 0x00, 0x01}, make([]byte, 6)...), "CONNECT failed"},
		{"unknown address type", []byte{0x05, 0x00}, append([]byte{0x05, 0x00, 0x00, 0x09}, make([]byte, 6)...), "address type"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				buf := make([]byte, 512)
				conn.Read(buf)
				conn.Write(tc.greeting)
				if tc.afterAuth == nil {
					return
				}
				conn.Read(buf)
				conn.Write(tc.afterAuth)
			}()

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, err = dialSOCKS5(ctx, ln.Addr().String(), "example.com", 443, 2*time.Second)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("dialSOCKS5 error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestDialSOCKS5RejectsTruncatedReply(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := dialSOCKS5(ctx, ln.Addr().String(), "example.com", 443, 1*time.Second); err == nil {
		t.Fatal("dialSOCKS5 accepted a truncated handshake")
	}
}

func TestDialSOCKS5RejectsLongHostname(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 64)
		conn.Read(buf)
		conn.Write([]byte{0x05, 0x00})
		io.Copy(io.Discard, conn)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = dialSOCKS5(ctx, ln.Addr().String(), strings.Repeat("a", 300), 443, time.Second)
	if err == nil || !strings.Contains(err.Error(), "hostname too long") {
		t.Fatalf("dialSOCKS5 error = %v, want hostname too long", err)
	}
}

func TestTestHTTPSRejectsPlainTextEndpoint(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "not tls")
	}))
	defer plain.Close()

	port := startTestSocks(t, socksConnect)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	target := "https://" + plain.Listener.Addr().String() + "/"
	if testHTTPS(ctx, port, target, nil) {
		t.Fatal("health check passed against a plaintext HTTP endpoint")
	}
}

func TestTestAnyURLSucceedsWhenOneEndpointWorks(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	port := startTestSocks(t, socksConnect)
	targets := []string{
		"https://127.0.0.1:1/", // unreachable, must not veto the healthy endpoint
		"https://" + srv.Listener.Addr().String() + "/",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if !testAnyURL(ctx, port, targets, &tls.Config{RootCAs: tlsServerPool(t, srv)}) {
		t.Fatal("one reachable endpoint did not make the multi-signal probe succeed")
	}
}

func TestTestAnyURLFailsWhenAllEndpointsFail(t *testing.T) {
	port := startTestSocks(t, socksRejectConnect)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if testAnyURL(ctx, port, []string{"https://cp.cloudflare.com", "https://www.gstatic.com/generate_204"}, nil) {
		t.Fatal("health check passed although every endpoint was rejected")
	}
}

func TestTestAnyURLRequiresTargets(t *testing.T) {
	if testAnyURL(context.Background(), 1, nil, nil) {
		t.Fatal("an empty target list must not report a healthy tunnel")
	}
	if testAnyURL(context.Background(), 1, []string{"", ""}, nil) {
		t.Fatal("blank targets must not report a healthy tunnel")
	}
}
