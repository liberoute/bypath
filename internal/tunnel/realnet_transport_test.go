//go:build realnet

package tunnel

// Loopback regression: generated VLESS WS and XHTTP client configs must carry
// real traffic through a real Xray server. No external server or certificate is
// needed because TLS terminates at the HTTPS origin, not at the VLESS hop.
//
// Run with:
//   BYPATH_XRAY=/path/to/xray go test -tags realnet ./internal/tunnel -run TestRealTransportLoopback -v

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/liberoute/bypath/internal/engine"
	"github.com/liberoute/bypath/internal/profile"
)

const loopbackUUID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

func startLoopbackXray(t *testing.T, xrayPath, cfgPath string, port int) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, xrayPath, "run", "-c", cfgPath)
	cmd.WaitDelay = 2 * time.Second
	var logs string
	logsBuf := &stringBuilder{}
	cmd.Stdout = logsBuf
	cmd.Stderr = logsBuf
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("starting xray: %v", err)
	}
	stopped := false
	stop = func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		_ = cmd.Wait()
	}
	t.Cleanup(stop)

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 300*time.Millisecond)
		if err == nil {
			conn.Close()
			return stop
		}
		time.Sleep(150 * time.Millisecond)
	}
	logs = redactDetail(tailString(logsBuf.String(), 500))
	stop()
	t.Fatalf("xray did not listen on :%d: %s", port, logs)
	return nil
}

type stringBuilder struct{ b []byte }

func (s *stringBuilder) Write(p []byte) (int, error) {
	s.b = append(s.b, p...)
	return len(p), nil
}
func (s *stringBuilder) String() string { return string(s.b) }

func writeXrayJSON(t *testing.T, cfg map[string]interface{}) string {
	t.Helper()
	path := t.TempDir() + "/config.json"
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal server config: %v", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write server config: %v", err)
	}
	return path
}

func loopbackServerConfig(port int, network, path string) map[string]interface{} {
	stream := map[string]interface{}{"network": network}
	switch network {
	case "ws":
		stream["wsSettings"] = map[string]interface{}{"path": path}
	case "xhttp":
		stream["xhttpSettings"] = map[string]interface{}{"path": path, "mode": "auto"}
	}
	return map[string]interface{}{
		"log": map[string]interface{}{"loglevel": "warning"},
		"inbounds": []map[string]interface{}{
			{
				"listen":   "127.0.0.1",
				"port":     port,
				"protocol": "vless",
				"settings": map[string]interface{}{
					"clients":    []map[string]interface{}{{"id": loopbackUUID}},
					"decryption": "none",
				},
				"streamSettings": stream,
			},
		},
		"outbounds": []map[string]interface{}{{"protocol": "freedom"}},
	}
}

func TestRealTransportLoopback(t *testing.T) {
	xrayPath := os.Getenv("BYPATH_XRAY")
	if xrayPath == "" {
		t.Skip("BYPATH_XRAY not set")
	}
	base, _ := strconv.Atoi(os.Getenv("BYPATH_REALNET_BASE_PORT"))
	if base <= 1024 {
		base = 24200
	}

	for i, tc := range []struct {
		network string
		path    string
		host    string
	}{
		{network: "ws", path: "/ws"},
		{network: "xhttp", path: "/x"},
	} {
		t.Run(tc.network, func(t *testing.T) {
			serverPort := base + i*2
			socksPort := base + i*2 + 1
			serverCfg := writeXrayJSON(t, loopbackServerConfig(serverPort, tc.network, tc.path))
			startLoopbackXray(t, xrayPath, serverCfg, serverPort)

			link := &profile.Link{
				Protocol:   "vless",
				Address:    "127.0.0.1",
				Port:       serverPort,
				UUID:       loopbackUUID,
				Network:    tc.network,
				Path:       tc.path,
				Host:       tc.host,
				ListenPort: socksPort,
			}
			cg := NewConfigGenerator(t.TempDir())
			clientCfg, err := cg.Generate(&engine.Engine{Name: "xray", Path: xrayPath}, link)
			if err != nil {
				t.Fatalf("client Generate: %v", err)
			}

			testCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			out, err := exec.CommandContext(testCtx, xrayPath, "run", "-test", "-c", clientCfg).CombinedOutput()
			cancel()
			if err != nil {
				t.Fatalf("xray rejected client config: %s", redactDetail(string(out)))
			}

			startLoopbackXray(t, xrayPath, clientCfg, socksPort)

			reqCtx, cancelReq := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancelReq()
			proxyAddr := fmt.Sprintf("127.0.0.1:%d", socksPort)
			_, status, latency, err := fetchViaProxy(reqCtx, proxyAddr, "https://www.gstatic.com/generate_204", 10*time.Second)
			if err != nil {
				t.Fatalf("%s client did not carry HTTPS through the loopback VLESS server: %v", tc.network, err)
			}
			if status != http.StatusNoContent && status != http.StatusOK {
				t.Fatalf("%s HTTPS status = %d", tc.network, status)
			}
			t.Logf("%s loopback ok: status=%d latency=%dms", tc.network, status, latency.Milliseconds())
		})
	}
}
