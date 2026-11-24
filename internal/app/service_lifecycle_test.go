package app

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"testing"

	"github.com/liberoute/bypath/internal/config"
)

func TestLocalServiceOperationsTypedUnsupported(t *testing.T) {
	svc, _ := newTestLocal(t)
	if _, err := svc.RestartService(context.Background(), true); CodeOf(err) != CodeUnsupported {
		t.Fatalf("%v", err)
	}
	st, err := svc.Settings(context.Background())
	if err != nil || st.ServiceRestartSupported || st.ServiceRestartReason == "" {
		t.Fatalf("%+v %v", st, err)
	}
	if len(st.EffectiveProxyEndpoints) != 1 || st.WebListen != svc.Config().Server.Web.Listen {
		t.Fatalf("%+v", st)
	}
}
func TestProxyInvalidRequestsNeverChangeSavedConfig(t *testing.T) {
	svc, _ := newTestLocal(t)
	old, _ := os.ReadFile(svc.configPath)
	for _, req := range []ProxyApply{{SOCKSPort: 0, SOCKSListen: "127.0.0.1"}, {SOCKSPort: 22, SOCKSListen: "127.0.0.1"}, {SOCKSPort: 8443, SOCKSListen: "127.0.0.1"}, {SOCKSPort: 1080, SOCKSListen: "0.0.0.0"}, {SOCKSPort: 1080, SOCKSListen: "8.8.8.8", ConfirmLAN: true}} {
		if _, err := svc.ApplyProxy(context.Background(), req); err == nil {
			t.Fatal("invalid proxy request accepted", req)
		}
		now, _ := os.ReadFile(svc.configPath)
		if string(now) != string(old) {
			t.Fatal("invalid request modified disk")
		}
	}
}
func TestListenerConflictBeforeStaging(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	if err := checkProxyListeners(config.ServerConfig{SOCKSPort: 2801}, config.ServerConfig{SOCKSPort: port, SOCKSListen: "127.0.0.1"}); err == nil {
		t.Fatal("occupied TCP listener accepted")
	}
}
func TestRestoreCannotPatchSOCKSPort(t *testing.T) {
	svc, _ := newTestLocal(t)
	old := svc.Config().Server.SOCKSPort
	b := Backup{Version: 1, Config: []byte("server:\n  socks_port: 2909\n")}
	raw, _ := json.Marshal(b)
	if err := svc.Restore(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	if svc.Config().Server.SOCKSPort != old {
		t.Fatal("restore bypassed staged proxy apply")
	}
}
func TestReconnectRecoveryPreservesActiveFileAndReportsServing(t *testing.T) {
	svc, _ := newTestLocal(t)
	ctx := context.Background()
	if _, err := svc.ImportURI(ctx, "default", testVLESS); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetActive(ctx, "default:node-a"); err != nil {
		t.Fatal(err)
	}
	saved, _ := os.ReadFile(svc.Config().Profiles.Directory + "/.active")
	rt := &stubRuntime{status: RuntimeStatus{State: "CONNECTED", ActiveGroup: "default", ActiveLink: "node-a"}, applyErr: context.Canceled}
	svc.runtime = rt
	if _, err := svc.Restart(ctx); err == nil {
		t.Fatal("failed reconnect reported success")
	}
	now, _ := os.ReadFile(svc.Config().Profiles.Directory + "/.active")
	if string(now) != string(saved) || rt.applyCalls != 2 || rt.requestStopCalls != 0 {
		t.Fatal("reconnect recovery did not preserve selection/service")
	}
}
