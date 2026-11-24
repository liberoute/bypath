package api

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/liberoute/bypath/internal/app"
	"github.com/liberoute/bypath/internal/profile"
)

func seedOrganizeSource(t *testing.T, svc *app.Local) {
	t.Helper()
	mgr := svc.Profiles()
	if err := mgr.CreateGroup("default", "subscription"); err != nil {
		t.Fatal(err)
	}
	if err := mgr.AddSubscription("default", "https://panel.example/sub"); err != nil {
		t.Fatal(err)
	}
	l, err := profile.ParseURI(apiTestVLESS)
	if err != nil {
		t.Fatal(err)
	}
	l.SourceID = profile.SourceIDFor("https://panel.example/sub")
	if err := mgr.AddLink("default", l); err != nil {
		t.Fatal(err)
	}
	mgr.SetActiveLink(l)
}

func TestSubscriptionOrganizeRemoteRoutePreservesLegacyBytes(t *testing.T) {
	srv, svc := newTestServer(t, "tok")
	defer srv.Close()
	seedOrganizeSource(t, svc)
	dir := svc.Profiles().Directory()
	bucket, _ := os.ReadFile(filepath.Join(dir, "default.json"))
	active, _ := os.ReadFile(filepath.Join(dir, ".active"))
	address := srv.Listener.Addr().String()
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := strconv.Atoi(port)
	remote := app.NewRemote(host, p, "tok")
	sub, err := remote.OrganizeSubscription(context.Background(), "default", "https://panel.example/sub", "")
	if err != nil {
		t.Fatal(err)
	}
	if sub.LayerGroupID == "" || sub.LayerGroup != "panel" || sub.LinkCount != 1 {
		t.Fatalf("organize response: %+v", sub)
	}
	for path, want := range map[string][]byte{"default.json": bucket, ".active": active} {
		got, err := os.ReadFile(filepath.Join(dir, path))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("organize changed %s", path)
		}
	}
	if _, err := remote.OrganizeSubscription(context.Background(), "default", "https://other.example/sub", ""); app.CodeOf(err) != app.CodeNotFound {
		t.Fatalf("unknown source: %v", err)
	}
	if _, err := remote.OrganizeSubscription(context.Background(), "default", "https://panel.example/sub", "../invalid"); app.CodeOf(err) != app.CodeInvalid {
		t.Fatalf("invalid name: %v", err)
	}
}

func TestSubscriptionOrganizeWebRouteRequiresCSRF(t *testing.T) {
	srv, web := newWebTest(t)
	seedOrganizeSource(t, web.svc)
	client := newWebClient(t)
	csrf, _ := webSetup(t, client, srv.URL)
	body := map[string]string{"group": "default", "url": "https://panel.example/sub"}
	path := srv.URL + "/api/v1/app/subscriptions/organize"
	status, _, _ := webDo(t, client, http.MethodPost, path, body, nil, nil)
	if status != http.StatusForbidden {
		t.Fatalf("organize without CSRF: %d", status)
	}
	status, result, _ := webDo(t, client, http.MethodPost, path, body, map[string]string{"X-CSRF-Token": csrf}, nil)
	if status != http.StatusOK || result["layer_group"] != "panel" {
		t.Fatalf("organize with CSRF: %d %v", status, result)
	}
}
