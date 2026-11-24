package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/liberoute/bypath/internal/app"
)

func postJSON(t *testing.T, url, body string) *http.Response {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func getJSON(t *testing.T, url string, dst interface{}) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d", url, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		t.Fatal(err)
	}
}

func TestAppAPILayerMigrationAndDeleteGuard(t *testing.T) {
	srv, _ := newTestServer(t, "")
	defer srv.Close()

	resp := postJSON(t, srv.URL+"/api/v1/app/connections/import",
		`{"group":"default","uri":"`+apiTestVLESS+`"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("import: status %d", resp.StatusCode)
	}

	resp = postJSON(t, srv.URL+"/api/v1/app/layer/migrate", `{"dry_run":false}`)
	var plan struct {
		AlreadyMigrated bool `json:"already_migrated"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&plan); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !plan.AlreadyMigrated {
		t.Fatalf("migrate: status %d plan %+v", resp.StatusCode, plan)
	}

	var status struct {
		Migrated bool `json:"migrated"`
	}
	getJSON(t, srv.URL+"/api/v1/app/layer/status", &status)
	if !status.Migrated {
		t.Fatal("layer status does not report the migration")
	}

	var groups struct {
		Groups []struct {
			ID    string `json:"id"`
			Name  string `json:"name"`
			Count int    `json:"count"`
		} `json:"groups"`
	}
	getJSON(t, srv.URL+"/api/v1/app/layer/groups", &groups)
	found := false
	for _, g := range groups.Groups {
		if g.Name == "default" && g.Count == 1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("bucket group missing: %+v", groups.Groups)
	}

	var conns struct {
		Connections []app.Connection `json:"connections"`
	}
	getJSON(t, srv.URL+"/api/v1/app/connections", &conns)
	if len(conns.Connections) != 1 || conns.Connections[0].StableID == "" {
		t.Fatalf("connection lacks stable id: %+v", conns.Connections)
	}

	// Select it, then verify the API refuses a bare delete.
	resp = postJSON(t, srv.URL+"/api/v1/app/connections/active", `{"id":"default:api-node"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("select: status %d", resp.StatusCode)
	}
	resp = postJSON(t, srv.URL+"/api/v1/app/connections/delete", `{"id":"default:api-node"}`)
	body := map[string]string{}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict || body["code"] != app.CodeConflict {
		t.Fatalf("delete was not guarded: status %d body %+v", resp.StatusCode, body)
	}

	var impact app.DeleteImpact
	getJSON(t, srv.URL+"/api/v1/app/connections/delete-plan?id=default%3Aapi-node", &impact)
	if !impact.Selected || impact.Allowed {
		t.Fatalf("delete plan did not guard the selection: %+v", impact)
	}

	resp = postJSON(t, srv.URL+"/api/v1/app/connections/delete",
		`{"id":"default:api-node","options":{"acknowledge_unset":true}}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("acknowledged delete: status %d", resp.StatusCode)
	}
}
