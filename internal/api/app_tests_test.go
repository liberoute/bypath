package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/liberoute/bypath/internal/app"
)

func TestTestEndpointsValidateInput(t *testing.T) {
	srv, _ := newTestServer(t, "")
	defer srv.Close()

	cases := []struct {
		name   string
		method string
		path   string
		body   string
		status int
	}{
		{"unknown kind", http.MethodPost, "/api/v1/app/tests/jobs", `{"kind":"traceroute"}`, http.StatusBadRequest},
		{"link scope without id", http.MethodPost, "/api/v1/app/tests/jobs", `{"scope":{"kind":"link"}}`, http.StatusBadRequest},
		{"unknown group", http.MethodPost, "/api/v1/app/tests/jobs", `{"scope":{"kind":"group","group":"nope"}}`, http.StatusNotFound},
		{"missing job", http.MethodGet, "/api/v1/app/tests/jobs/job-missing", "", http.StatusNotFound},
		{"cancel missing job", http.MethodPost, "/api/v1/app/tests/jobs/job-missing/cancel", "", http.StatusNotFound},
		{"results without connection", http.MethodGet, "/api/v1/app/tests/results", "", http.StatusBadRequest},
		{"upload is disabled", http.MethodPost, "/api/v1/app/tests/jobs", `{"kind":"speed","upload":true}`, http.StatusBadRequest},
		{"bad target", http.MethodPost, "/api/v1/app/tests/targets", `{"url":"http://127.0.0.1/x"}`, http.StatusBadRequest},
		{"missing target", http.MethodDelete, "/api/v1/app/tests/targets/t_missing", "", http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var body *strings.Reader
			if tc.body == "" {
				body = strings.NewReader("")
			} else {
				body = strings.NewReader(tc.body)
			}
			req, err := http.NewRequest(tc.method, srv.URL+tc.path, body)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.status {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.status)
			}
			var payload map[string]string
			if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
				t.Fatalf("error body: %v", err)
			}
			if payload["code"] == "" || payload["message"] == "" {
				t.Fatalf("unexpected error body: %+v", payload)
			}
		})
	}
}

func TestTestResultsEmptyIsArray(t *testing.T) {
	srv, svc := newTestServer(t, "")
	defer srv.Close()
	if _, err := svc.ImportURI(t.Context(), "default", apiTestVLESS); err != nil {
		t.Fatal(err)
	}

	resp, err := http.Get(srv.URL + "/api/v1/app/tests/results?connection=default:api-node")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var results []app.TestResult
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if results == nil || len(results) != 0 {
		t.Fatalf("expected an empty array, got %#v", results)
	}
}

func TestSpeedTargetRegistryAPI(t *testing.T) {
	srv, _ := newTestServer(t, "")
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/v1/app/tests/targets")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var targets []app.SpeedTarget
	if err := json.NewDecoder(resp.Body).Decode(&targets); err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || !targets[0].BuiltIn || targets[0].Host != "dl.google.com" {
		t.Fatalf("unexpected default registry: %+v", targets)
	}

	add := func(url string) *http.Response {
		body, _ := json.Marshal(map[string]string{"url": url})
		resp, err := http.Post(srv.URL+"/api/v1/app/tests/targets", "application/json", strings.NewReader(string(body)))
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	r := add("https://speed.example.net/payload.bin")
	if r.StatusCode != http.StatusCreated {
		t.Fatalf("add status = %d", r.StatusCode)
	}
	var created app.SpeedTarget
	json.NewDecoder(r.Body).Decode(&created)
	r.Body.Close()
	if created.ID == "" || created.Host != "speed.example.net" {
		t.Fatalf("unexpected created target: %+v", created)
	}
	if dup := add("https://speed.example.net/payload.bin"); dup.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate status = %d", dup.StatusCode)
	}
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/v1/app/tests/targets/"+created.ID, nil)
	del, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	del.Body.Close()
	if del.StatusCode != http.StatusOK {
		t.Fatalf("delete status = %d", del.StatusCode)
	}
}

func TestBudgetAndUsageEndpoints(t *testing.T) {
	srv, svc := newTestServer(t, "")
	defer srv.Close()
	if _, err := svc.ImportURI(t.Context(), "default", apiTestVLESS); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(srv.URL+"/api/v1/app/tests/budget", "application/json",
		strings.NewReader(`{"kind":"speed","scope":{"kind":"all"}}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("budget status = %d", resp.StatusCode)
	}
	var budget app.TestBudget
	if err := json.NewDecoder(resp.Body).Decode(&budget); err != nil {
		t.Fatal(err)
	}
	if budget.PerLinkMB != 10 || budget.PerBatchMB != 40 || budget.WorstCaseMB != 10 || budget.Target != "dl.google.com" {
		t.Fatalf("unexpected budget: %+v", budget)
	}
	if budget.UploadEnabled {
		t.Fatal("upload must be disabled")
	}

	uResp, err := http.Get(srv.URL + "/api/v1/app/tests/usage")
	if err != nil {
		t.Fatal(err)
	}
	defer uResp.Body.Close()
	var usage app.SpeedUsage
	if err := json.NewDecoder(uResp.Body).Decode(&usage); err != nil {
		t.Fatal(err)
	}
	if usage.Label == "" || usage.Bytes != 0 {
		t.Fatalf("unexpected usage: %+v", usage)
	}
}
