package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRemoteDecodesResultsAndTypedErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"code": "unauthorized", "message": "bad token"})
			return
		}
		switch r.URL.Path {
		case "/api/v1/app/status":
			json.NewEncoder(w).Encode(Status{State: "CONNECTED", ActiveLink: "node-a", APIPort: 8080})
		case "/api/v1/app/connection":
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"code": "not_found", "message": "gone", "hint": "check the id"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	r := &Remote{base: srv.URL, token: "tok", http: &http.Client{Timeout: 5 * time.Second}}
	ctx := context.Background()

	st, err := r.Status(ctx)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if st.State != "CONNECTED" || st.ActiveLink != "node-a" {
		t.Fatalf("unexpected status: %+v", st)
	}

	_, err = r.GetConnection(ctx, "missing")
	if CodeOf(err) != CodeNotFound {
		t.Fatalf("expected not_found, got %v", err)
	}
	var ae *Error
	if !errors.As(err, &ae) || ae.Hint != "check the id" {
		t.Fatalf("typed error lost its hint: %+v", err)
	}

	bad := &Remote{base: srv.URL, token: "wrong", http: &http.Client{Timeout: 5 * time.Second}}
	if _, err := bad.Status(ctx); CodeOf(err) != CodeUnauthorized {
		t.Fatalf("expected unauthorized, got %v", err)
	}
}

func TestRemoteUnreachableIsUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()

	r := &Remote{base: url, http: &http.Client{Timeout: time.Second}}
	if _, err := r.Status(context.Background()); CodeOf(err) != CodeUnavailable {
		t.Fatalf("expected unavailable, got %v", err)
	}
}

func TestLifecycleRequestsOutlastGatewayStartupBudget(t *testing.T) {
	// The gateway may spend its whole 5-minute total budget before the first
	// candidate answers. A shorter client deadline cancels the HTTP request,
	// and the daemon aborts the start it was still working on.
	if lifecycleTimeout <= 5*time.Minute {
		t.Fatalf("lifecycleTimeout = %s, does not cover the gateway startup budget", lifecycleTimeout)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/app/connect" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(ActionResult{Applied: true, Message: "ok"})
	}))
	defer srv.Close()

	r := &Remote{base: srv.URL, http: &http.Client{}}
	res, err := r.Connect(context.Background(), "default:node-a")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if !res.Applied {
		t.Fatalf("result = %+v", res)
	}
}

func TestRemoteCheckEgressUsesAppRoute(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		json.NewEncoder(w).Encode(EgressCheck{TunnelExit: "192.0.2.10", DirectIP: "198.51.100.7"})
	}))
	defer srv.Close()

	r := &Remote{base: srv.URL, http: &http.Client{Timeout: 5 * time.Second}}
	check, err := r.CheckEgress(context.Background())
	if err != nil {
		t.Fatalf("check egress: %v", err)
	}
	if gotPath != "/api/v1/app/routing/egress" {
		t.Fatalf("CheckEgress requested %q, want the app route", gotPath)
	}
	if check.TunnelExit != "192.0.2.10" || check.DirectIP != "198.51.100.7" {
		t.Fatalf("unexpected egress payload: %+v", check)
	}
}
