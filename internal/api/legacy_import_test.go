package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/liberoute/bypath/internal/app"
)

// TestLegacyAddLinkRejectsSSHKeyPaths is the F-02 regression: the legacy
// POST /api/v1/profiles/links route must apply the same key-path refusal as the
// application API, on both the token-protected TCP router and the control
// socket, before the root daemon touches any named file.
func TestLegacyAddLinkRejectsSSHKeyPaths(t *testing.T) {
	cases := []struct {
		name      string
		uri       string
		control   bool
		wantCode  int
		wantError string
	}{
		{
			name:      "root key over TCP",
			uri:       "ssh://root@example.com:22?key=/root/.ssh/id_rsa#root-key",
			wantCode:  http.StatusBadRequest,
			wantError: "SSH key file paths are not accepted",
		},
		{
			name:      "unreadable root key over TCP",
			uri:       "ssh://deploy@example.com:22?key=/root/.ssh/id_ed25519#root-ed25519",
			wantCode:  http.StatusBadRequest,
			wantError: "SSH key file paths are not accepted",
		},
		{
			name:      "traversal key over the control socket",
			uri:       "ssh://root@example.com:22?key=../../etc/shadow#traversal-key",
			control:   true,
			wantCode:  http.StatusBadRequest,
			wantError: "SSH key file paths are not accepted",
		},
		{
			name:     "password link still accepted",
			uri:      "ssh://root@example.com:22#password-link",
			wantCode: http.StatusCreated,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, svc, server := newTestServerWith(t, "tok", nil)
			defer srv.Close()

			base := srv.URL
			if tc.control {
				local := httptest.NewServer(server.localRouter)
				defer local.Close()
				base = local.URL
			}

			body, err := json.Marshal(map[string]string{"group": "legacy", "uri": tc.uri})
			if err != nil {
				t.Fatal(err)
			}
			req, err := http.NewRequest(http.MethodPost, base+"/api/v1/profiles/links", strings.NewReader(string(body)))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			if !tc.control {
				req.Header.Set("Authorization", "Bearer tok")
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			var payload map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
				t.Fatalf("decoding response: %v", err)
			}
			if resp.StatusCode != tc.wantCode {
				t.Fatalf("status=%d, want %d (body %v)", resp.StatusCode, tc.wantCode, payload)
			}

			conns, err := svc.ListConnections(context.Background(), app.ConnectionFilter{})
			if err != nil {
				t.Fatalf("listing connections: %v", err)
			}
			if tc.wantCode == http.StatusBadRequest {
				msg := fmt.Sprint(payload["message"])
				if !strings.Contains(msg, tc.wantError) {
					t.Fatalf("unexpected error message: %q", msg)
				}
				if len(conns) != 0 {
					t.Fatalf("the rejected link was stored: %+v", conns)
				}
				return
			}
			if len(conns) != 1 {
				t.Fatalf("the accepted link was not stored: %+v", conns)
			}
		})
	}
}
