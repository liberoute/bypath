package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const subBody = testVLESS + "\n" +
	"vless://22222222-2222-2222-2222-222222222222@example.org:8443?security=tls&type=grpc#node-b\n"

func TestSubscriptionRefreshIsTransactional(t *testing.T) {
	svc, _ := newSubscriptionTestLocal(t)
	ctx := context.Background()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(subBody))
	}))
	defer srv.Close()

	sub, err := svc.AddSubscription(ctx, "panel", srv.URL+"/sub?token=abc")
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if !strings.Contains(sub.RedactedURL, "/…") || strings.Contains(sub.RedactedURL, "token=abc") {
		t.Fatalf("URL not redacted: %s", sub.RedactedURL)
	}

	refreshed, err := svc.RefreshSubscription(ctx, "panel", sub.URL, nil)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if refreshed.LinkCount != 2 {
		t.Fatalf("expected 2 links, got %d", refreshed.LinkCount)
	}
	list, _ := svc.ListConnections(ctx, ConnectionFilter{Group: "panel"})
	if len(list) != 2 {
		t.Fatalf("expected 2 stored links, got %+v", list)
	}
	for _, c := range list {
		if c.FromSubscription == "" {
			t.Fatalf("connection has no subscription provenance: %+v", c)
		}
	}

	// A failed refresh must keep the working links and record the error.
	srv.Close()
	if _, err := svc.RefreshSubscription(ctx, "panel", sub.URL, nil); CodeOf(err) != CodeUnavailable {
		t.Fatalf("expected unavailable error, got %v", err)
	}
	after, _ := svc.ListConnections(ctx, ConnectionFilter{Group: "panel"})
	if len(after) != 2 {
		t.Fatalf("failed refresh dropped links: %+v", after)
	}
	subs, _ := svc.ListSubscriptions(ctx)
	if len(subs) != 1 || subs[0].LastError == "" || subs[0].LastRefresh == "" {
		t.Fatalf("failure not recorded: %+v", subs)
	}
	if subs[0].LinkCount != 2 {
		t.Fatalf("stored link count = %d, want 2 (metadata must not double-count)", subs[0].LinkCount)
	}
}

func TestSubscriptionRefreshKeepsIdentityAcrossRefreshes(t *testing.T) {
	svc, _ := newSubscriptionTestLocal(t)
	ctx := context.Background()

	body := subBody
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Write([]byte(body))
	}))
	defer srv.Close()

	sub, err := svc.AddSubscription(ctx, "panel", srv.URL+"/sub?token=abc")
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if _, err := svc.RefreshSubscription(ctx, "panel", sub.URL, nil); err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	// An unchanged refresh must be a no-op, not a second copy of every link.
	refreshed, err := svc.RefreshSubscription(ctx, "panel", sub.URL, nil)
	if err != nil {
		t.Fatalf("second refresh: %v", err)
	}
	if refreshed.LinkCount != 2 {
		t.Fatalf("unchanged refresh stored %d links, want 2", refreshed.LinkCount)
	}
	list, _ := svc.ListConnections(ctx, ConnectionFilter{Group: "panel"})
	if len(list) != 2 {
		t.Fatalf("unchanged refresh duplicated links: %+v", list)
	}

	// Dropping a link from the provider keeps the stored one (so .active can
	// never be invalidated) but must not create a new entry for the survivor.
	mu.Lock()
	body = testVLESS + "\n"
	mu.Unlock()
	refreshed, err = svc.RefreshSubscription(ctx, "panel", sub.URL, nil)
	if err != nil {
		t.Fatalf("third refresh: %v", err)
	}
	if refreshed.LinkCount != 2 {
		t.Fatalf("refresh after removal stored %d links, want 2 (one kept orphaned)", refreshed.LinkCount)
	}
	after, _ := svc.ListConnections(ctx, ConnectionFilter{Group: "panel"})
	if len(after) != 2 {
		t.Fatalf("refresh after removal changed the link set: %+v", after)
	}
	for _, c := range after {
		if strings.Contains(c.Remark, "(2)") {
			t.Fatalf("refresh minted a duplicate remark: %+v", c)
		}
	}
}

func TestSubscriptionPreviewStoresNothing(t *testing.T) {
	svc, _ := newSubscriptionTestLocal(t)
	ctx := context.Background()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(subBody))
	}))
	defer srv.Close()

	raw := srv.URL + "/sub?token=abc"
	preview, err := svc.PreviewSubscription(ctx, raw)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if preview.Total != 2 || len(preview.Links) != 2 {
		t.Fatalf("preview = %+v", preview)
	}
	if strings.Contains(preview.RedactedURL, "token=abc") {
		t.Fatalf("preview leaks the subscription token: %s", preview.RedactedURL)
	}
	if preview.Links[0].Remark == "" || preview.Links[0].Protocol == "" || preview.Links[0].Address == "" {
		t.Fatalf("preview entry is incomplete: %+v", preview.Links[0])
	}
	if subs, _ := svc.ListSubscriptions(ctx); len(subs) != 0 {
		t.Fatalf("preview persisted a subscription: %+v", subs)
	}
	if list, _ := svc.ListConnections(ctx, ConnectionFilter{}); len(list) != 0 {
		t.Fatalf("preview persisted links: %+v", list)
	}

	// The same payload imported twice is previewed with its duplicate count.
	if _, err := svc.ImportSubscriptionText(ctx, "bulk", subBody); err != nil {
		t.Fatal(err)
	}
	textPreview, err := svc.PreviewSubscriptionText(ctx, subBody)
	if err != nil {
		t.Fatalf("text preview: %v", err)
	}
	if textPreview.Total != 2 || textPreview.Duplicates != 2 || len(textPreview.Links) != 0 {
		t.Fatalf("duplicate preview = %+v", textPreview)
	}
}

func TestPreviewFailureRedactsURL(t *testing.T) {
	svc, _ := newSubscriptionTestLocal(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	_, err := svc.PreviewSubscription(context.Background(), srv.URL+"/sub?token=abc")
	if CodeOf(err) != CodeUnavailable {
		t.Fatalf("expected unavailable, got %v", err)
	}
	if strings.Contains(err.Error(), "token=abc") {
		t.Fatalf("error leaks the subscription token: %v", err)
	}
}

func TestAddSubscriptionRejectsNonHTTP(t *testing.T) {
	svc, _ := newSubscriptionTestLocal(t)
	for _, raw := range []string{"file:///etc/passwd", "ftp://example.com/sub", "example.com/sub"} {
		if _, err := svc.AddSubscription(context.Background(), "x", raw); CodeOf(err) != CodeInvalid {
			t.Fatalf("%s was accepted: %v", raw, err)
		}
	}
}

func TestSubscriptionGroupLabelForIPHost(t *testing.T) {
	if got := groupLabelForURL("http://127.0.0.1:19090/sub.txt"); got != "sub" {
		t.Fatalf("IP host label = %q, want sub", got)
	}
	if got := groupLabelForURL("https://panel.example.com/sub"); got != "example" {
		t.Fatalf("domain label = %q, want example", got)
	}
}

const rejectedDump = testVLESS + "\n" +
	"vless://33333333-3333-3333-3333-333333333333@example.org:443?security=tls&type=tcp&headerType=http#unsupported-transport\n" +
	"http://example.org/not-a-proxy\n"

func TestPreviewReportsRejectedLinesWithoutEchoingThem(t *testing.T) {
	svc, _ := newSubscriptionTestLocal(t)
	preview, err := svc.PreviewSubscriptionText(context.Background(), rejectedDump)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if preview.Total != 1 || len(preview.Links) != 1 {
		t.Fatalf("accepted links = %+v, want the single valid link", preview)
	}
	if preview.RejectedCount != 2 || len(preview.Rejected) != 2 {
		t.Fatalf("rejected = %+v, want two diagnostics", preview.Rejected)
	}
	seen := map[string]int{}
	for _, d := range preview.Rejected {
		seen[d.Category]++
		if d.Line < 1 || d.Message == "" {
			t.Fatalf("incomplete diagnostic: %+v", d)
		}
		for _, secret := range []string{"example.org", "33333333", "http://"} {
			if strings.Contains(d.Message, secret) {
				t.Fatalf("diagnostic echoes input %q: %+v", secret, d)
			}
		}
	}
	if seen["unsupported_configuration"] != 1 || seen["parse_failure"] != 1 {
		t.Fatalf("categories = %v, want one unsupported and one parse failure", seen)
	}
}

func TestImportKeepsValidLinksAndReportsRejectedOnes(t *testing.T) {
	svc, _ := newSubscriptionTestLocal(t)
	res, err := svc.ImportSubscriptionText(context.Background(), "shadowrocket", rejectedDump)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(res.Created) != 1 {
		t.Fatalf("created = %+v, want the single valid link", res.Created)
	}
	if len(res.Diagnostics) != 2 {
		t.Fatalf("diagnostics = %+v, want two", res.Diagnostics)
	}
	list, _ := svc.ListConnections(context.Background(), ConnectionFilter{Group: "shadowrocket"})
	if len(list) != 1 {
		t.Fatalf("stored connections = %+v", list)
	}
}

func TestImportWithNoValidLinksReturnsDiagnostics(t *testing.T) {
	svc, _ := newSubscriptionTestLocal(t)
	res, err := svc.ImportSubscriptionText(context.Background(), "shadowrocket", "http://example.org/not-a-proxy\n")
	if CodeOf(err) != CodeInvalid {
		t.Fatalf("expected invalid, got %v", err)
	}
	if len(res.Diagnostics) != 1 || res.Diagnostics[0].Category != "parse_failure" {
		t.Fatalf("diagnostics = %+v", res.Diagnostics)
	}
	if list, _ := svc.ListConnections(context.Background(), ConnectionFilter{}); len(list) != 0 {
		t.Fatalf("invalid import stored links: %+v", list)
	}
}

func TestImportSubscriptionTextSkipsDuplicates(t *testing.T) {
	svc, _ := newSubscriptionTestLocal(t)
	ctx := context.Background()
	res, err := svc.ImportSubscriptionText(ctx, "bulk", subBody)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Created) != 2 {
		t.Fatalf("expected 2 created, got %+v", res)
	}
	again, err := svc.ImportSubscriptionText(ctx, "bulk", subBody)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Created) != 0 || len(again.Skipped) != 2 {
		t.Fatalf("duplicates not skipped: %+v", again)
	}
}
