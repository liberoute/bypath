package tui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/liberoute/bypath/internal/app"
)

type organizeSourceStub struct {
	app.Contract
	calls             int
	bucket, url, name string
}

func (s *organizeSourceStub) OrganizeSubscription(_ context.Context, bucket, url, name string) (app.Subscription, error) {
	s.calls++
	s.bucket, s.url, s.name = bucket, url, name
	return app.Subscription{Group: bucket, URL: url, LayerGroupID: "g_test", LayerGroup: "Europe"}, nil
}

func (s *organizeSourceStub) AddSubscription(_ context.Context, bucket, rawURL string) (app.Subscription, error) {
	s.calls++
	s.bucket, s.url = bucket, rawURL
	return app.Subscription{Group: "Europe (2)", URL: rawURL}, nil
}

func TestSourceOrganizePreviewRechecksAutomaticNameOnConfirm(t *testing.T) {
	svc := &organizeSourceStub{}
	m := &Menu{svc: svc}
	m.showSubscriptionPreview(subPreviewMsg{preview: app.SubscriptionPreview{Group: "Europe"}, url: "https://panel.example/sub#Europe"})
	cmd := m.overlay.onSelect(m, 1) // Register without another fetch.
	if cmd == nil {
		t.Fatal("preview confirmation returned no command")
	}
	batch := cmd().(tea.BatchMsg)
	msg := batch[0]().(doneMsg)
	if msg.err != nil || svc.calls != 1 || svc.bucket != "" {
		t.Fatalf("preview pinned an outdated group name: %+v %+v", svc, msg)
	}
}

func TestSourceOrganizeActionUsesContractWithoutRefreshing(t *testing.T) {
	svc := &organizeSourceStub{}
	m := &Menu{svc: svc, section: secSubscriptions, width: 80, height: 30, subs: []app.Subscription{{Group: "panel", URL: "https://panel.example/sub", ProposedGroup: "Europe"}}}
	m.subscriptionsKey(tea.KeyMsg{}, "o")
	if m.overlay.kind != ovChoice || svc.calls != 0 {
		t.Fatal("organize did not ask for confirmation")
	}
	for _, text := range []string{"Europe", ".active", "not failover"} {
		if !strings.Contains(m.overlay.info, text) {
			t.Fatalf("confirmation missing %s", text)
		}
	}
	cmd := m.overlay.onSelect(m, 1)
	if cmd == nil {
		t.Fatal("confirmation produced no command")
	}
	batch, ok := cmd().(tea.BatchMsg)
	if !ok {
		t.Fatal("organize did not start service command")
	}
	msg := batch[0]().(doneMsg)
	if msg.err != nil || svc.calls != 1 || svc.bucket != "panel" || svc.name != "" || !strings.Contains(msg.result.Message, "Europe") {
		t.Fatalf("organize contract result: %+v %+v", svc, msg)
	}
}

func TestSourceOrganizeLayout(t *testing.T) {
	for _, width := range []int{40, 80, 120} {
		m := layoutMenu(secSubscriptions, width, 30)
		got := stripANSI(m.View())
		if !strings.Contains(got, "o organize") {
			t.Fatalf("%d-column Sources lost organize action", width)
		}
		path := filepath.Join("testdata", "layout", fmt.Sprintf("sources-%d.txt", width))
		if *updateLayout {
			if err := os.WriteFile(path, []byte(got), 0644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.ReplaceAll(string(want), "\r\n", "\n") != got {
			t.Fatalf("Sources layout changed at width %d", width)
		}
	}
}
