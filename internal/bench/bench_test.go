package bench

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/liberoute/bypath/internal/profile"
)

func newManager(t *testing.T) *profile.Manager {
	t.Helper()
	mgr, err := profile.NewManager(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return mgr
}

func TestBenchableMatchesListFilter(t *testing.T) {
	cases := []struct {
		name string
		link *profile.Link
		want bool
	}{
		{"regular", &profile.Link{Address: "192.0.2.4", Port: 443}, true},
		{"nil", nil, false},
		{"placeholder address", &profile.Link{Address: "0.0.0.0", Port: 443}, false},
		{"empty address", &profile.Link{Address: "", Port: 443}, false},
		{"unroutable port", &profile.Link{Address: "192.0.2.4", Port: 9}, false},
	}
	for _, c := range cases {
		if got := Benchable(c.link); got != c.want {
			t.Errorf("%s: Benchable = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestEngineForMatchesGatewaySelection(t *testing.T) {
	cases := []struct {
		link *profile.Link
		want string
	}{
		{&profile.Link{Protocol: "vless"}, "sing-box"},
		{&profile.Link{Protocol: "openvpn"}, "sing-box"},
		{&profile.Link{Protocol: "vless", Network: "xhttp"}, "xray"},
		{&profile.Link{Protocol: "vless", Network: "splithttp"}, "xray"},
	}
	for _, c := range cases {
		if got := EngineFor(c.link); got != c.want {
			t.Errorf("%s/%s: EngineFor = %q, want %q", c.link.Protocol, c.link.Network, got, c.want)
		}
	}
}

func TestRunReportsEmptyProfileAndBadScope(t *testing.T) {
	mgr := newManager(t)
	if _, err := Run(context.Background(), mgr, Request{}, Options{}); !errors.Is(err, ErrNoGroups) {
		t.Fatalf("empty profile: err = %v, want ErrNoGroups", err)
	}

	if err := mgr.AddLink("work", &profile.Link{Remark: "a", Protocol: "vless", Address: "192.0.2.4", Port: 443}); err != nil {
		t.Fatalf("AddLink: %v", err)
	}
	if _, err := Run(context.Background(), mgr, Request{Group: "missing"}, Options{}); !errors.Is(err, ErrNoGroups) {
		t.Fatalf("unknown group: err = %v, want a wrapped ErrNoGroups", err)
	}
}

func TestRunReportsNoTestableLinks(t *testing.T) {
	mgr := newManager(t)
	if err := mgr.AddLink("work", &profile.Link{Remark: "placeholder", Protocol: "vless", Address: "0.0.0.0", Port: 443}); err != nil {
		t.Fatalf("AddLink: %v", err)
	}
	if _, err := Run(context.Background(), mgr, Request{Group: "work"}, Options{}); !errors.Is(err, ErrNoLinks) {
		t.Fatalf("placeholder-only group: err = %v, want ErrNoLinks", err)
	}
}

func TestActivateResolvesRowIdentity(t *testing.T) {
	mgr := newManager(t)
	if err := mgr.AddLink("work", &profile.Link{Remark: "fast", Protocol: "vless", Address: "192.0.2.4", Port: 443}); err != nil {
		t.Fatalf("AddLink: %v", err)
	}
	if err := Activate(mgr, "work", "fast"); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	active := mgr.GetActiveLink()
	if active == nil || active.Remark != "fast" {
		t.Fatalf("active link = %+v, want the named row", active)
	}
	if err := Activate(mgr, "work", "absent"); err == nil {
		t.Fatal("Activate of a missing row must fail")
	}
	if err := Activate(mgr, "missing", "fast"); err == nil {
		t.Fatal("Activate in a missing group must fail")
	}
}

func TestRunPreservesActiveLinkAcrossSave(t *testing.T) {
	dir := t.TempDir()
	mgr, err := profile.NewManager(dir, "default")
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := mgr.AddLink("work", &profile.Link{Remark: "keep", Protocol: "vless", Address: "127.0.0.1", Port: 443}); err != nil {
		t.Fatalf("AddLink: %v", err)
	}
	if err := mgr.AddLink("work", &profile.Link{Remark: "other", Protocol: "vless", Address: "127.0.0.1", Port: 444}); err != nil {
		t.Fatalf("AddLink: %v", err)
	}
	g, err := mgr.GetGroup("work")
	if err != nil {
		t.Fatalf("GetGroup: %v", err)
	}
	mgr.SetActiveLink(g.Links[0])

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// Persisting benchmark verdicts must not disturb the stored selection.
	if _, err := Run(ctx, mgr, Request{Group: "work"}, Options{}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	reopened, err := profile.NewManager(dir, "default")
	if err != nil {
		t.Fatalf("reopening profiles: %v", err)
	}
	active := reopened.GetActiveLink()
	if active == nil || active.Remark != "keep" {
		t.Fatalf("active link after bench = %+v, want the previously selected link", active)
	}
}

func TestSortRowsByRemarkDoesNotMutateInput(t *testing.T) {
	rows := []Row{{Remark: "c"}, {Remark: "a"}, {Remark: "b"}}
	sorted := SortRowsByRemark(rows)
	if sorted[0].Remark != "a" || sorted[2].Remark != "c" {
		t.Fatalf("sorted = %v", sorted)
	}
	if rows[0].Remark != "c" {
		t.Fatalf("input was reordered: %v", rows)
	}
}
