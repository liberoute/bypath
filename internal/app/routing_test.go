package app

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/liberoute/bypath/internal/config"
)

// fakeRuntime stands in for the gateway so routing tests never touch a tunnel.
type fakeRuntime struct {
	mu          sync.Mutex
	state       string
	activeLink  string
	activeGroup string
	applyErr    error
	applied     int
	reloads     int
}

func (f *fakeRuntime) Status() RuntimeStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	return RuntimeStatus{State: f.state, ActiveLink: f.activeLink, ActiveGroup: f.activeGroup}
}

func (f *fakeRuntime) setServing(group, remark string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state = "CONNECTED"
	f.activeGroup = group
	f.activeLink = remark
}

func (f *fakeRuntime) ApplyActiveLink(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applied++
	return f.applyErr
}

func (f *fakeRuntime) StopTunnel(ctx context.Context) error { return nil }
func (f *fakeRuntime) RequestStop() error                   { return nil }
func (f *fakeRuntime) Engines() []Engine                    { return nil }
func (f *fakeRuntime) Reload(cfg *config.Config) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reloads++
	return nil
}

func (f *fakeRuntime) setState(state string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state = state
}

func (f *fakeRuntime) applyCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.applied
}

func baseRoutingRules() []config.RoutingRule {
	return []config.RoutingRule{
		{Match: "geoip:de", Outbound: "direct"},
		{Match: "domain_suffix:de", Outbound: "direct"},
		{Match: "default", Outbound: "proxy"},
	}
}

// newRoutingLocal builds a service around an in-memory routing configuration.
// The history directory lives under a fresh temp dir so snapshots never touch
// the developer's machine state.
func newRoutingLocal(t *testing.T, rules []config.RoutingRule, rt Runtime) *Local {
	t.Helper()
	svc, _ := newTestLocal(t)
	cfg := &config.Config{}
	cfg.Server.APIPort = 8080
	cfg.Server.SOCKSPort = 2801
	cfg.Server.Listen = "127.0.0.1"
	cfg.Gateway.Enabled = true
	cfg.Gateway.DNSMode = "strict"
	cfg.Gateway.DNSUpstream = []string{"1.1.1.1"}
	cfg.HealthCheck.Interval = "30s"
	cfg.Profiles.Directory = t.TempDir()
	cfg.Profiles.ActiveGroup = "default"
	cfg.Routing.Rules = rules
	svc.cfg = cfg
	svc.runtime = rt
	return svc
}

func appErrorCode(t *testing.T, err error) string {
	t.Helper()
	var ae *Error
	if !errors.As(err, &ae) {
		t.Fatalf("expected *Error, got %T: %v", err, err)
	}
	return ae.Code
}

func rulePairs(rules []config.RoutingRule) []string {
	out := make([]string, len(rules))
	for i, r := range rules {
		out[i] = r.Match + "=" + r.Outbound
	}
	return out
}

func TestComposeRulesPreservesCoreOrder(t *testing.T) {
	current := []config.RoutingRule{
		{Match: "domain:keep.example", Outbound: "direct"},
		{Match: "geoip:de", Outbound: "direct"},
		{Match: "geosite:CATEGORY-DE", Outbound: "direct"},
		{Match: "default", Outbound: "proxy"},
	}
	edit := RoutingEdit{
		Force: []RoutingRuleInput{
			{Match: "domain:force.example", Outbound: "proxy"},
			{Match: "domain:blocked.example", Outbound: "block"},
		},
		Direct: []RoutingRuleInput{
			{Match: "domain_suffix:.direct.example", Outbound: "direct"},
		},
	}
	got := rulePairs(composeRules(current, edit))
	want := []string{
		"domain:force.example=proxy",
		"domain:blocked.example=block",
		"geoip:de=direct",
		"geosite:CATEGORY-DE=direct",
		"domain_suffix:direct.example=direct",
		"default=proxy",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("compose order\n got: %v\nwant: %v", got, want)
	}
}

func TestComposeRulesKeepsDefaultLastWhenNoDefaultExists(t *testing.T) {
	current := []config.RoutingRule{{Match: "geoip:de", Outbound: "direct"}}
	got := rulePairs(composeRules(current, RoutingEdit{}))
	if len(got) != 1 || got[0] != "geoip:de=direct" {
		t.Fatalf("unexpected composition without a default rule: %v", got)
	}
}

func TestValidateEditRejectsUnsafeExceptions(t *testing.T) {
	tests := []struct {
		name string
		edit RoutingEdit
		want string
	}{
		{
			name: "force direct is refused",
			edit: RoutingEdit{Force: []RoutingRuleInput{{Match: "domain:x.example", Outbound: "direct"}}},
			want: "must be PROXY or BLOCK",
		},
		{
			name: "direct group cannot proxy",
			edit: RoutingEdit{Direct: []RoutingRuleInput{{Match: "domain:x.example", Outbound: "proxy"}}},
			want: "can only contain DIRECT",
		},
		{
			name: "bad cidr",
			edit: RoutingEdit{Direct: []RoutingRuleInput{{Match: "ip_cidr:203.0.113.0/33", Outbound: "direct"}}},
			want: "not an IP range",
		},
		{
			name: "geoip is core policy",
			edit: RoutingEdit{Force: []RoutingRuleInput{{Match: "geoip:de", Outbound: "proxy"}}},
			want: "only domain, domain_suffix and ip_cidr",
		},
		{
			name: "exact domain with leading dot",
			edit: RoutingEdit{Direct: []RoutingRuleInput{{Match: "domain:.x.example", Outbound: "direct"}}},
			want: "must not start with a dot",
		},
		{
			name: "duplicate with same action",
			edit: RoutingEdit{Force: []RoutingRuleInput{
				{Match: "domain:x.example", Outbound: "proxy"},
				{Match: "domain:X.example", Outbound: "proxy"},
			}},
			want: "listed twice",
		},
		{
			name: "contradicting action",
			edit: RoutingEdit{
				Force:  []RoutingRuleInput{{Match: "domain:x.example", Outbound: "proxy"}},
				Direct: []RoutingRuleInput{{Match: "domain:x.example", Outbound: "direct"}},
			},
			want: "different action",
		},
		{
			name: "missing matcher value",
			edit: RoutingEdit{Direct: []RoutingRuleInput{{Match: "domain_suffix:", Outbound: "direct"}}},
			want: "must look like",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateEdit(tc.edit)
			if err == nil {
				t.Fatalf("expected rejection")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}

	valid := RoutingEdit{
		Force: []RoutingRuleInput{
			{Match: "domain:blocked.example", Outbound: "block"},
			{Match: "domain_suffix:force.example", Outbound: "proxy"},
		},
		Direct: []RoutingRuleInput{
			{Match: "domain:direct.example", Outbound: "direct"},
			{Match: "ip_cidr:203.0.113.0/24", Outbound: "direct"},
		},
	}
	if err := validateEdit(valid); err != nil {
		t.Fatalf("valid edit rejected: %v", err)
	}
}

func TestEditWarningsFlagDirectTrafficAndOverlappingExceptions(t *testing.T) {
	warnings := editWarnings(RoutingEdit{
		Force:  []RoutingRuleInput{{Match: "domain:shop.example", Outbound: "proxy"}},
		Direct: []RoutingRuleInput{{Match: "domain_suffix:example", Outbound: "direct"}},
	})
	joined := strings.Join(warnings, "\n")
	if !strings.Contains(joined, "goes through the tunnel although another rule") {
		t.Fatalf("missing warning about an overlapping tunnel rule: %v", warnings)
	}
	if !strings.Contains(joined, "gateway's address") {
		t.Fatalf("direct warning must say the traffic leaves from this gateway: %v", warnings)
	}
}

func TestEditWarningsStayQuietWithoutAnOverlap(t *testing.T) {
	warnings := editWarnings(RoutingEdit{
		Force: []RoutingRuleInput{{Match: "domain:shop.example", Outbound: "proxy"}},
	})
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings without a direct exception: %v", warnings)
	}
}

func TestRoutingRevisionTracksEveryInput(t *testing.T) {
	svc := newRoutingLocal(t, baseRoutingRules(), nil)
	before := routingRevision(svc.Config())
	if len(before) != 16 {
		t.Fatalf("revision %q is not 16 hex characters", before)
	}
	if again := routingRevision(svc.Config()); again != before {
		t.Fatalf("revision is not stable: %s vs %s", before, again)
	}

	changed := *svc.Config()
	changed.Routing = svc.Config().Routing
	changed.Routing.Rules = append([]config.RoutingRule{{Match: "domain:new.example", Outbound: "direct"}}, changed.Routing.Rules...)
	if routingRevision(&changed) == before {
		t.Fatal("revision ignored a rules change")
	}

	dns := *svc.Config()
	dns.Gateway = svc.Config().Gateway
	dns.Gateway.DNSMode = "local"
	if routingRevision(&dns) == before {
		t.Fatal("revision ignored a DNS mode change")
	}
}

func TestPreviewRoutingMatchesModelAndWarns(t *testing.T) {
	svc := newRoutingLocal(t, baseRoutingRules(), nil)
	ctx := context.Background()

	preview, err := svc.PreviewRouting(ctx, RoutingEdit{
		Direct: []RoutingRuleInput{{Match: "domain_suffix:example.com", Outbound: "direct"}},
	})
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if preview.Revision != routingRevision(svc.Config()) {
		t.Fatalf("preview revision %q does not match the loaded policy", preview.Revision)
	}
	if preview.DefaultOutbound != "proxy" {
		t.Fatalf("default outbound %q, want proxy", preview.DefaultOutbound)
	}
	if len(preview.Warnings) == 0 {
		t.Fatal("a direct foreign suffix must carry a warning")
	}
	if len(preview.Rules) == 0 || preview.Rules[len(preview.Rules)-1].Kind != "default" {
		t.Fatalf("preview rules must end with the default entry: %+v", preview.Rules)
	}
	if got := preview.Summary[len(preview.Summary)-1]; got != "Everything else → PROXY" {
		t.Fatalf("summary tail %q", got)
	}
	// Preview must never persist anything.
	if _, err := os.Stat(svc.configPath); err == nil {
		t.Fatal("preview wrote the configuration file")
	}
}

func TestPreviewRoutingRefusesLegacyPolicy(t *testing.T) {
	svc := newRoutingLocal(t, nil, nil)
	_, err := svc.PreviewRouting(context.Background(), RoutingEdit{})
	if err == nil {
		t.Fatal("legacy policy accepted an editable preview")
	}
	if code := appErrorCode(t, err); code != CodeInvalid {
		t.Fatalf("code %s, want %s", code, CodeInvalid)
	}
}

func TestApplyRoutingPersistsSnapshotsAndRollsBack(t *testing.T) {
	rt := &fakeRuntime{state: "DISCONNECTED"}
	svc := newRoutingLocal(t, baseRoutingRules(), rt)
	ctx := context.Background()

	overview, err := svc.RoutingOverview(ctx)
	if err != nil {
		t.Fatalf("overview: %v", err)
	}
	if overview.Mode != "rules" || !overview.CanEdit {
		t.Fatalf("overview not editable: mode=%q can_edit=%v", overview.Mode, overview.CanEdit)
	}

	change, err := svc.ApplyRouting(ctx, RoutingEdit{
		Force: []RoutingRuleInput{{Match: "domain:blocked.example", Outbound: "block"}},
	}, overview.Revision, "test exception")
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !change.Applied || change.RestartRequired {
		t.Fatalf("unexpected apply result: %+v", change)
	}
	if change.Snapshot == "" {
		t.Fatal("apply did not record a rollback snapshot")
	}
	if change.Revision == overview.Revision {
		t.Fatal("revision did not change after apply")
	}

	onDisk, err := os.ReadFile(svc.configPath)
	if err != nil {
		t.Fatalf("reading written config: %v", err)
	}
	if !strings.Contains(string(onDisk), "domain:blocked.example") {
		t.Fatal("the applied exception is not in the written configuration")
	}
	if rules := svc.Config().Routing.Rules; len(rules) == 0 || rules[0].Match != "domain:blocked.example" {
		t.Fatalf("force exception is not first in the active rules: %v", rulePairs(rules))
	}

	// A stale preview must be rejected instead of overwriting the new policy.
	_, err = svc.ApplyRouting(ctx, RoutingEdit{}, overview.Revision, "")
	if err == nil {
		t.Fatal("stale revision was accepted")
	}
	if code := appErrorCode(t, err); code != CodeConflict {
		t.Fatalf("code %s, want %s", code, CodeConflict)
	}

	snapshots := svc.listRoutingSnapshots()
	if len(snapshots) != 1 || snapshots[0].ID != change.Snapshot {
		t.Fatalf("unexpected snapshot list: %+v", snapshots)
	}
	if snapshots[0].Note != "test exception" {
		t.Fatalf("snapshot note %q", snapshots[0].Note)
	}

	rolled, err := svc.RollbackRouting(ctx, change.Snapshot)
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if !rolled.Applied {
		t.Fatalf("rollback not applied: %+v", rolled)
	}
	if got := rulePairs(svc.Config().Routing.Rules); strings.Join(got, "|") != strings.Join(rulePairs(baseRoutingRules()), "|") {
		t.Fatalf("rollback did not restore the previous policy: %v", got)
	}
	if len(svc.listRoutingSnapshots()) != 2 {
		t.Fatal("the rollback itself must be snapshotted so it can be reverted")
	}

	// The rejected unreadable id must not be used as a path.
	if _, err := svc.RollbackRouting(ctx, "../config"); err == nil {
		t.Fatal("path traversal id was accepted")
	}
}

func TestApplyRoutingRestoresPolicyWhenTunnelFails(t *testing.T) {
	rt := &fakeRuntime{state: "CONNECTED", applyErr: errors.New("engine refused the config")}
	svc := newRoutingLocal(t, baseRoutingRules(), rt)
	ctx := context.Background()

	_, err := svc.ApplyRouting(ctx, RoutingEdit{
		Force: []RoutingRuleInput{{Match: "domain:blocked.example", Outbound: "block"}},
	}, "", "should fail")
	if err == nil {
		t.Fatal("apply reported success although the tunnel failed")
	}
	if code := appErrorCode(t, err); code != CodeUnavailable {
		t.Fatalf("code %s, want %s", code, CodeUnavailable)
	}
	if got := rulePairs(svc.Config().Routing.Rules); strings.Join(got, "|") != strings.Join(rulePairs(baseRoutingRules()), "|") {
		t.Fatalf("previous policy was not restored in memory: %v", got)
	}
	onDisk, readErr := os.ReadFile(svc.configPath)
	if readErr != nil {
		t.Fatalf("reading restored config: %v", readErr)
	}
	if strings.Contains(string(onDisk), "domain:blocked.example") {
		t.Fatal("the failed policy is still on disk")
	}
	if rt.applyCount() != 2 {
		t.Fatalf("expected the new tunnel and the retry, got %d attempts", rt.applyCount())
	}
}

func TestApplyRoutingWaitsForRestartWhileConnecting(t *testing.T) {
	rt := &fakeRuntime{state: "CONNECTING"}
	svc := newRoutingLocal(t, baseRoutingRules(), rt)

	change, err := svc.ApplyRouting(context.Background(), RoutingEdit{
		Direct: []RoutingRuleInput{{Match: "domain:direct.example", Outbound: "direct"}},
	}, "", "")
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if change.Applied || !change.RestartRequired {
		t.Fatalf("a connecting gateway must not report the rules as live: %+v", change)
	}
}

func TestRoutingOverviewReportsLegacyPolicyAsIgnored(t *testing.T) {
	rules := append(baseRoutingRules(), config.RoutingRule{Match: "domain:old.example", Outbound: "direct"})
	svc := newRoutingLocal(t, rules, nil)
	cfg := svc.Config()
	cfg.Whitelist.Countries = []string{"ir"}
	cfg.Whitelist.BypassDomains = []string{"legacy.example"}

	overview, err := svc.RoutingOverview(context.Background())
	if err != nil {
		t.Fatalf("overview: %v", err)
	}
	if !overview.Legacy.Present || !overview.Legacy.Ignored {
		t.Fatalf("legacy whitelist not reported as ignored: %+v", overview.Legacy)
	}
	if !strings.Contains(strings.Join(overview.Warnings, "\n"), "ignored because routing.rules exists") {
		t.Fatalf("missing ignored-whitelist warning: %v", overview.Warnings)
	}
}

func TestRoutingOverviewLegacyModeIsReadOnly(t *testing.T) {
	svc := newRoutingLocal(t, nil, nil)
	cfg := svc.Config()
	cfg.Whitelist.Countries = []string{"ir"}
	cfg.Whitelist.BypassDomains = []string{"legacy.example"}

	overview, err := svc.RoutingOverview(context.Background())
	if err != nil {
		t.Fatalf("overview: %v", err)
	}
	if overview.Mode != "legacy" {
		t.Fatalf("mode %q, want legacy", overview.Mode)
	}
	if overview.CanEdit || overview.CanEditReason == "" {
		t.Fatalf("legacy policy must be read-only with a reason: %+v", overview)
	}
	if overview.DefaultOutbound != "proxy" {
		t.Fatalf("default outbound %q", overview.DefaultOutbound)
	}
}

func TestRoutingProfilesOnlyApplyVerifiedExceptions(t *testing.T) {
	svc := newRoutingLocal(t, baseRoutingRules(), nil)
	profiles := routingProfiles(svc.Config())
	byID := map[string]RoutingProfile{}
	for _, p := range profiles {
		byID[p.ID] = p
	}

	if p := byID["builtin-policy"]; p.Status != "active" || !p.Enabled || p.Edit != nil {
		t.Fatalf("base policy profile unexpected: %+v", p)
	}
	checks := byID["ip-check-hosts"]
	if checks.Status != "available" || checks.Enabled {
		t.Fatalf("IP-check profile should be available but inactive: %+v", checks)
	}
	if checks.Edit == nil || len(checks.Edit.Direct) != 4 {
		t.Fatalf("IP-check profile must carry four direct hosts: %+v", checks.Edit)
	}
	for _, rule := range checks.Edit.Direct {
		if strings.HasPrefix(rule.Match, "ip_cidr:") {
			t.Fatalf("IP-check profile must not route IP ranges: %s", rule.Match)
		}
	}

	// Applying the profile's rules must mark it enabled.
	svc2 := newRoutingLocal(t, append(append([]config.RoutingRule{}, baseRoutingRules()...),
		config.RoutingRule{Match: "domain_suffix:cloudflare.com", Outbound: "direct"},
		config.RoutingRule{Match: "domain_suffix:ip-api.com", Outbound: "direct"},
		config.RoutingRule{Match: "domain_suffix:ipinfo.io", Outbound: "direct"},
		config.RoutingRule{Match: "domain_suffix:api.myip.com", Outbound: "direct"},
	), nil)
	for _, p := range routingProfiles(svc2.Config()) {
		if p.ID == "ip-check-hosts" && !p.Enabled {
			t.Fatalf("profile should be detected as active: %+v", p)
		}
	}
}

func TestParseTarget(t *testing.T) {
	tests := []struct {
		in     string
		host   string
		isIP   bool
		reject bool
	}{
		{in: "example.com", host: "example.com"},
		{in: "https://Example.COM:8443/path?q=1", host: "example.com"},
		{in: "example.com.", host: "example.com"},
		{in: "203.0.113.9", host: "203.0.113.9", isIP: true},
		{in: "203.0.113.9:443", host: "203.0.113.9", isIP: true},
		{in: "[2001:db8::1]", host: "2001:db8::1", isIP: true},
		{in: "[2001:db8::1]:443", host: "2001:db8::1", isIP: true},
		{in: "", reject: true},
		{in: "not a host", reject: true},
		{in: "-bad.example", reject: true},
	}
	for _, tc := range tests {
		host, isIP, err := parseTarget(tc.in)
		if tc.reject {
			if err == nil {
				t.Fatalf("%q was accepted as %q", tc.in, host)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%q rejected: %v", tc.in, err)
		}
		if host != tc.host || isIP != tc.isIP {
			t.Fatalf("%q parsed as (%q,%v), want (%q,%v)", tc.in, host, isIP, tc.host, tc.isIP)
		}
	}
}

func TestSuffixMatchIsLabelBound(t *testing.T) {
	tests := []struct {
		host, suffix string
		want         bool
	}{
		{"example.com", "example.com", true},
		{"www.example.com", "example.com", true},
		{"example.com", ".example.com", true},
		{"notexample.com", "example.com", false},
		{"example.com.evil.test", "example.com", false},
		{"", "example.com", false},
	}
	for _, tc := range tests {
		if got := suffixMatch(tc.host, tc.suffix); got != tc.want {
			t.Fatalf("suffixMatch(%q,%q)=%v want %v", tc.host, tc.suffix, got, tc.want)
		}
	}
}

func TestExplainRouteDomainSuffixAndExact(t *testing.T) {
	rules := []config.RoutingRule{
		{Match: "domain:news.example", Outbound: "proxy"},
		{Match: "domain_suffix:example.org", Outbound: "direct"},
		{Match: "default", Outbound: "proxy"},
	}
	svc := newRoutingLocal(t, rules, nil)
	ctx := context.Background()

	exact, err := svc.ExplainRoute(ctx, "https://news.example/story")
	if err != nil {
		t.Fatalf("explain exact: %v", err)
	}
	if exact.Outcome != "PROXY" || exact.Kind != "domain" || exact.DNS != "not_needed" || !exact.Certain {
		t.Fatalf("exact domain explained as %+v", exact)
	}
	if exact.DecidedBy == nil || exact.DecidedBy.Kind != "domain" || exact.DecidedBy.Match != "Exact domain: news.example" {
		t.Fatalf("wrong deciding rule: %+v", exact.DecidedBy)
	}
	if exact.DecidedBy.Position != 2 || exact.DecidedBy.Scope != "rule" {
		t.Fatalf("deciding rule reported at #%d scope %q, want the second plan entry", exact.DecidedBy.Position, exact.DecidedBy.Scope)
	}
	if !strings.Contains(exact.Summary, "PROXY") {
		t.Fatalf("summary does not name the action: %q", exact.Summary)
	}

	suffix, err := svc.ExplainRoute(ctx, "deep.example.org")
	if err != nil {
		t.Fatalf("explain suffix: %v", err)
	}
	if suffix.Outcome != "DIRECT" || suffix.DecidedBy == nil || suffix.DecidedBy.Kind != "domain_suffix" {
		t.Fatalf("suffix domain explained as %+v", suffix)
	}

	// A lookalike must not inherit the suffix rule.
	other, err := svc.ExplainRoute(ctx, "notexample.org")
	if err != nil {
		t.Fatalf("explain lookalike: %v", err)
	}
	if other.Outcome != "PROXY" {
		t.Fatalf("lookalike host matched the suffix rule: %+v", other.DecidedBy)
	}
	// The fallthrough must cite the real catch-all entry, not a synthetic one
	// appended past the end of the plan the engine runs.
	plan := routingPlan(svc.Config())
	if got, want := other.DecidedBy.Position, len(plan); got != want {
		t.Fatalf("fallthrough reported at #%d, want the default entry at #%d", got, want)
	}
	if other.DecidedBy.Scope != "default" || other.DecidedBy.Match != "Everything not matched above" {
		t.Fatalf("fallthrough did not cite the default rule: %+v", other.DecidedBy)
	}
}

func TestExplainRouteIPRules(t *testing.T) {
	rules := []config.RoutingRule{
		{Match: "ip_cidr:203.0.113.0/24", Outbound: "direct"},
		{Match: "ip_cidr:198.51.100.0/24", Outbound: "block"},
		{Match: "default", Outbound: "proxy"},
	}
	svc := newRoutingLocal(t, rules, nil)
	ctx := context.Background()

	inside, err := svc.ExplainRoute(ctx, "203.0.113.9")
	if err != nil {
		t.Fatalf("explain cidr: %v", err)
	}
	if inside.Outcome != "DIRECT" || inside.Kind != "ip" || !inside.Certain {
		t.Fatalf("cidr address explained as %+v", inside)
	}

	blocked, err := svc.ExplainRoute(ctx, "198.51.100.10")
	if err != nil {
		t.Fatalf("explain block: %v", err)
	}
	if blocked.Outcome != "BLOCK" {
		t.Fatalf("blocked range explained as %+v", blocked)
	}

	privateAddr, err := svc.ExplainRoute(ctx, "192.168.1.10")
	if err != nil {
		t.Fatalf("explain private: %v", err)
	}
	if privateAddr.Outcome != "DIRECT" || privateAddr.DecidedBy == nil || privateAddr.DecidedBy.Kind != "private" {
		t.Fatalf("private address explained as %+v", privateAddr.DecidedBy)
	}

	fallthroughAddr, err := svc.ExplainRoute(ctx, "8.8.4.4")
	if err != nil {
		t.Fatalf("explain default: %v", err)
	}
	if fallthroughAddr.Outcome != "PROXY" || fallthroughAddr.DecidedBy == nil || fallthroughAddr.DecidedBy.Kind != "default" {
		t.Fatalf("unmatched address explained as %+v", fallthroughAddr.DecidedBy)
	}
	if got, want := fallthroughAddr.DecidedBy.Position, len(routingPlan(svc.Config())); got != want {
		t.Fatalf("unmatched address reported at #%d, want the default entry at #%d", got, want)
	}
	if !strings.Contains(fallthroughAddr.Summary, "default policy") {
		t.Fatalf("default summary %q", fallthroughAddr.Summary)
	}
}

func TestExplainRouteDNSUnavailableIsHonest(t *testing.T) {
	svc := newRoutingLocal(t, baseRoutingRules(), nil)
	out, err := svc.ExplainRoute(context.Background(), "unknown.example")
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	if out.DNS != "unavailable" || out.Certain {
		t.Fatalf("disconnected gateway claimed a certain answer: %+v", out)
	}
	if !strings.Contains(strings.Join(out.Warnings, "\n"), "Start the gateway") {
		t.Fatalf("missing advice for an unavailable DNS check: %v", out.Warnings)
	}
	if out.Outcome != "PROXY" {
		t.Fatalf("outcome %q", out.Outcome)
	}
}

func TestExplainRouteDNSFailureUsesGatewayResolver(t *testing.T) {
	rt := &fakeRuntime{state: "CONNECTED"}
	svc := newRoutingLocal(t, baseRoutingRules(), rt)
	svc.cfg.Server.DNSPort = closedUDPPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := svc.ExplainRoute(ctx, "missing.example")
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	if out.DNS != "failed" || out.Certain {
		t.Fatalf("expected a failed lookup with an uncertain answer: %+v", out)
	}
}

// --- route test -------------------------------------------------------------

func closedTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

func closedUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	conn.Close()
	return port
}

// startFakeSOCKS accepts one no-auth SOCKS5 CONNECT and then hands the
// connection to respond, so the panel's tunnel test can run without a tunnel.
func startFakeSOCKS(t *testing.T, respond func(net.Conn)) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				var greeting [2]byte
				if _, err := io.ReadFull(c, greeting[:]); err != nil {
					return
				}
				methods := make([]byte, int(greeting[1]))
				if _, err := io.ReadFull(c, methods); err != nil {
					return
				}
				if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
					return
				}
				var head [4]byte
				if _, err := io.ReadFull(c, head[:]); err != nil {
					return
				}
				switch head[3] {
				case 0x01:
					_, err = io.CopyN(io.Discard, c, 6)
				case 0x04:
					_, err = io.CopyN(io.Discard, c, 18)
				case 0x03:
					var n [1]byte
					if _, err = io.ReadFull(c, n[:]); err == nil {
						_, err = io.CopyN(io.Discard, c, int64(n[0])+2)
					}
				default:
					return
				}
				if err != nil {
					return
				}
				if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
					return
				}
				respond(c)
			}(conn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestTestRouteBlockedByRuleNeedsNoConnection(t *testing.T) {
	rules := []config.RoutingRule{
		{Match: "ip_cidr:203.0.113.0/24", Outbound: "deny"},
		{Match: "default", Outbound: "proxy"},
	}
	svc := newRoutingLocal(t, rules, nil)
	result, err := svc.TestRoute(context.Background(), "203.0.113.8", 443)
	if err != nil {
		t.Fatalf("test route: %v", err)
	}
	if result.Verdict != "blocked_by_rule" || result.VerdictText == "" {
		t.Fatalf("unexpected verdict: %+v", result)
	}
	if result.Explanation.Outcome != "BLOCK" {
		t.Fatalf("explanation outcome %q", result.Explanation.Outcome)
	}
}

func TestTestRouteGatewayOffline(t *testing.T) {
	svc := newRoutingLocal(t, baseRoutingRules(), nil)
	result, err := svc.TestRoute(context.Background(), "198.51.100.7", 443)
	if err != nil {
		t.Fatalf("test route: %v", err)
	}
	if result.Verdict != "gateway_offline" {
		t.Fatalf("verdict %q", result.Verdict)
	}
}

func TestTestRouteDNSFailure(t *testing.T) {
	rt := &fakeRuntime{state: "CONNECTED"}
	svc := newRoutingLocal(t, baseRoutingRules(), rt)
	svc.cfg.Server.DNSPort = closedUDPPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := svc.TestRoute(ctx, "missing.example", 80)
	if err != nil {
		t.Fatalf("test route: %v", err)
	}
	if result.Verdict != "dns_failure" {
		t.Fatalf("verdict %q (%s)", result.Verdict, result.VerdictText)
	}
}

func TestTestRouteConnectionFailed(t *testing.T) {
	rt := &fakeRuntime{state: "CONNECTED"}
	svc := newRoutingLocal(t, baseRoutingRules(), rt)
	svc.cfg.Server.SOCKSPort = closedTCPPort(t)

	result, err := svc.TestRoute(context.Background(), "198.51.100.7", 80)
	if err != nil {
		t.Fatalf("test route: %v", err)
	}
	if result.Verdict != "connection_failed" {
		t.Fatalf("verdict %q (%s)", result.Verdict, result.VerdictText)
	}
	if result.Detail == "" {
		t.Fatal("a failed connection must explain itself")
	}
}

func TestTestRouteTCPConnectedOnOtherPorts(t *testing.T) {
	socksPort := startFakeSOCKS(t, func(c net.Conn) {
		<-time.After(300 * time.Millisecond)
	})
	rt := &fakeRuntime{state: "CONNECTED"}
	svc := newRoutingLocal(t, baseRoutingRules(), rt)
	svc.cfg.Server.SOCKSPort = socksPort

	result, err := svc.TestRoute(context.Background(), "198.51.100.7", 9000)
	if err != nil {
		t.Fatalf("test route: %v", err)
	}
	if result.Verdict != "tcp_connected" {
		t.Fatalf("verdict %q (%s)", result.Verdict, result.VerdictText)
	}
	if !strings.Contains(result.VerdictText, "Only connectivity") {
		t.Fatalf("verdict text must state what was checked: %q", result.VerdictText)
	}
}

func TestTestRouteHTTPReachableAndHTTPError(t *testing.T) {
	tests := []struct {
		name    string
		answer  string
		status  int
		verdict string
	}{
		{name: "reachable", answer: "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", status: 200, verdict: "reachable"},
		{name: "site error", answer: "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n", status: 503, verdict: "http_error"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			answer := tc.answer
			socksPort := startFakeSOCKS(t, func(c net.Conn) {
				// Read the request before answering, then drain until the client
				// closes: closing with unread input would reset the connection
				// and discard the response we just wrote.
				reader := bufio.NewReader(c)
				for {
					line, err := reader.ReadString('\n')
					if err != nil || strings.TrimSpace(line) == "" {
						break
					}
				}
				_, _ = io.WriteString(c, answer)
				_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
				_, _ = io.Copy(io.Discard, reader)
			})
			rt := &fakeRuntime{state: "CONNECTED"}
			svc := newRoutingLocal(t, baseRoutingRules(), rt)
			svc.cfg.Server.SOCKSPort = socksPort

			result, err := svc.TestRoute(context.Background(), "198.51.100.7", 80)
			if err != nil {
				t.Fatalf("test route: %v", err)
			}
			if result.Verdict != tc.verdict || result.HTTPStatus != tc.status {
				t.Fatalf("verdict %q status %d (%s)", result.Verdict, result.HTTPStatus, result.VerdictText)
			}
			if tc.status == 503 && !strings.Contains(result.VerdictText, "destination is reachable") {
				t.Fatalf("HTTP error must not be blamed on the route: %q", result.VerdictText)
			}
		})
	}
}

func TestTestRouteTLSFailureIsDistinguished(t *testing.T) {
	socksPort := startFakeSOCKS(t, func(c net.Conn) {
		_, _ = io.WriteString(c, "this is not a TLS handshake\n")
	})
	rt := &fakeRuntime{state: "CONNECTED"}
	rules := append([]config.RoutingRule{
		{Match: "domain:svc.test", Outbound: "direct"},
	}, baseRoutingRules()...)
	svc := newRoutingLocal(t, rules, rt)
	svc.cfg.Server.SOCKSPort = socksPort

	result, err := svc.TestRoute(context.Background(), "svc.test", 443)
	if err != nil {
		t.Fatalf("test route: %v", err)
	}
	if result.Verdict != "tls_failure" {
		t.Fatalf("verdict %q (%s)", result.Verdict, result.VerdictText)
	}
	if result.Explanation.DNS != "not_needed" {
		t.Fatalf("a domain rule should decide without DNS: %+v", result.Explanation)
	}
}

func TestTestRouteRejectsBadPort(t *testing.T) {
	svc := newRoutingLocal(t, baseRoutingRules(), nil)
	if _, err := svc.TestRoute(context.Background(), "198.51.100.7", 70000); err == nil {
		t.Fatal("out-of-range port accepted")
	}
}
