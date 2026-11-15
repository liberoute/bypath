package app

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/geo"
	"github.com/liberoute/bypath/internal/paths"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// writeSplitRuleSet writes a binary .srs rule set in the format sing-box loads.
func writeSplitRuleSet(t *testing.T, path string, domains, suffixes, cidrs []string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	set := option.PlainRuleSet{Rules: []option.HeadlessRule{{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultHeadlessRule{
			Domain:       domains,
			DomainSuffix: suffixes,
			IPCIDR:       cidrs,
		},
	}}}
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := srs.Write(file, set, C.RuleSetVersionCurrent); err != nil {
		t.Fatalf("write rule set %s: %v", path, err)
	}
}

// writeSplitAssets provisions the two files a sing-box country split needs.
func writeSplitAssets(t *testing.T, geoDir, country string) {
	t.Helper()
	writeSplitRuleSet(t, filepath.Join(geoDir, "geosite-"+country+".srs"), nil, []string{"irna.ir"}, nil)
	writeSplitRuleSet(t, filepath.Join(geoDir, "geoip-"+country+".srs"), nil, nil, []string{"5.22.0.0/16"})
}

// newSplitLocal builds a local service whose routing policy is the shipped
// proxy-only default, with the split configured when country is non-empty.
func newSplitLocal(t *testing.T, country string, withAssets bool) (*Local, *paths.Resolved) {
	t.Helper()
	svc, p := newTestLocal(t)
	cfg := svc.Config()
	cfg.Routing.Rules = []config.RoutingRule{{Match: "default", Outbound: "proxy"}}
	cfg.Routing.CountrySplit = country
	cfg.Engines.PreferredEngine = "sing-box"
	svc.cfg = cfg
	svc.runtime = &fakeRuntime{}
	if withAssets && country != "" {
		writeSplitAssets(t, p.GeoDir, country)
	}
	return svc, p
}

func splitPtr(value string) *string { return &value }

func hasWarningContaining(warnings []string, needle string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, needle) {
			return true
		}
	}
	return false
}

// TestRoutingOverviewSingboxDoesNotWarnAboutDatAssets pins the defect this work
// fixes: a sing-box gateway must not be told that xray's .dat databases are
// missing, because it never loads them.
func TestRoutingOverviewSingboxDoesNotWarnAboutDatAssets(t *testing.T) {
	svc, _ := newSplitLocal(t, "", false)
	overview, err := svc.RoutingOverview(context.Background())
	if err != nil {
		t.Fatalf("overview: %v", err)
	}
	if overview.Assets.Engine != "sing-box" {
		t.Fatalf("assets reported for engine %q", overview.Assets.Engine)
	}
	if !overview.Assets.GeoIPPresent || !overview.Assets.GeoSitePresent {
		t.Fatalf("proxy-only policy reported unusable geo assets: %+v", overview.Assets)
	}
	for _, warning := range overview.Warnings {
		if strings.Contains(warning, "geoip.dat") || strings.Contains(warning, "geosite.dat") {
			t.Fatalf("sing-box gateway warned about xray databases: %q", warning)
		}
	}
	for _, rule := range overview.Rules {
		if rule.Scope == "country-split" {
			t.Fatalf("no split is configured, but the plan contains %+v", rule)
		}
	}
	if overview.DefaultOutbound != "proxy" {
		t.Fatalf("default outbound %q, want proxy", overview.DefaultOutbound)
	}
}

// TestRoutingOverviewPredictsEngineBeforeStart covers the panel's offline
// state: with no live tunnel and no explicit preference, the overview must name
// the engine the next start will pick (the first fallback) instead of leaving
// the plan and its split warnings attributed to a blank engine.
func TestRoutingOverviewPredictsEngineBeforeStart(t *testing.T) {
	svc, _ := newSplitLocal(t, "", false)
	cfg := svc.Config()
	cfg.Engines.PreferredEngine = ""
	cfg.Engines.Fallback.Order = []string{"sing-box", "xray"}
	svc.cfg = cfg

	overview, err := svc.RoutingOverview(context.Background())
	if err != nil {
		t.Fatalf("overview: %v", err)
	}
	if overview.Engine != "sing-box" {
		t.Fatalf("engine %q, want the fallback's first entry sing-box", overview.Engine)
	}
	if overview.Assets.Engine != "sing-box" || overview.Assets.GeoIP.Format != "srs" {
		t.Fatalf("assets described for the wrong engine: %+v", overview.Assets)
	}

	preview, err := svc.PreviewRouting(context.Background(), RoutingEdit{Split: splitPtr("ir")})
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if !hasWarningContaining(preview.Warnings, "from the sing-box engine") {
		t.Fatalf("split warnings do not name the predicted engine: %v", preview.Warnings)
	}
	for _, warning := range preview.Warnings {
		if strings.Contains(warning, "the  engine") {
			t.Fatalf("warning has a blank engine name: %q", warning)
		}
	}
}

func TestRoutingOverviewSplitCoverageSingbox(t *testing.T) {
	svc, _ := newSplitLocal(t, "ir", true)
	overview, err := svc.RoutingOverview(context.Background())
	if err != nil {
		t.Fatalf("overview: %v", err)
	}
	if overview.Assets.GeoIP.Format != "srs" || overview.Assets.GeoSite.Format != "srs" {
		t.Fatalf("asset format reported for sing-box: %+v", overview.Assets)
	}
	if len(overview.Assets.GeoIP.Missing) != 0 || len(overview.Assets.GeoSite.Missing) != 0 {
		t.Fatalf("usable assets reported missing: %+v", overview.Assets)
	}
	if got := overview.Assets.GeoIP.Usable; len(got) != 1 || got[0] != "ir" {
		t.Fatalf("geoip coverage %v, want [ir]", got)
	}
	if got := overview.Assets.GeoSite.Usable; len(got) != 1 || got[0] != "ir" {
		t.Fatalf("geosite coverage %v, want [ir]", got)
	}

	var split []RoutingRuleView
	for _, rule := range overview.Rules {
		if rule.Scope == "country-split" {
			split = append(split, rule)
		}
	}
	if len(split) != 2 {
		t.Fatalf("plan has %d split rules, want 2: %+v", len(split), overview.Rules)
	}
	for _, rule := range split {
		if rule.Outbound != "direct" || rule.Effect != "DIRECT" {
			t.Fatalf("split rule %+v does not go DIRECT", rule)
		}
	}
	last := overview.Rules[len(overview.Rules)-1]
	if last.Kind != "default" || last.Outbound != "proxy" {
		t.Fatalf("catch-all is not last: %+v", last)
	}
}

func TestRoutingOverviewSplitMissingAssetsWarnsPerRule(t *testing.T) {
	svc, _ := newSplitLocal(t, "ir", false)
	overview, err := svc.RoutingOverview(context.Background())
	if err != nil {
		t.Fatalf("overview: %v", err)
	}
	if got := overview.Assets.GeoIP.Missing; len(got) != 1 || got[0] != "ir" {
		t.Fatalf("geoip missing %v, want [ir]", got)
	}
	if got := overview.Assets.GeoSite.Missing; len(got) != 1 || got[0] != "ir" {
		t.Fatalf("geosite missing %v, want [ir]", got)
	}
	if !hasWarningContaining(overview.Warnings, "inactive") {
		t.Fatalf("missing per-rule inactive warning: %v", overview.Warnings)
	}

	preview, err := svc.PreviewRouting(context.Background(), RoutingEdit{Split: splitPtr("ir")})
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if !hasWarningContaining(preview.Warnings, "Applying downloads it first") {
		t.Fatalf("preview does not explain provisioning: %v", preview.Warnings)
	}
}

func TestPreviewRoutingNormalizesAndRejectsSplit(t *testing.T) {
	svc, _ := newSplitLocal(t, "", false)
	preview, err := svc.PreviewRouting(context.Background(), RoutingEdit{Split: splitPtr(" IR ")})
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if preview.Edit.Split == nil || *preview.Edit.Split != "ir" {
		t.Fatalf("split not normalized: %+v", preview.Edit.Split)
	}

	for _, bad := range []string{"iran", "i1", "i", "ایران"} {
		if _, err := svc.PreviewRouting(context.Background(), RoutingEdit{Split: splitPtr(bad)}); err == nil {
			t.Fatalf("split %q was accepted", bad)
		} else if code := appErrorCode(t, err); code != CodeInvalid {
			t.Fatalf("split %q rejected with %s, want %s", bad, code, CodeInvalid)
		}
	}
}

// TestApplyRoutingSplitFailsClosed proves a split is never persisted when its
// assets cannot be provisioned: the policy stays proxy-only.
func TestApplyRoutingSplitFailsClosed(t *testing.T) {
	svc, p := newSplitLocal(t, "", false)
	svc.provisionGeo = func(cfg *config.Config, country, engine, geoDir, engineDir string) error {
		// A downloader that reports success but leaves the files unusable must
		// still be rejected by the post-provision check.
		writeSplitRuleSet(t, filepath.Join(geoDir, "geoip-"+country+".srs"), nil, nil, []string{"5.22.0.0/16"})
		return nil
	}

	_, err := svc.ApplyRouting(context.Background(), RoutingEdit{Split: splitPtr("ir")}, "", "")
	if err == nil {
		t.Fatal("apply succeeded without a usable geosite asset")
	}
	if code := appErrorCode(t, err); code != CodeUnavailable {
		t.Fatalf("apply failed with %s, want %s", code, CodeUnavailable)
	}
	if got := svc.Config().Routing.CountrySplit; got != "" {
		t.Fatalf("failed apply changed the split to %q", got)
	}
	if data, readErr := os.ReadFile(p.ConfigFile); readErr == nil && strings.Contains(string(data), "country_split") {
		t.Fatalf("failed apply wrote country_split to disk:\n%s", data)
	}
}

func TestApplyRoutingSplitProvisionsAndPersists(t *testing.T) {
	svc, p := newSplitLocal(t, "", false)
	svc.provisionGeo = func(cfg *config.Config, country, engine, geoDir, engineDir string) error {
		writeSplitAssets(t, geoDir, country)
		return nil
	}

	change, err := svc.ApplyRouting(context.Background(), RoutingEdit{Split: splitPtr("ir")}, "", "enable IR split")
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !change.Applied {
		t.Fatalf("apply not applied: %+v", change)
	}
	if change.Snapshot == "" {
		t.Fatal("apply did not record a rollback snapshot")
	}
	if got := svc.Config().Routing.CountrySplit; got != "ir" {
		t.Fatalf("split persisted as %q", got)
	}
	if !hasWarningContaining(change.Warnings, "IR split") {
		t.Fatalf("change does not explain the split: %v", change.Warnings)
	}
	for _, warning := range change.Warnings {
		if strings.Contains(warning, "Applying downloads it first") {
			t.Fatalf("applied change still lists a provisioning warning: %q", warning)
		}
	}

	data, err := os.ReadFile(p.ConfigFile)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(string(data), "country_split: ir") {
		t.Fatalf("config file does not carry the split:\n%s", data)
	}

	var sawSplit bool
	for _, rule := range change.Rules {
		if rule.Scope == "country-split" && rule.Outbound == "direct" {
			sawSplit = true
		}
	}
	if !sawSplit {
		t.Fatalf("applied plan has no DIRECT split rule: %+v", change.Rules)
	}
}

func TestRollbackRoutingRestoresSplit(t *testing.T) {
	svc, _ := newSplitLocal(t, "", false)
	svc.provisionGeo = func(cfg *config.Config, country, engine, geoDir, engineDir string) error {
		writeSplitAssets(t, geoDir, country)
		return nil
	}
	ctx := context.Background()

	enabled, err := svc.ApplyRouting(ctx, RoutingEdit{Split: splitPtr("ir")}, "", "enable")
	if err != nil {
		t.Fatalf("enable: %v", err)
	}
	disabled, err := svc.ApplyRouting(ctx, RoutingEdit{Split: splitPtr("")}, "", "disable")
	if err != nil {
		t.Fatalf("disable: %v", err)
	}
	if got := svc.Config().Routing.CountrySplit; got != "" {
		t.Fatalf("disable left the split at %q", got)
	}

	if _, err := svc.RollbackRouting(ctx, disabled.Snapshot); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if got := svc.Config().Routing.CountrySplit; got != "ir" {
		t.Fatalf("rollback restored split %q, want ir (enabled snapshot %s)", got, enabled.Snapshot)
	}
}

func TestExplainRouteUsesSplitRuleSets(t *testing.T) {
	svc, _ := newSplitLocal(t, "ir", true)
	ctx := context.Background()

	domain, err := svc.ExplainRoute(ctx, "www.irna.ir")
	if err != nil {
		t.Fatalf("explain domain: %v", err)
	}
	if domain.Outcome != "DIRECT" {
		t.Fatalf("split domain explained as %+v", domain)
	}
	// sing-box resolves the name before the route rules; with no connected
	// gateway the split decision is still shown, but not as a proven answer.
	if domain.DNS != "unavailable" || domain.Certain {
		t.Fatalf("split domain claimed a certain answer without a resolver: %+v", domain)
	}
	if domain.DecidedBy == nil || domain.DecidedBy.Kind != "geosite" || domain.DecidedBy.Scope != "country-split" {
		t.Fatalf("split domain decided by %+v", domain.DecidedBy)
	}

	address, err := svc.ExplainRoute(ctx, "5.22.1.9")
	if err != nil {
		t.Fatalf("explain address: %v", err)
	}
	if address.Outcome != "DIRECT" || address.Kind != "ip" {
		t.Fatalf("split address explained as %+v", address)
	}
	if address.DecidedBy == nil || address.DecidedBy.Kind != "geoip" || address.DecidedBy.Scope != "country-split" {
		t.Fatalf("split address decided by %+v", address.DecidedBy)
	}

	unmatched, err := svc.ExplainRoute(ctx, "8.8.4.4")
	if err != nil {
		t.Fatalf("explain unmatched: %v", err)
	}
	if unmatched.Outcome != "PROXY" || unmatched.DecidedBy == nil || unmatched.DecidedBy.Kind != "default" {
		t.Fatalf("unmatched address explained as %+v", unmatched.DecidedBy)
	}
}

// TestExplainRouteSplitKeywordListStaysHonest covers a rule set that carries
// entries the panel cannot evaluate: a negative answer must not be presented as
// proof that the name is absent.
func TestExplainRouteSplitKeywordListStaysHonest(t *testing.T) {
	svc, p := newSplitLocal(t, "ir", false)
	// A working resolver keeps the answer out of the "DNS unavailable" case, so
	// only the inconclusive list can make it uncertain.
	svc.runtime = &fakeRuntime{state: "CONNECTED"}
	svc.cfg.Server.DNSPort = startFakeDNS(t, net.IPv4(203, 0, 113, 9))
	writeSplitRuleSet(t, filepath.Join(p.GeoDir, "geosite-ir.srs"), nil, nil, nil)
	// A file with only IP prefixes is still complete; add a keyword entry to make
	// the domain answer inconclusive.
	set := option.PlainRuleSet{Rules: []option.HeadlessRule{{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultHeadlessRule{
			DomainKeyword: []string{"irna"},
			IPCIDR:        []string{"5.22.0.0/16"},
		},
	}}}
	file, err := os.Create(filepath.Join(p.GeoDir, "geosite-ir.srs"))
	if err != nil {
		t.Fatal(err)
	}
	if err := srs.Write(file, set, C.RuleSetVersionCurrent); err != nil {
		file.Close()
		t.Fatal(err)
	}
	file.Close()
	writeSplitRuleSet(t, filepath.Join(p.GeoDir, "geoip-ir.srs"), nil, nil, []string{"5.22.0.0/16"})

	out, err := svc.ExplainRoute(context.Background(), "other.example")
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	if out.Outcome != "PROXY" {
		t.Fatalf("unmatched domain explained as %+v", out)
	}
	var detail string
	for _, step := range out.Steps {
		if step.Label == "Published domain list: ir" {
			detail = step.Detail
		}
	}
	if !strings.Contains(detail, "cannot be checked here") {
		t.Fatalf("inconclusive list reported as %q", detail)
	}
	if out.Certain {
		t.Fatalf("an inconclusive list still produced a certain answer: %+v", out)
	}
}

// TestDownloadSplitAssetsUsesOperatorOverrides pins the two provisioning
// sources: the built-in defaults are commit-pinned, and an operator mirror is
// honoured for both families instead of being silently replaced by the default.
func TestDownloadSplitAssetsUsesOperatorOverrides(t *testing.T) {
	var requested []string
	payload := buildSplitRuleSet(t, "ir.example")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = append(requested, r.URL.Path)
		w.Write(payload)
	}))
	defer server.Close()

	dir := t.TempDir()
	cfg := &config.Config{}
	cfg.Whitelist.GeoipURL = server.URL + "/mirror/geoip-{country}.srs"
	cfg.Whitelist.GeositeURL = server.URL + "/mirror/geosite-{country}.srs"

	s := &Local{}
	if err := s.downloadSplitAssets(cfg, "ir", "sing-box", dir, dir); err != nil {
		t.Fatalf("downloadSplitAssets: %v", err)
	}
	want := map[string]bool{"/mirror/geoip-ir.srs": false, "/mirror/geosite-ir.srs": false}
	for _, path := range requested {
		if _, ok := want[path]; ok {
			want[path] = true
		}
	}
	for path, seen := range want {
		if !seen {
			t.Errorf("operator override %s was not requested (got %v)", path, requested)
		}
	}
	for _, name := range []string{"geoip-ir.srs", "geosite-ir.srs"} {
		if !geo.ValidSRSFile(filepath.Join(dir, name)) {
			t.Errorf("%s is not a loadable rule set", name)
		}
	}
}

// TestRoutingOverviewReportsDirectDNS keeps the panel honest about the split's
// DNS path: with a direct resolver configured there is no outage warning, and
// the resolver is named in the overview.
func TestRoutingOverviewReportsDirectDNS(t *testing.T) {
	svc, _ := newSplitLocal(t, "ir", true)
	cfg := svc.Config()
	cfg.Gateway.DirectDNS = "192.0.2.53"
	svc.cfg = cfg

	overview, err := svc.RoutingOverview(context.Background())
	if err != nil {
		t.Fatalf("overview: %v", err)
	}
	if overview.DirectDNS != "192.0.2.53" {
		t.Fatalf("overview direct_dns = %q", overview.DirectDNS)
	}
	if hasWarningContaining(overview.Warnings, "gateway.direct_dns") {
		t.Fatalf("configured direct resolver still warns about the outage path: %v", overview.Warnings)
	}
}

// TestRoutingOverviewWarnsSplitWithoutDirectDNS records the corrected AD-01
// claim: without gateway.direct_dns the gateway still resolves domestic names
// through the tunnel, so the panel must say they fail during an outage.
func TestRoutingOverviewWarnsSplitWithoutDirectDNS(t *testing.T) {
	svc, _ := newSplitLocal(t, "ir", true)

	overview, err := svc.RoutingOverview(context.Background())
	if err != nil {
		t.Fatalf("overview: %v", err)
	}
	if !hasWarningContaining(overview.Warnings, "gateway.direct_dns") {
		t.Fatalf("split without a direct resolver did not warn: %v", overview.Warnings)
	}
}

func buildSplitRuleSet(t *testing.T, suffix string) []byte {
	t.Helper()
	var buf bytes.Buffer
	set := option.PlainRuleSet{Rules: []option.HeadlessRule{{
		Type:           C.RuleTypeDefault,
		DefaultOptions: option.DefaultHeadlessRule{DomainSuffix: []string{suffix}},
	}}}
	if err := srs.Write(&buf, set, C.RuleSetVersionCurrent); err != nil {
		t.Fatalf("encode fixture: %v", err)
	}
	return buf.Bytes()
}

// TestApplyRoutingRefusesSplitOnXray pins the T4 gate at the write boundary:
// xray cannot route its DNS resolver through the tunnel, so the split is
// refused before any file is written rather than saved and failing at start.
func TestApplyRoutingRefusesSplitOnXray(t *testing.T) {
	svc, p := newSplitLocal(t, "", false)
	cfg := svc.Config()
	cfg.Engines.PreferredEngine = "xray"
	svc.cfg = cfg
	svc.runtime = nil

	_, err := svc.ApplyRouting(context.Background(), RoutingEdit{Split: splitPtr("ir")}, "", "test")
	appErr, ok := err.(*Error)
	if !ok || appErr.Code != CodeInvalid {
		t.Fatalf("apply error = %v, want an invalid-policy error", err)
	}
	if !strings.Contains(appErr.Message, "sing-box") {
		t.Fatalf("message does not name the required engine: %q", appErr.Message)
	}
	if got := svc.Config().Routing.CountrySplit; got != "" {
		t.Fatalf("split saved despite the refusal: %q", got)
	}
	if data, readErr := os.ReadFile(p.ConfigFile); readErr == nil && strings.Contains(string(data), "country_split") {
		t.Fatalf("refused apply wrote country_split to disk:\n%s", data)
	}
}

// TestPreviewRoutingXraySplitWarns keeps the panel ahead of the refusal: the
// preview explains that the split needs sing-box instead of promising a
// download that apply would reject.
func TestPreviewRoutingXraySplitWarns(t *testing.T) {
	svc, _ := newSplitLocal(t, "", false)
	cfg := svc.Config()
	cfg.Engines.PreferredEngine = "xray"
	svc.cfg = cfg

	preview, err := svc.PreviewRouting(context.Background(), RoutingEdit{Split: splitPtr("ir")})
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if !hasWarningContaining(preview.Warnings, "needs the sing-box engine") {
		t.Fatalf("preview does not explain the xray refusal: %v", preview.Warnings)
	}
	for _, rule := range preview.Rules {
		if rule.Scope == "country-split" && !rule.Skipped {
			t.Fatalf("preview reports an active split that apply would refuse: %+v", rule)
		}
	}
}

// TestRoutingSnapshotCarriesDirectDNS keeps rollback complete: direct_dns is a
// routing input, so it belongs to the snapshot and to the revision fingerprint.
func TestRoutingSnapshotCarriesDirectDNS(t *testing.T) {
	cfg := &config.Config{}
	cfg.Gateway.DirectDNS = "192.0.2.53"
	snap := snapshotFromConfig(cfg, "note")
	if snap.DirectDNS != "192.0.2.53" {
		t.Fatalf("snapshot direct_dns = %q", snap.DirectDNS)
	}
	other := &config.Config{}
	if routingRevision(cfg) == routingRevision(other) {
		t.Fatal("direct_dns is not part of the revision fingerprint")
	}
}
