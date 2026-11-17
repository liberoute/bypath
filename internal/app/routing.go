package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/geo"
	"github.com/liberoute/bypath/internal/tunnel"
	"gopkg.in/yaml.v3"
)

// RoutingRuleInput is one exception the panel can edit. Only matchers whose
// meaning is obvious to a non-technical operator are accepted: an exact domain,
// a domain suffix (the domain and every subdomain), or an IP range. GeoIP and
// geosite rules are shown as core policy and are never rewritten here.
type RoutingRuleInput struct {
	Match    string `json:"match"`
	Outbound string `json:"outbound"`
}

// RoutingEdit is the editable policy layer.
type RoutingEdit struct {
	// Force wins over the geo directives: the destination always uses the
	// tunnel (or is blocked).
	Force []RoutingRuleInput `json:"force"`
	// Direct wins over the default outbound but not over core DIRECT rules.
	Direct []RoutingRuleInput `json:"direct"`
	// Split is the opt-in single-country split: its geoip and geosite
	// categories go DIRECT while every unmatched destination keeps the default
	// outbound. "" disables it, a two-letter code enables it, and nil leaves the
	// current setting untouched so a profile that only edits exceptions cannot
	// switch a split off by accident.
	Split *string `json:"split,omitempty"`
}

// RoutingRuleView is one effective rule rendered for display.
type RoutingRuleView struct {
	Position int    `json:"position"`
	Scope    string `json:"scope"`
	Source   string `json:"source"`
	Kind     string `json:"kind"`
	Match    string `json:"match"`
	Outbound string `json:"outbound"`
	Effect   string `json:"effect"`
	Note     string `json:"note,omitempty"`
	Skipped  bool   `json:"skipped,omitempty"`
}

// GeoAssetCoverage reports whether the running engine can satisfy one matcher
// family. Requested lists the categories the policy references, Usable those
// backed by a loadable asset, and Missing the ones that are not. It is computed
// from the same plan the generator uses, so it cannot promise coverage the
// engine would not get.
type GeoAssetCoverage struct {
	Kind      string   `json:"kind"`   // geoip or geosite
	Format    string   `json:"format"` // srs (sing-box) or dat (xray)
	Requested []string `json:"requested"`
	Usable    []string `json:"usable"`
	Missing   []string `json:"missing"`
	Paths     []string `json:"paths,omitempty"`
}

// RoutingAssets reports which geo databases back the geo rules for the engine
// that is actually running. GeoIPPresent/GeoSitePresent mean "every category
// this policy requests is usable" — not "a .dat file exists" — so an unused or
// different engine's database never produces a false warning.
type RoutingAssets struct {
	Engine         string           `json:"engine"`
	GeoIPPath      string           `json:"geoip_path,omitempty"`
	GeoSitePath    string           `json:"geosite_path,omitempty"`
	GeoIPPresent   bool             `json:"geoip_present"`
	GeoSitePresent bool             `json:"geosite_present"`
	GeoIP          GeoAssetCoverage `json:"geoip"`
	GeoSite        GeoAssetCoverage `json:"geosite"`
	// Provenance describes the installed files that back the plan: source URL,
	// SHA-256 and fetch time. Empty when the asset was not installed by bypath.
	Provenance []GeoAssetProvenance `json:"provenance,omitempty"`
	// GeoDir is the rule-set directory; it is a host path and stays internal.
	GeoDir string `json:"-"`
}

// LocalDNSView is one local DNS suffix group, shown read-only.
type LocalDNSView struct {
	Server  string   `json:"server"`
	Domains []string `json:"domains"`
}

// LegacyRoutingView reports whitelist fields that are ignored or in use.
type LegacyRoutingView struct {
	Present           bool     `json:"present"`
	Ignored           bool     `json:"ignored"`
	Countries         []string `json:"countries,omitempty"`
	BypassDomains     []string `json:"bypass_domains,omitempty"`
	ForceProxyDomains []string `json:"force_proxy_domains,omitempty"`
	GeositeCountries  []string `json:"geosite_countries,omitempty"`
}

// RoutingProfile is a named, reviewed compatibility policy.
type RoutingProfile struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Status      string       `json:"status"` // active, available, review
	Verified    string       `json:"verified,omitempty"`
	Enabled     bool         `json:"enabled"`
	Edit        *RoutingEdit `json:"edit,omitempty"`
	Warnings    []string     `json:"warnings,omitempty"`
}

// RoutingSnapshotView is one rollback point. The contents stay on the host.
type RoutingSnapshotView struct {
	ID      string `json:"id"`
	Created string `json:"created"`
	Note    string `json:"note"`
	Rules   int    `json:"rules"`
}

// RoutingOverview is the whole routing screen in one response.
type RoutingOverview struct {
	Revision         string                `json:"revision"`
	Mode             string                `json:"mode"` // rules or legacy
	Engine           string                `json:"engine,omitempty"`
	DefaultOutbound  string                `json:"default_outbound"`
	DNSMode          string                `json:"dns_mode"`
	DirectDNS        string                `json:"direct_dns,omitempty"`
	RestartRequired  bool                  `json:"restart_required,omitempty"`
	PendingRestart   []string              `json:"pending_restart,omitempty"`
	GatewayConnected bool                  `json:"gateway_connected"`
	CanEdit          bool                  `json:"can_edit"`
	CanEditReason    string                `json:"can_edit_reason,omitempty"`
	Rules            []RoutingRuleView     `json:"rules"`
	Edit             RoutingEdit           `json:"edit"`
	Warnings         []string              `json:"warnings"`
	Assets           RoutingAssets         `json:"assets"`
	LocalDNS         []LocalDNSView        `json:"local_dns"`
	Legacy           LegacyRoutingView     `json:"legacy"`
	Profiles         []RoutingProfile      `json:"profiles"`
	Snapshots        []RoutingSnapshotView `json:"snapshots"`
}

// RoutingPreview is a composed, validated candidate. It never touches the host.
type RoutingPreview struct {
	Revision        string            `json:"revision"`
	DefaultOutbound string            `json:"default_outbound"`
	Rules           []RoutingRuleView `json:"rules"`
	Edit            RoutingEdit       `json:"edit"`
	Warnings        []string          `json:"warnings"`
	Summary         []string          `json:"summary"`
}

// RoutingChange reports what an apply actually did.
type RoutingChange struct {
	Applied         bool              `json:"applied"`
	RestartRequired bool              `json:"restart_required"`
	Message         string            `json:"message"`
	Revision        string            `json:"revision"`
	Snapshot        string            `json:"snapshot,omitempty"`
	Rules           []RoutingRuleView `json:"rules"`
	Warnings        []string          `json:"warnings,omitempty"`
}

// RoutingOverview builds the policy view from persisted configuration. It reads
// the installed geo databases to report which rules can actually run.
func (s *Local) RoutingOverview(ctx context.Context) (RoutingOverview, error) {
	cfg := s.Config()
	engine := s.routingEngine()
	plan := s.routingPlan(cfg, engine)
	out := RoutingOverview{
		Revision:         routingRevision(cfg),
		Mode:             routingMode(cfg),
		Engine:           engine,
		DNSMode:          effectiveDNSMode(cfg),
		DirectDNS:        strings.TrimSpace(cfg.Gateway.DirectDNS),
		Rules:            routingRuleViews(plan),
		Edit:             editableFromRules(cfg),
		Profiles:         routingProfiles(cfg),
		Snapshots:        s.listRoutingSnapshots(),
		Legacy:           legacyView(cfg),
		LocalDNS:         localDNSViews(cfg),
		CanEdit:          routingMode(cfg) == "rules",
		GatewayConnected: s.gatewayConnected(),
	}
	if !out.CanEdit {
		out.CanEditReason = "This gateway uses the legacy whitelist (whitelist.*). Migrate it to routing.rules before editing exceptions here; the panel never rewrites legacy policy silently."
	}
	out.DefaultOutbound = defaultOutbound(plan)
	out.Assets = s.routingAssets(engine, cfg)
	out.PendingRestart = s.pendingRestartFields()
	out.RestartRequired = len(out.PendingRestart) > 0
	out.Warnings = routingWarnings(cfg, plan)
	if out.RestartRequired {
		out.Warnings = append([]string{"The saved configuration is not live yet: the running tunnel still uses the previous rules until it is restarted (pending: " + strings.Join(out.PendingRestart, ", ") + ")."}, out.Warnings...)
	}
	return out, nil
}

func routingMode(cfg *config.Config) string {
	if len(cfg.Routing.Rules) > 0 {
		return "rules"
	}
	return "legacy"
}

func effectiveDNSMode(cfg *config.Config) string {
	if cfg.Gateway.DNSMode == "" {
		return "strict"
	}
	return cfg.Gateway.DNSMode
}

func (s *Local) gatewayConnected() bool {
	if s.runtime == nil {
		return false
	}
	return s.runtime.Status().State == "CONNECTED"
}

// markPendingRestart records saved fields the running engine has not loaded.
func (s *Local) markPendingRestart(fields []string) {
	s.mu.Lock()
	seen := map[string]bool{}
	for _, field := range s.pendingRestart {
		seen[field] = true
	}
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" || seen[field] {
			continue
		}
		seen[field] = true
		s.pendingRestart = append(s.pendingRestart, field)
	}
	s.mu.Unlock()
}

// clearPendingRestart is called once a restart has loaded the saved config.
func (s *Local) clearPendingRestart() {
	s.mu.Lock()
	s.pendingRestart = nil
	s.mu.Unlock()
}

func (s *Local) pendingRestartFields() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.pendingRestart) == 0 {
		return nil
	}
	return append([]string(nil), s.pendingRestart...)
}

// routingEngine names the engine that will evaluate routing. A running tunnel
// reports the engine it actually started; otherwise the configured preference
// and then the fallback order predict what the next start will pick, so the
// panel never describes the policy against a blank engine name.
func (s *Local) routingEngine() string {
	if s.runtime != nil {
		if rs := s.runtime.Status(); rs.Engine != "" {
			return rs.Engine
		}
	}
	cfg := s.Config()
	if preferred := strings.TrimSpace(cfg.Engines.PreferredEngine); preferred != "" {
		return preferred
	}
	for _, candidate := range cfg.Engines.Fallback.Order {
		if trimmed := strings.TrimSpace(candidate); trimmed != "" {
			return trimmed
		}
	}
	return "sing-box"
}

// routingPlan builds the same ordered plan the named engine's generator emits.
// The generator in internal/tunnel owns the order; this function only maps the
// persisted configuration onto it.
func (s *Local) routingPlan(cfg *config.Config, engine string) []tunnel.PlanEntry {
	geoDir, engineDir := "", ""
	if s.paths != nil {
		geoDir, engineDir = s.paths.GeoDir, s.paths.EngineDir
	}
	cg := &tunnel.ConfigGenerator{
		CountrySplit: cfg.Routing.CountrySplit,
		GeoDir:       geoDir,
		EngineDir:    engineDir,
	}
	if len(cfg.Routing.Rules) > 0 {
		rules := make([]tunnel.RoutingRule, len(cfg.Routing.Rules))
		for i, r := range cfg.Routing.Rules {
			rules[i] = tunnel.RoutingRule{Match: r.Match, Outbound: r.Outbound}
		}
		cg.RoutingRules = rules
		cg.ExternalOutbounds = cfg.Routing.ExternalOutbounds
	} else {
		cg.WhitelistCountries = cfg.Whitelist.Countries
		cg.GeositeCountries = cfg.Whitelist.GeositeCountries
		if len(cg.GeositeCountries) == 0 {
			cg.GeositeCountries = cfg.Whitelist.Countries
		}
		cg.BypassDomains = cfg.Whitelist.BypassDomains
		cg.ForceProxyDomains = cfg.Whitelist.ForceProxyDomains
	}
	for _, entry := range cfg.Gateway.LocalDNS {
		if entry.Server != "" && len(entry.Domains) > 0 {
			cg.LocalDNSRules = append(cg.LocalDNSRules, tunnel.LocalDNSRule{Server: entry.Server, Domains: entry.Domains})
		}
	}
	return cg.RoutingPlan(engine)
}

func routingRuleViews(plan []tunnel.PlanEntry) []RoutingRuleView {
	out := make([]RoutingRuleView, 0, len(plan))
	for i, entry := range plan {
		view := RoutingRuleView{
			Position: i + 1,
			Scope:    planEntryScope(entry),
			Kind:     entry.Kind,
			Source:   scopeLabel(planEntryScope(entry)),
			Match:    entryMatchLabel(entry),
			Outbound: tunnel.EffectiveOutbound(entry.Outbound),
			Effect:   strings.ToUpper(tunnel.EffectiveOutbound(entry.Outbound)),
		}
		if entry.Skip != "" {
			view.Skipped = true
			view.Note = "Not active: " + entry.Skip
			view.Effect = "INACTIVE"
		}
		out = append(out, view)
	}
	return out
}

// planEntryScope names where an entry comes from. A catch-all default is the
// default policy wherever it was declared, so it must not be labelled as an
// exception just because the operator wrote it in routing.rules.
func planEntryScope(entry tunnel.PlanEntry) string {
	if entry.Kind == "default" {
		return "default"
	}
	return entry.Scope
}

func scopeLabel(scope string) string {
	switch scope {
	case "builtin":
		return "Built-in safety rule"
	case "probe":
		return "Startup health check"
	case "local-dns":
		return "Local network DNS"
	case "force-proxy":
		return "Legacy force-proxy domain"
	case "bypass":
		return "Legacy bypass domain"
	case "country":
		return "Legacy whitelisted country"
	case "country-split":
		return "Country split policy"
	case "rule":
		return "Your exception"
	default:
		return "Default policy"
	}
}

func entryMatchLabel(entry tunnel.PlanEntry) string {
	switch entry.Kind {
	case "private":
		return "Private and loopback addresses"
	case "domain_suffix_list":
		return "Domain suffix: " + strings.Join(entry.Domains, ", ")
	case "geoip":
		return "IP addresses in country: " + entry.Value
	case "geosite":
		return "Published domain list: " + entry.Value
	case "domain":
		return "Exact domain: " + entry.Value
	case "domain_suffix":
		return "Domain suffix: " + entry.Value
	case "ip_cidr":
		return "IP range: " + entry.Value
	case "default":
		return "Everything not matched above"
	case "unsupported":
		return "Unsupported rule: " + entry.Value
	default:
		return entry.Kind
	}
}

func defaultOutbound(plan []tunnel.PlanEntry) string {
	for i := len(plan) - 1; i >= 0; i-- {
		if plan[i].Kind == "default" {
			return tunnel.EffectiveOutbound(plan[i].Outbound)
		}
	}
	return "proxy"
}

// defaultPlanEntry returns the catch-all entry and its 1-based position so the
// explainer can cite the rule the engine actually falls through to.
func defaultPlanEntry(plan []tunnel.PlanEntry) (tunnel.PlanEntry, int, bool) {
	for i := len(plan) - 1; i >= 0; i-- {
		if plan[i].Kind == "default" {
			return plan[i], i + 1, true
		}
	}
	return tunnel.PlanEntry{}, 0, false
}

// routingAssets reports geo coverage for the engine that will evaluate the
// policy. The coverage is derived from the plan, so the panel describes exactly
// the rules the engine can run: sing-box loads per-country .srs rule sets while
// xray reads the .dat category databases.
func (s *Local) routingAssets(engine string, cfg *config.Config) RoutingAssets {
	assets := RoutingAssets{
		Engine: strings.ToLower(strings.TrimSpace(engine)),
		GeoIP:  GeoAssetCoverage{Kind: "geoip"},
		GeoSite: GeoAssetCoverage{
			Kind: "geosite",
		},
	}
	if s.paths != nil {
		assets.GeoDir = s.paths.GeoDir
	}
	xray := assets.Engine == "xray"
	if xray {
		assets.GeoIP.Format = "dat"
		assets.GeoSite.Format = "dat"
		assets.GeoIPPath = s.geoAsset("geoip.dat")
		assets.GeoSitePath = s.geoAsset("geosite.dat")
	} else {
		assets.GeoIP.Format = "srs"
		assets.GeoSite.Format = "srs"
	}
	for _, entry := range s.routingPlan(cfg, engine) {
		var coverage *GeoAssetCoverage
		switch entry.Kind {
		case "geoip":
			coverage = &assets.GeoIP
		case "geosite":
			coverage = &assets.GeoSite
		default:
			continue
		}
		coverage.Requested = appendUnique(coverage.Requested, entry.Value)
		if entry.Skip != "" {
			coverage.Missing = appendUnique(coverage.Missing, entry.Value)
			continue
		}
		coverage.Usable = appendUnique(coverage.Usable, entry.Value)
		if path := geoAssetForEntry(assets, entry); path != "" {
			coverage.Paths = appendUnique(coverage.Paths, path)
		}
	}
	assets.GeoIPPresent = len(assets.GeoIP.Missing) == 0
	assets.GeoSitePresent = len(assets.GeoSite.Missing) == 0
	assets.Provenance = assetProvenance(append(append([]string{}, assets.GeoIP.Paths...), assets.GeoSite.Paths...))
	return assets
}

// GeoAssetProvenance is the recorded origin of one installed geo asset.
type GeoAssetProvenance struct {
	Name      string `json:"name"`
	SourceURL string `json:"source_url"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
	FetchedAt string `json:"fetched_at"`
}

func assetProvenance(paths []string) []GeoAssetProvenance {
	var out []GeoAssetProvenance
	seen := map[string]bool{}
	for _, path := range paths {
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true
		record, err := geo.ReadProvenance(path)
		if err != nil {
			continue
		}
		out = append(out, GeoAssetProvenance{
			Name:      filepath.Base(path),
			SourceURL: record.SourceURL,
			SHA256:    record.SHA256,
			Size:      record.Size,
			FetchedAt: record.FetchedAt.UTC().Format(time.RFC3339),
		})
	}
	return out
}

// geoAssetForEntry resolves the file that backs one geo plan entry.
func geoAssetForEntry(assets RoutingAssets, entry tunnel.PlanEntry) string {
	if assets.Engine == "xray" {
		if entry.Kind == "geoip" {
			return assets.GeoIPPath
		}
		return assets.GeoSitePath
	}
	if assets.GeoDir == "" {
		return ""
	}
	return filepath.Join(assets.GeoDir, entry.Kind+"-"+entry.Value+".srs")
}

func appendUnique(list []string, value string) []string {
	for _, have := range list {
		if have == value {
			return list
		}
	}
	return append(list, value)
}

// ensureSplitAssets provisions the geo databases the opt-in split needs for the
// engine that will run it. It runs before the config write and refuses the
// change when an asset cannot be obtained, so the split is never saved with
// rules the engine would skip.
func (s *Local) ensureSplitAssets(cfg *config.Config, country, engine string) error {
	geoDir, engineDir := "", ""
	if s.paths != nil {
		geoDir, engineDir = s.paths.GeoDir, s.paths.EngineDir
	}
	if geoDir == "" {
		return errorf(CodeUnavailable, "the geo directory is not configured, so the %s split cannot be prepared", strings.ToUpper(country))
	}
	if splitAssetsUsable(country, engine, geoDir, engineDir) {
		return nil
	}
	var err error
	if s.provisionGeo != nil {
		err = s.provisionGeo(cfg, country, engine, geoDir, engineDir)
	} else {
		err = s.downloadSplitAssets(cfg, country, engine, geoDir, engineDir)
	}
	if splitAssetsUsable(country, engine, geoDir, engineDir) {
		return nil
	}
	detail := "the download did not produce a usable database"
	if err != nil {
		detail = Redact(err.Error())
	}
	hint := "check the gateway's internet access and retry; 'bypath geo update' performs the same download. The routing policy was not changed."
	if strings.EqualFold(engine, "xray") {
		hint = "check the gateway's internet access and retry; 'bypath geo update' performs the same download. If an older database is installed in the engine directory, refresh or remove it. The routing policy was not changed."
	}
	return &Error{
		Code:    CodeUnavailable,
		Message: "cannot enable the " + strings.ToUpper(country) + " split: the " + strings.ToLower(engine) + " geo databases do not cover this country (" + detail + ")",
		Hint:    hint,
	}
}

// splitAssetsUsable reports whether the engine can load both categories.
func splitAssetsUsable(country, engine, geoDir, engineDir string) bool {
	if strings.EqualFold(engine, "xray") {
		category := strings.ToUpper(country)
		ipPath := findXrayAsset("geoip.dat", engineDir, geoDir)
		sitePath := findXrayAsset("geosite.dat", engineDir, geoDir)
		if ipPath == "" || sitePath == "" {
			return false
		}
		_, siteOK := geo.FindXrayCategory(sitePath, country)
		return geo.HasXrayCategory(ipPath, category) && siteOK
	}
	return geo.ValidSRSFile(filepath.Join(geoDir, "geoip-"+country+".srs")) &&
		geo.ValidSRSFile(filepath.Join(geoDir, "geosite-"+country+".srs"))
}

// downloadSplitAssets provisions the missing files from the pinned sources.
func (s *Local) downloadSplitAssets(cfg *config.Config, country, engine, geoDir, engineDir string) error {
	if strings.EqualFold(engine, "xray") {
		dir := geoDir
		if findXrayAsset("geoip.dat", engineDir) != "" || findXrayAsset("geosite.dat", engineDir) != "" {
			dir = engineDir
		}
		return geo.DownloadXrayGeoFiles(dir, 0)
	}
	var firstErr error
	if !geo.ValidSRSFile(filepath.Join(geoDir, "geoip-"+country+".srs")) {
		template := strings.TrimSpace(cfg.Whitelist.GeoipURL)
		if template == "" {
			template = geo.GeoipSRSURL
		}
		if err := geo.DownloadGeoipFiles(template, []string{country}, geoDir, 0); err != nil {
			firstErr = err
		}
	}
	if !geo.ValidSRSFile(filepath.Join(geoDir, "geosite-"+country+".srs")) {
		template := strings.TrimSpace(cfg.Whitelist.GeositeURL)
		if template == "" {
			template = geo.GeositeSRSURL
		}
		if err := geo.DownloadGeositeFiles(template, []string{country}, geoDir, 0); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// findXrayAsset returns the first loadable database with this name.
func findXrayAsset(name string, dirs ...string) string {
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		if path := geo.FindXrayAsset(dir, name); path != "" {
			return path
		}
	}
	return ""
}

func (s *Local) geoAsset(name string) string {
	dirs := []string{}
	if s.paths != nil {
		dirs = append(dirs, s.paths.EngineDir, s.paths.GeoDir)
	}
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		if p := geo.FindXrayAsset(dir, name); p != "" {
			return p
		}
	}
	return ""
}

func legacyView(cfg *config.Config) LegacyRoutingView {
	view := LegacyRoutingView{
		Countries:         append([]string(nil), cfg.Whitelist.Countries...),
		BypassDomains:     append([]string(nil), cfg.Whitelist.BypassDomains...),
		ForceProxyDomains: append([]string(nil), cfg.Whitelist.ForceProxyDomains...),
		GeositeCountries:  append([]string(nil), cfg.Whitelist.GeositeCountries...),
	}
	view.Present = len(view.Countries) > 0 || len(view.BypassDomains) > 0 || len(view.ForceProxyDomains) > 0 || len(view.GeositeCountries) > 0
	view.Ignored = view.Present && len(cfg.Routing.Rules) > 0
	return view
}

func localDNSViews(cfg *config.Config) []LocalDNSView {
	out := make([]LocalDNSView, 0, len(cfg.Gateway.LocalDNS))
	for _, entry := range cfg.Gateway.LocalDNS {
		out = append(out, LocalDNSView{Server: entry.Server, Domains: append([]string(nil), entry.Domains...)})
	}
	return out
}

// routingWarnings reports conditions that change what the policy actually does.
// Missing geo coverage is already reported per rule (the rule view is marked
// inactive), so this function never emits a blanket warning about a database
// the running engine does not use.
func routingWarnings(cfg *config.Config, plan []tunnel.PlanEntry) []string {
	var warnings []string
	if len(cfg.Routing.Rules) == 0 {
		warnings = append(warnings, "This gateway uses the legacy whitelist policy. Rules are still shown, but exceptions can only be edited after migrating to routing.rules.")
	} else if legacyView(cfg).Present {
		warnings = append(warnings, "whitelist.* entries are present but ignored because routing.rules exists. They have no effect on traffic.")
	}
	if strings.EqualFold(cfg.Gateway.DNSMode, "local") {
		warnings = append(warnings, "DNS mode is \"local\": lookups may leave through the local ISP resolver instead of the tunnel when the tunnel DNS is unavailable.")
	}
	if cfg.Routing.CountrySplit != "" && strings.TrimSpace(cfg.Gateway.DirectDNS) == "" {
		warnings = append(warnings, "The "+strings.ToUpper(cfg.Routing.CountrySplit)+" split has no gateway.direct_dns: the gateway resolves domestic names through the tunnel, so they stop resolving while the tunnel is down. Set gateway.direct_dns to a trusted resolver reachable without the tunnel.")
	}
	if strings.EqualFold(tunnel.EffectiveOutbound(defaultOutbound(plan)), "block") {
		warnings = append(warnings, "The default outbound is BLOCK: unmatched traffic is dropped rather than proxied.")
	}
	for _, entry := range plan {
		if entry.Skip != "" {
			warnings = append(warnings, entryMatchLabel(entry)+" is inactive: "+entry.Skip+".")
		}
	}
	return warnings
}

// editableFromRules splits the current rules into the two editable groups and
// keeps everything else (geo rules, external outbounds) as fixed core policy.
func editableFromRules(cfg *config.Config) RoutingEdit {
	var edit RoutingEdit
	for _, rule := range cfg.Routing.Rules {
		outbound := strings.ToLower(strings.TrimSpace(rule.Outbound))
		if !isEditableMatcher(rule.Match) || !isEditableOutbound(outbound) {
			continue
		}
		if outbound == "direct" {
			edit.Direct = append(edit.Direct, RoutingRuleInput{Match: rule.Match, Outbound: "direct"})
		} else {
			edit.Force = append(edit.Force, RoutingRuleInput{Match: rule.Match, Outbound: outbound})
		}
	}
	split := cfg.Routing.CountrySplit
	edit.Split = &split
	return edit
}

func isEditableMatcher(match string) bool {
	typ, _, _ := strings.Cut(strings.TrimSpace(match), ":")
	switch typ {
	case "domain", "domain_suffix", "ip_cidr":
		return true
	}
	return false
}

func isEditableOutbound(outbound string) bool {
	switch outbound {
	case "direct", "proxy", "deny", "block", "reject":
		return true
	}
	return false
}

// composeRules rebuilds routing.rules from the editable layer while preserving
// the fixed core rules in their original order:
//
//	force exceptions → fixed rules (geo, external outbounds) → direct exceptions → default
//
// Force exceptions must precede geo DIRECT rules to win over them. Direct
// exceptions must follow geo DIRECT rules (which already send that traffic
// direct) but precede the default, so they still bypass a proxy default.
func composeRules(current []config.RoutingRule, edit RoutingEdit) []config.RoutingRule {
	var core []config.RoutingRule
	var defaultRule *config.RoutingRule
	for i := range current {
		rule := current[i]
		if strings.TrimSpace(rule.Match) == "default" {
			r := rule
			defaultRule = &r
			continue
		}
		if isEditableMatcher(rule.Match) && isEditableOutbound(strings.ToLower(strings.TrimSpace(rule.Outbound))) {
			continue
		}
		core = append(core, rule)
	}
	out := make([]config.RoutingRule, 0, len(edit.Force)+len(core)+len(edit.Direct)+1)
	for _, rule := range edit.Force {
		out = append(out, config.RoutingRule{Match: normalizeMatcher(rule.Match), Outbound: normalizeOutbound(rule.Outbound)})
	}
	out = append(out, core...)
	for _, rule := range edit.Direct {
		out = append(out, config.RoutingRule{Match: normalizeMatcher(rule.Match), Outbound: "direct"})
	}
	if defaultRule != nil {
		out = append(out, *defaultRule)
	}
	return out
}

func normalizeMatcher(match string) string {
	typ, value, ok := strings.Cut(strings.TrimSpace(match), ":")
	if !ok {
		return strings.TrimSpace(match)
	}
	value = strings.TrimSpace(value)
	if typ == "domain_suffix" {
		value = strings.TrimPrefix(value, ".")
	}
	return typ + ":" + value
}

func normalizeOutbound(outbound string) string {
	outbound = strings.ToLower(strings.TrimSpace(outbound))
	if outbound == "" {
		return "proxy"
	}
	return outbound
}

// validateEdit guards the two exception groups before they touch the config.
func validateEdit(edit RoutingEdit) error {
	seen := map[string]string{}
	check := func(group string, rules []RoutingRuleInput, allowForce bool) error {
		for _, rule := range rules {
			match := normalizeMatcher(rule.Match)
			typ, value, ok := strings.Cut(match, ":")
			if !ok || strings.TrimSpace(value) == "" {
				return errorf(CodeInvalid, "%s rule %q must look like domain:example.com, domain_suffix:example.com or ip_cidr:203.0.113.0/24", group, match)
			}
			switch typ {
			case "domain":
				if strings.HasPrefix(value, ".") || strings.ContainsAny(value, " \t\r\n\x00/") {
					return errorf(CodeInvalid, "%s rule %q: an exact domain must not start with a dot or contain separators; use domain_suffix for a whole suffix", group, match)
				}
			case "domain_suffix":
				if value == "" || strings.ContainsAny(value, " \t\r\n\x00/") {
					return errorf(CodeInvalid, "%s rule %q: a domain suffix must be a domain such as example.com", group, match)
				}
			case "ip_cidr":
				if _, _, err := net.ParseCIDR(value); err != nil {
					return errorf(CodeInvalid, "%s rule %q: %q is not an IP range (CIDR)", group, match, value)
				}
			default:
				return errorf(CodeInvalid, "%s rule %q: only domain, domain_suffix and ip_cidr rules can be edited here", group, match)
			}
			outbound := normalizeOutbound(rule.Outbound)
			if allowForce {
				if outbound != "proxy" && !isDenyName(outbound) {
					return errorf(CodeInvalid, "%s rule %q: the action must be PROXY or BLOCK", group, match)
				}
			} else if outbound != "direct" {
				return errorf(CodeInvalid, "%s rule %q: the direct list can only contain DIRECT rules", group, match)
			}
			key := typ + ":" + strings.ToLower(value)
			if previous, exists := seen[key]; exists {
				if previous != outbound {
					return errorf(CodeInvalid, "%s rule %q is already present with a different action (the first one wins in the engine, so the second would never apply)", group, match)
				}
				return errorf(CodeInvalid, "%s rule %q is listed twice", group, match)
			}
			seen[key] = outbound
		}
		return nil
	}
	if err := check("force", edit.Force, true); err != nil {
		return err
	}
	return check("direct", edit.Direct, false)
}

func isDenyName(outbound string) bool {
	switch outbound {
	case "deny", "block", "reject":
		return true
	}
	return false
}

// candidateConfig applies an edit to a deep copy of the current configuration.
func candidateConfig(cfg *config.Config, edit RoutingEdit) (*config.Config, []string, error) {
	if routingMode(cfg) != "rules" {
		return nil, nil, errorf(CodeInvalid, "this gateway uses the legacy whitelist; migrate it to routing.rules before editing exceptions")
	}
	if err := validateEdit(edit); err != nil {
		return nil, nil, err
	}
	split := cfg.Routing.CountrySplit
	if edit.Split != nil {
		split = strings.ToLower(strings.TrimSpace(*edit.Split))
		if split != "" && !isCountryCode(split) {
			return nil, nil, errorf(CodeInvalid, "the country split must be a two-letter code such as \"ir\", or empty to turn it off")
		}
	}
	work := *cfg
	work.Routing = cfg.Routing
	work.Routing.CountrySplit = split
	work.Routing.Rules = composeRules(cfg.Routing.Rules, edit)
	work.Whitelist = cfg.Whitelist
	work.Gateway = cfg.Gateway
	work.Gateway.LocalDNS = append([]config.LocalDNSEntry(nil), cfg.Gateway.LocalDNS...)

	if err := validateConfigDocument(&work); err != nil {
		return nil, nil, err
	}
	warnings := editWarnings(edit)
	if split != "" {
		warnings = append(warnings, "The "+strings.ToUpper(split)+" split sends every site and address in the "+strings.ToUpper(split)+" geo lists DIRECT: this gateway's address is visible to them instead of the tunnel exit. Everything unmatched keeps the default outbound.")
	}
	return &work, warnings, nil
}

// isCountryCode accepts only a lowercase ISO 3166-1 alpha-2 code. The value
// names geoip/geosite categories and is joined into rule-set file names.
func isCountryCode(v string) bool {
	if len(v) != 2 {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 'a' || v[i] > 'z' {
			return false
		}
	}
	return true
}

// validateConfigDocument round-trips through the same parser the daemon uses on
// startup, so an accepted edit can never produce a config the next start
// rejects.
func validateConfigDocument(cfg *config.Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return asAppError(err, CodeInternal, "encoding candidate configuration")
	}
	parsed, err := config.Parse(data)
	if err != nil {
		return errorf(CodeInvalid, "the edited rules are not valid: %v", err)
	}
	if err := parsed.NormalizeAndValidate(); err != nil {
		return errorf(CodeInvalid, "the edited rules are not valid: %v", err)
	}
	return nil
}

func editWarnings(edit RoutingEdit) []string {
	var warnings []string
	var directSuffixes []string
	for _, rule := range edit.Direct {
		typ, value, _ := strings.Cut(normalizeMatcher(rule.Match), ":")
		value = strings.ToLower(strings.TrimSpace(value))
		if typ == "ip_cidr" {
			warnings = append(warnings, rule.Match+" goes DIRECT: traffic to this range leaves from this gateway's own address, not through the tunnel.")
			continue
		}
		if typ == "domain" || typ == "domain_suffix" {
			directSuffixes = append(directSuffixes, strings.TrimPrefix(value, "."))
		}
		warnings = append(warnings, rule.Match+" goes DIRECT: anyone watching this network can see that traffic and the destination sees this gateway's address, not the tunnel exit.")
	}
	for _, rule := range edit.Force {
		typ, value, _ := strings.Cut(normalizeMatcher(rule.Match), ":")
		if typ != "domain_suffix" && typ != "domain" {
			continue
		}
		suffix := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(value)), ".")
		if overlapsDirectSuffix(suffix, directSuffixes) {
			warnings = append(warnings, rule.Match+" goes through the tunnel although another rule in this edit sends an overlapping domain direct; sites that expect a local address may block or throttle connections that arrive from a foreign exit.")
		}
	}
	return warnings
}

func overlapsDirectSuffix(suffix string, direct []string) bool {
	for _, other := range direct {
		if other == "" {
			continue
		}
		if suffix == other || strings.HasSuffix(suffix, "."+other) || strings.HasSuffix(other, "."+suffix) {
			return true
		}
	}
	return false
}

// PreviewRouting composes and validates an edit without touching the host.
func (s *Local) PreviewRouting(ctx context.Context, edit RoutingEdit) (RoutingPreview, error) {
	cfg := s.Config()
	if routingMode(cfg) != "rules" {
		return RoutingPreview{}, errorf(CodeInvalid, "this gateway uses the legacy whitelist; exceptions can only be edited after migrating to routing.rules")
	}
	candidate, warnings, err := candidateConfig(cfg, edit)
	if err != nil {
		return RoutingPreview{}, err
	}
	engine := s.routingEngine()
	plan := s.routingPlan(candidate, engine)
	warnings = append(warnings, splitAssetWarnings(engine, candidate.Routing.CountrySplit, plan)...)
	return RoutingPreview{
		Revision:        routingRevision(cfg),
		DefaultOutbound: defaultOutbound(plan),
		Rules:           routingRuleViews(plan),
		Edit:            sanitizeEdit(edit),
		Warnings:        warnings,
		Summary:         routingSummary(plan),
	}, nil
}

// splitAssetWarnings tells the operator what the split still needs. Applying
// downloads missing assets first and refuses the change if they cannot be
// obtained, so a split can never be enabled with inactive rules. xray cannot
// run the split at all, so that refusal is reported before any download.
func splitAssetWarnings(engine, country string, plan []tunnel.PlanEntry) []string {
	if country == "" {
		return nil
	}
	if strings.EqualFold(engine, "xray") {
		return []string{"The " + strings.ToUpper(country) + " split needs the sing-box engine: xray cannot route its DNS resolver through the tunnel. Applying is refused; select sing-box or turn the split off."}
	}
	var warnings []string
	for _, entry := range plan {
		if entry.Scope != "country-split" || entry.Skip == "" {
			continue
		}
		warnings = append(warnings, "The "+strings.ToUpper(country)+" split needs "+entryMatchLabel(entry)+" from the "+engine+" engine: "+entry.Skip+". Applying downloads it first; if that fails, the policy is left unchanged.")
	}
	return warnings
}

func sanitizeEdit(edit RoutingEdit) RoutingEdit {
	out := RoutingEdit{}
	for _, rule := range edit.Force {
		out.Force = append(out.Force, RoutingRuleInput{Match: normalizeMatcher(rule.Match), Outbound: normalizeOutbound(rule.Outbound)})
	}
	for _, rule := range edit.Direct {
		out.Direct = append(out.Direct, RoutingRuleInput{Match: normalizeMatcher(rule.Match), Outbound: "direct"})
	}
	if edit.Split != nil {
		split := strings.ToLower(strings.TrimSpace(*edit.Split))
		out.Split = &split
	}
	if out.Force == nil {
		out.Force = []RoutingRuleInput{}
	}
	if out.Direct == nil {
		out.Direct = []RoutingRuleInput{}
	}
	return out
}

func routingSummary(plan []tunnel.PlanEntry) []string {
	var summary []string
	for _, entry := range plan {
		if entry.Kind == "default" {
			continue
		}
		label := entryMatchLabel(entry)
		if entry.Skip != "" {
			summary = append(summary, label+" → inactive ("+entry.Skip+")")
			continue
		}
		summary = append(summary, label+" → "+strings.ToUpper(tunnel.EffectiveOutbound(entry.Outbound)))
	}
	summary = append(summary, "Everything else → "+strings.ToUpper(defaultOutbound(plan)))
	return summary
}

// routingRevision fingerprints every routing input. An apply must present the
// revision it previewed, so a concurrent change is rejected with a conflict
// instead of being silently overwritten.
func routingRevision(cfg *config.Config) string {
	payload := struct {
		Rules        []config.RoutingRule   `json:"rules"`
		External     map[string]string      `json:"external"`
		Whitelist    config.WhitelistConfig `json:"whitelist"`
		LocalDNS     []config.LocalDNSEntry `json:"local_dns"`
		DNSMode      string                 `json:"dns_mode"`
		DirectDNS    string                 `json:"direct_dns"`
		CountrySplit string                 `json:"country_split"`
	}{
		Rules: cfg.Routing.Rules, External: cfg.Routing.ExternalOutbounds,
		Whitelist: cfg.Whitelist, LocalDNS: cfg.Gateway.LocalDNS, DNSMode: cfg.Gateway.DNSMode,
		DirectDNS:    cfg.Gateway.DirectDNS,
		CountrySplit: cfg.Routing.CountrySplit,
	}
	data, _ := json.Marshal(payload)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])[:16]
}

// ApplyRouting persists a validated edit atomically, takes a rollback snapshot
// of the previous state and restarts a connected tunnel so the new rules take
// effect. A restart failure restores the snapshot and attempts the old tunnel
// again, so a bad rule can never leave the gateway down.
func (s *Local) ApplyRouting(ctx context.Context, edit RoutingEdit, expectedRevision, note string) (RoutingChange, error) {
	s.routingApplyMu.Lock()
	defer s.routingApplyMu.Unlock()

	// Compose the candidate while holding s.mu. Another writer (a settings
	// change, for example) may replace s.cfg between a read and the write; if
	// the candidate were built from the earlier snapshot, that unrelated change
	// would be silently overwritten.
	s.mu.Lock()
	cfg := s.cfg
	if routingMode(cfg) != "rules" {
		s.mu.Unlock()
		return RoutingChange{}, errorf(CodeInvalid, "this gateway uses the legacy whitelist; migrate it to routing.rules before editing exceptions")
	}
	if expectedRevision != "" && expectedRevision != routingRevision(cfg) {
		s.mu.Unlock()
		return RoutingChange{}, &Error{
			Code:    CodeConflict,
			Message: "the routing policy changed after this screen was loaded",
			Hint:    "reload the Routing screen, re-apply your exceptions and preview again",
		}
	}
	candidate, warnings, err := candidateConfig(cfg, edit)
	if err != nil {
		s.mu.Unlock()
		return RoutingChange{}, err
	}
	s.mu.Unlock()
	engine := s.routingEngine()

	// Provision before any write: a split that cannot be backed by usable geo
	// assets is refused, so it is never enabled with rules the engine skips.
	if country := candidate.Routing.CountrySplit; country != "" {
		if strings.EqualFold(engine, "xray") {
			return RoutingChange{}, &Error{
				Code:    CodeInvalid,
				Message: "the " + strings.ToUpper(country) + " split needs the sing-box engine: xray cannot route its DNS resolver through the tunnel, so proxied names would reach the local resolver",
				Hint:    "select sing-box as the preferred engine and apply again, or turn the split off. The routing policy was not changed.",
			}
		}
		if err := s.ensureSplitAssets(cfg, country, engine); err != nil {
			return RoutingChange{}, err
		}
	}

	s.mu.Lock()
	if s.cfg != cfg {
		s.mu.Unlock()
		return RoutingChange{}, &Error{
			Code:    CodeConflict,
			Message: "the routing policy changed while the geo assets were being prepared",
			Hint:    "reload the Routing screen and preview again",
		}
	}
	snapshot, snapErr := s.writeRoutingSnapshot(cfg, note)
	if snapErr != nil {
		s.mu.Unlock()
		return RoutingChange{}, snapErr
	}
	if err := s.writeConfig(candidate); err != nil {
		s.mu.Unlock()
		return RoutingChange{}, err
	}
	previous := s.cfg
	s.cfg = candidate
	s.mu.Unlock()

	plan := s.routingPlan(candidate, engine)
	change := RoutingChange{
		Applied:  true,
		Revision: routingRevision(candidate),
		Snapshot: snapshot,
		Rules:    routingRuleViews(plan),
		Warnings: append(warnings, splitAssetWarnings(engine, candidate.Routing.CountrySplit, plan)...),
	}
	if s.runtime == nil {
		change.Message = "Routing saved. Start the gateway to apply it."
		return change, nil
	}
	s.runtime.Reload(candidate)
	state := s.runtime.Status().State
	switch state {
	case "CONNECTED":
		if err := s.restartForRouting(candidate, previous); err != nil {
			return RoutingChange{}, err
		}
		s.clearPendingRestart()
		change.Message = "Routing saved and the tunnel was restarted with the new rules."
		return change, nil
	case "CONNECTING", "RECOVERING", "STOPPING":
		s.markPendingRestart([]string{"routing"})
		change.Applied = false
		change.RestartRequired = true
		change.Message = "Routing saved, but the gateway is " + strings.ToLower(state) + ". Restart the tunnel to apply the new rules; rollback is available if they cause trouble."
		return change, nil
	default:
		change.Message = "Routing saved. It will apply the next time the tunnel starts."
		return change, nil
	}
}

// restartForRouting restarts a connected gateway. On failure it restores the
// previous configuration on disk and brings the old tunnel back up.
func (s *Local) restartForRouting(candidate *config.Config, previous *config.Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := s.runtime.ApplyActiveLink(ctx); err != nil {
		restoreErr := s.restoreRoutingConfig(previous)
		var retryErr error
		if restoreErr == nil {
			retryErr = s.runtime.ApplyActiveLink(ctx)
		}
		message := "the tunnel did not come up with the new rules: " + Redact(err.Error())
		hint := "the previous routing policy was restored"
		if restoreErr != nil {
			hint = "the previous routing policy could not be restored automatically: " + Redact(restoreErr.Error())
		} else if retryErr != nil {
			hint = "the previous routing policy was restored, but the old tunnel also failed to restart: " + Redact(retryErr.Error())
		}
		return &Error{Code: CodeUnavailable, Message: message, Hint: hint, Err: err}
	}
	return nil
}

// restoreRoutingConfig writes a previous policy back and reloads the runtime.
func (s *Local) restoreRoutingConfig(previous *config.Config) error {
	s.mu.Lock()
	if err := s.writeConfig(previous); err != nil {
		s.mu.Unlock()
		return err
	}
	s.cfg = previous
	s.mu.Unlock()
	if s.runtime != nil {
		s.runtime.Reload(previous)
	}
	return nil
}

// --- rollback snapshots ----------------------------------------------------

type routingSnapshot struct {
	ID           string                 `json:"id"`
	Created      string                 `json:"created"`
	Note         string                 `json:"note"`
	Revision     string                 `json:"revision"`
	Rules        []config.RoutingRule   `json:"rules"`
	External     map[string]string      `json:"external_outbounds,omitempty"`
	Whitelist    config.WhitelistConfig `json:"whitelist"`
	LocalDNS     []config.LocalDNSEntry `json:"local_dns,omitempty"`
	DNSMode      string                 `json:"dns_mode,omitempty"`
	DirectDNS    string                 `json:"direct_dns,omitempty"`
	CountrySplit string                 `json:"country_split,omitempty"`
}

func (s *Local) routingHistoryDir() string {
	if s == nil || s.cfg == nil {
		return ""
	}
	base := s.cfg.Profiles.Directory
	if base == "" {
		if s.paths == nil {
			return ""
		}
		base = s.paths.DataDir
	}
	if base == "" {
		return ""
	}
	return filepath.Join(base, "routing-history")
}

func snapshotFromConfig(cfg *config.Config, note string) routingSnapshot {
	now := time.Now().UTC()
	return routingSnapshot{
		ID:           now.Format("20060102T150405Z") + "-" + routingRevision(cfg)[:6],
		Created:      now.Format(time.RFC3339),
		Note:         note,
		Revision:     routingRevision(cfg),
		Rules:        append([]config.RoutingRule(nil), cfg.Routing.Rules...),
		External:     cfg.Routing.ExternalOutbounds,
		Whitelist:    cfg.Whitelist,
		LocalDNS:     append([]config.LocalDNSEntry(nil), cfg.Gateway.LocalDNS...),
		DNSMode:      cfg.Gateway.DNSMode,
		DirectDNS:    cfg.Gateway.DirectDNS,
		CountrySplit: cfg.Routing.CountrySplit,
	}
}

// writeRoutingSnapshot records the current policy before it is replaced. The
// caller holds s.mu. Files are root-only; credentials never appear here because
// only routing inputs are stored.
func (s *Local) writeRoutingSnapshot(cfg *config.Config, note string) (string, error) {
	dir := s.routingHistoryDir()
	if dir == "" {
		return "", nil
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", asAppError(err, CodeInternal, "creating routing history directory")
	}
	snapshot := snapshotFromConfig(cfg, note)
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return "", asAppError(err, CodeInternal, "encoding routing snapshot")
	}
	path := filepath.Join(dir, snapshot.ID+".json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		return "", asAppError(err, CodeInternal, "writing routing snapshot")
	}
	s.pruneRoutingSnapshots(dir, 10)
	return snapshot.ID, nil
}

func (s *Local) listRoutingSnapshots() []RoutingSnapshotView {
	dir := s.routingHistoryDir()
	if dir == "" {
		return []RoutingSnapshotView{}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []RoutingSnapshotView{}
	}
	views := make([]RoutingSnapshotView, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		var snapshot routingSnapshot
		if json.Unmarshal(data, &snapshot) != nil {
			continue
		}
		views = append(views, RoutingSnapshotView{
			ID: snapshot.ID, Created: snapshot.Created, Note: snapshot.Note, Rules: len(snapshot.Rules),
		})
	}
	sort.Slice(views, func(i, j int) bool { return views[i].Created > views[j].Created })
	return views
}

func (s *Local) pruneRoutingSnapshots(dir string, keep int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			names = append(names, entry.Name())
		}
	}
	if len(names) <= keep {
		return
	}
	sort.Strings(names)
	for _, name := range names[:len(names)-keep] {
		_ = os.Remove(filepath.Join(dir, name))
	}
}

func (s *Local) loadRoutingSnapshot(id string) (routingSnapshot, error) {
	if id == "" || id != filepath.Base(id) || strings.Contains(id, "..") {
		return routingSnapshot{}, errorf(CodeInvalid, "invalid snapshot id")
	}
	dir := s.routingHistoryDir()
	if dir == "" {
		return routingSnapshot{}, errorf(CodeUnavailable, "routing history is not available on this installation")
	}
	data, err := os.ReadFile(filepath.Join(dir, id+".json"))
	if err != nil {
		return routingSnapshot{}, errorf(CodeNotFound, "routing snapshot %q not found", id)
	}
	var snapshot routingSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return routingSnapshot{}, errorf(CodeInvalid, "routing snapshot %q is unreadable", id)
	}
	return snapshot, nil
}

// RollbackRouting restores a saved policy. The rollback itself is snapshotted,
// so an accidental rollback can be reverted the same way.
func (s *Local) RollbackRouting(ctx context.Context, id string) (RoutingChange, error) {
	s.routingApplyMu.Lock()
	defer s.routingApplyMu.Unlock()

	if id == "" {
		snapshots := s.listRoutingSnapshots()
		if len(snapshots) == 0 {
			return RoutingChange{}, errorf(CodeNotFound, "there is no routing snapshot to roll back to")
		}
		id = snapshots[0].ID
	}
	snapshot, err := s.loadRoutingSnapshot(id)
	if err != nil {
		return RoutingChange{}, err
	}

	// Build the restored document from the configuration that is current now,
	// not from a snapshot read before another writer could replace it.
	s.mu.Lock()
	cfg := s.cfg
	work := *cfg
	work.Routing = cfg.Routing
	work.Routing.Rules = append([]config.RoutingRule(nil), snapshot.Rules...)
	work.Routing.CountrySplit = snapshot.CountrySplit
	if snapshot.External != nil {
		work.Routing.ExternalOutbounds = snapshot.External
	}
	work.Whitelist = snapshot.Whitelist
	work.Gateway = cfg.Gateway
	work.Gateway.LocalDNS = append([]config.LocalDNSEntry(nil), snapshot.LocalDNS...)
	work.Gateway.DNSMode = snapshot.DNSMode
	work.Gateway.DirectDNS = snapshot.DirectDNS
	if err := validateConfigDocument(&work); err != nil {
		s.mu.Unlock()
		return RoutingChange{}, errorf(CodeInvalid, "the saved policy is no longer valid on this host: %v", err)
	}

	previousSnapshot, snapErr := s.writeRoutingSnapshot(cfg, "before rollback to "+id)
	if snapErr != nil {
		s.mu.Unlock()
		return RoutingChange{}, snapErr
	}
	if err := s.writeConfig(&work); err != nil {
		s.mu.Unlock()
		return RoutingChange{}, err
	}
	previous := s.cfg
	s.cfg = &work
	s.mu.Unlock()

	engine := s.routingEngine()
	plan := s.routingPlan(&work, engine)
	change := RoutingChange{
		Applied:  true,
		Revision: routingRevision(&work),
		Snapshot: previousSnapshot,
		Rules:    routingRuleViews(plan),
		Warnings: routingWarnings(&work, plan),
		Message:  "Rolled back to the policy saved at " + snapshot.Created + ".",
	}
	if snapshot.Note != "" {
		change.Message += " (" + snapshot.Note + ")"
	}
	if s.runtime == nil {
		change.Message += " Start the gateway to apply it."
		return change, nil
	}
	s.runtime.Reload(&work)
	switch s.runtime.Status().State {
	case "CONNECTED":
		if err := s.restartForRouting(&work, previous); err != nil {
			return RoutingChange{}, err
		}
		s.clearPendingRestart()
		change.Message += " The tunnel was restarted with the restored rules."
	case "CONNECTING", "RECOVERING", "STOPPING":
		s.markPendingRestart([]string{"routing"})
		change.Applied = false
		change.RestartRequired = true
		change.Message += " Restart the tunnel to apply the restored rules."
	}
	return change, nil
}
