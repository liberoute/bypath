package tunnel

import (
	"fmt"
	"log"
	"net"
	"strings"
)

// PlanEntry is one routing rule in the order the engine evaluates it. The
// panel uses the plan to explain a destination; the generator uses the same
// plan to emit the engine config, so the explanation cannot drift from what the
// tunnel actually runs.
type PlanEntry struct {
	// Scope is where the entry comes from: builtin, force-proxy, local-dns,
	// bypass, country, rule, or default.
	Scope string `json:"scope"`
	// Kind is the matcher family: private, domain_suffix_list, domain,
	// domain_suffix, geoip, geosite, ip_cidr or default.
	Kind string `json:"kind"`
	// Value is the matcher value without its type prefix.
	Value string `json:"value,omitempty"`
	// Resolved is the tag spelling the installed geosite.dat actually uses.
	Resolved string `json:"resolved,omitempty"`
	// Domains carries a whole suffix list for the grouped scopes.
	Domains []string `json:"domains,omitempty"`
	// Outbound is the configured outbound name ("direct", "proxy", "deny", an
	// external name).
	Outbound string `json:"outbound"`
	// SourceIndex is the index in routing.rules, or -1 for generated entries.
	SourceIndex int `json:"source_index"`
	// Skip explains why the entry is not emitted (missing geo category). An
	// omitted rule always leaves traffic on the default outbound.
	Skip string `json:"skip,omitempty"`
}

// EffectiveOutbound maps a configured outbound name to the engine tag.
func EffectiveOutbound(outbound string) string {
	if isDenyOutbound(outbound) {
		return xrayBlockOutboundTag
	}
	return outbound
}

// geoGate reports whether the installed databases can satisfy a geo matcher and
// how the engine must spell the value. xray accepts only the exact geosite tag
// present in geosite.dat; sing-box instead loads a per-country .srs rule set.
// skip explains an unusable matcher so the panel can name the missing asset.
type geoGate func(kind, value string) (resolved, skip string)

// xrayGeoGate is the xray flavour: the .dat databases must exist AND carry the
// category, because xray aborts startup when a rule names a missing code.
func (cg *ConfigGenerator) xrayGeoGate(kind, value string) (string, string) {
	switch kind {
	case "geoip":
		if !cg.xrayGeoipAvailable(value) {
			return "", fmt.Sprintf("geoip.dat is missing or has no %q category", strings.ToUpper(value))
		}
		return "", ""
	case "geosite":
		resolved, ok := cg.xrayGeositeTag(value)
		if !ok {
			return "", fmt.Sprintf("geosite.dat is missing or has no %q category", value)
		}
		return resolved, ""
	}
	return "", ""
}

// singboxGeoGate is the sing-box flavour: the local binary rule set must be
// present and valid. Referencing a missing rule_set makes sing-box refuse the
// whole configuration, so an unusable asset drops the rule instead.
func (cg *ConfigGenerator) singboxGeoGate(kind, value string) (string, string) {
	tag := cg.geoRuleSetTag(kind, value)
	if tag == "" {
		return "", fmt.Sprintf("%s-%s.srs is missing or not a binary rule set; run 'bypath geo update'", kind, value)
	}
	return tag, ""
}

// ProbeInboundTag names the loopback SOCKS inbound the gateway reserves for its
// own startup health probes. The forced probe route is scoped to this inbound,
// so client traffic through the operator listeners keeps following the explicit
// routing rules and deny policies even for the probe hostnames.
const ProbeInboundTag = "bypath-probe"

// StartupProbeDomains are the hosts the gateway contacts to prove its tunnel.
// They only bypass operator and country rules for the probe inbound above; a
// startup probe must never verify the direct path while the proxy is broken,
// and an operator rule must never be silently overridden for other clients.
// A suffix covers the www. and generate_204 forms the probes use.
var StartupProbeDomains = []string{
	"example.com",
	"gstatic.com",
	"msftconnecttest.com",
	"captive.apple.com",
}

// RoutingPlan builds the ordered plan the named engine evaluates. The panel and
// the explanation use it so display cannot drift from the generated config.
func (cg *ConfigGenerator) RoutingPlan(engine string) []PlanEntry {
	if strings.EqualFold(strings.TrimSpace(engine), "xray") {
		return cg.XrayRoutingPlan()
	}
	return cg.SingboxRoutingPlan()
}

// XrayRoutingPlan builds the ordered plan the xray generator emits. The tunnel
// resolver pin comes first: xray dials every https resolver through the router,
// so a whitelist or geoip rule that covers the resolver address would otherwise
// send DNS traffic direct and expose queries the tunnel is meant to carry.
func (cg *ConfigGenerator) XrayRoutingPlan() []PlanEntry {
	plan := cg.planWithGate(cg.xrayGeoGate)
	// The generator refuses a split on xray, so the panel must not describe one
	// as active: both entries carry the refusal so the explanation names the
	// reason instead of a direct path the engine would never take.
	for i := range plan {
		if plan[i].Scope == "country-split" {
			plan[i].Skip = xraySplitRefusal
		}
	}
	if pin := cg.xrayTunnelResolverEntry(); pin != nil {
		plan = append([]PlanEntry{*pin}, plan...)
	}
	return plan
}

// xrayTunnelResolverEntry describes the pin xrayRoutingSection emits for the
// DoH endpoint the DNS section resolves through.
func (cg *ConfigGenerator) xrayTunnelResolverEntry() *PlanEntry {
	host, isIP := cg.tunnelResolverEndpoint()
	if host == "" {
		return nil
	}
	entry := &PlanEntry{Scope: "dns-pin", Kind: "domain", Value: host, Outbound: "proxy", SourceIndex: -1}
	if isIP {
		mask := "/128"
		if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
			mask = "/32"
		}
		entry.Kind, entry.Value = "ip_cidr", host+mask
	}
	return entry
}

// ValidatePlanForEngine refuses a plan the generator would silently widen. A
// rule whose geo assets are unusable is skipped; with a DIRECT default the
// traffic it was meant to proxy or deny falls to DIRECT, so generation fails
// instead of emitting a policy broader than the operator's.
func (cg *ConfigGenerator) ValidatePlanForEngine(engine string) error {
	plan := cg.RoutingPlan(engine)
	defaultOutbound := ""
	for _, entry := range plan {
		if entry.Kind == "default" {
			defaultOutbound = EffectiveOutbound(entry.Outbound)
		}
	}
	if defaultOutbound != "direct" {
		return nil
	}
	for _, entry := range plan {
		if entry.Skip == "" || entry.Kind == "default" {
			continue
		}
		if EffectiveOutbound(entry.Outbound) == "direct" {
			continue
		}
		return fmt.Errorf("routing rule %s cannot be honoured (%s); with a DIRECT default that traffic would leave DIRECT, so no engine config is generated. Run 'bypath geo update' or set a proxy default", planEntryLabel(entry), entry.Skip)
	}
	return nil
}

// SingboxRoutingPlan builds the ordered plan the sing-box generator emits.
func (cg *ConfigGenerator) SingboxRoutingPlan() []PlanEntry {
	return cg.planWithGate(cg.singboxGeoGate)
}

// countrySplitMatchers lists the two matchers that implement the opt-in country
// split. geosite comes first so a domain can be decided before resolution.
func (cg *ConfigGenerator) countrySplitMatchers() []string {
	if cg.CountrySplit == "" {
		return nil
	}
	return []string{"geosite:" + cg.CountrySplit, "geoip:" + cg.CountrySplit}
}

// appendCountrySplit places the split rules after the explicit rules (so an
// operator exception still wins) and before the catch-all default.
func (cg *ConfigGenerator) appendCountrySplit(plan []PlanEntry, gate geoGate) []PlanEntry {
	for _, matcher := range cg.countrySplitMatchers() {
		kind, value, _ := strings.Cut(matcher, ":")
		entry := PlanEntry{
			Scope:       "country-split",
			Kind:        kind,
			Value:       value,
			Outbound:    "direct",
			SourceIndex: -1,
		}
		entry.Resolved, entry.Skip = gate(kind, value)
		plan = append(plan, entry)
	}
	return plan
}

func (cg *ConfigGenerator) planWithGate(gate geoGate) []PlanEntry {
	plan := []PlanEntry{{
		Scope:       "builtin",
		Kind:        "private",
		Outbound:    "direct",
		SourceIndex: -1,
	}}

	if len(cg.RoutingRules) > 0 {
		for _, rule := range cg.LocalDNSRules {
			if len(rule.Domains) == 0 {
				continue
			}
			plan = append(plan, PlanEntry{
				Scope:       "local-dns",
				Kind:        "domain_suffix_list",
				Domains:     append([]string(nil), rule.Domains...),
				Outbound:    "direct",
				SourceIndex: -1,
			})
		}
		var defaultEntry *PlanEntry
		for i, rule := range cg.RoutingRules {
			entry := cg.planFromRule(i, rule, gate)
			if entry.Kind == "default" {
				// The generator consumes the catch-all as route.final and emits
				// the split rules after every explicit rule, so the plan must keep
				// the default last or it would describe a shorter direct path
				// than the engine actually takes.
				defaultEntry = &entry
				continue
			}
			plan = append(plan, entry)
		}
		plan = cg.appendCountrySplit(plan, gate)
		if defaultEntry != nil {
			plan = append(plan, *defaultEntry)
		}
		return appendDefault(plan, "proxy")
	}

	if len(cg.ForceProxyDomains) > 0 {
		plan = append(plan, PlanEntry{
			Scope:       "force-proxy",
			Kind:        "domain_suffix_list",
			Domains:     append([]string(nil), cg.ForceProxyDomains...),
			Outbound:    "proxy",
			SourceIndex: -1,
		})
	}
	for _, rule := range cg.LocalDNSRules {
		if len(rule.Domains) == 0 {
			continue
		}
		plan = append(plan, PlanEntry{
			Scope:       "local-dns",
			Kind:        "domain_suffix_list",
			Domains:     append([]string(nil), rule.Domains...),
			Outbound:    "direct",
			SourceIndex: -1,
		})
	}
	if len(cg.BypassDomains) > 0 {
		plan = append(plan, PlanEntry{
			Scope:       "bypass",
			Kind:        "domain_suffix_list",
			Domains:     append([]string(nil), cg.BypassDomains...),
			Outbound:    "direct",
			SourceIndex: -1,
		})
	}
	// The legacy route emits a geosite rule before the geoip rule for the same
	// country list, so DNS classification can decide those names by domain.
	geositeCountries := cg.GeositeCountries
	if len(geositeCountries) == 0 {
		geositeCountries = cg.WhitelistCountries
	}
	for _, country := range geositeCountries {
		entry := PlanEntry{
			Scope:       "country",
			Kind:        "geosite",
			Value:       country,
			Outbound:    "direct",
			SourceIndex: -1,
		}
		entry.Resolved, entry.Skip = gate("geosite", country)
		plan = append(plan, entry)
	}
	for _, country := range cg.WhitelistCountries {
		entry := PlanEntry{
			Scope:       "country",
			Kind:        "geoip",
			Value:       country,
			Outbound:    "direct",
			SourceIndex: -1,
		}
		entry.Resolved, entry.Skip = gate("geoip", country)
		plan = append(plan, entry)
	}
	return appendDefault(cg.appendCountrySplit(plan, gate), "proxy")
}

func appendDefault(plan []PlanEntry, outbound string) []PlanEntry {
	for _, entry := range plan {
		if entry.Kind == "default" {
			return plan
		}
	}
	return append(plan, PlanEntry{
		Scope:       "default",
		Kind:        "default",
		Outbound:    outbound,
		SourceIndex: -1,
	})
}

func (cg *ConfigGenerator) planFromRule(index int, rule RoutingRule, gate geoGate) PlanEntry {
	entry := PlanEntry{Scope: "rule", Outbound: rule.Outbound, SourceIndex: index}
	match := strings.TrimSpace(rule.Match)
	if match == "default" {
		entry.Kind = "default"
		return entry
	}
	typ, val, ok := strings.Cut(match, ":")
	if !ok {
		entry.Kind = "unsupported"
		entry.Skip = fmt.Sprintf("unsupported matcher %q", match)
		return entry
	}
	entry.Kind = typ
	entry.Value = val
	switch typ {
	case "geoip", "geosite":
		entry.Resolved, entry.Skip = gate(typ, val)
	case "domain", "domain_suffix", "ip_cidr":
	default:
		entry.Kind = "unsupported"
		entry.Skip = fmt.Sprintf("unsupported matcher %q", match)
	}
	return entry
}

// xrayRoutingSection renders the plan as xray's routing object. Skipped entries
// are logged and omitted: omitting a direct rule narrows the direct set, and
// omitting a proxy/deny rule leaves traffic on the default outbound.
func (cg *ConfigGenerator) xrayRoutingSection() map[string]interface{} {
	finalOutbound := "proxy"
	var rules []map[string]interface{}

	// The daemon's probe inbound is forced through the tunnel and closed to
	// everything else. Both rules carry the inbound tag, so they never decide a
	// client destination and cannot override an operator rule or deny policy.
	if cg.ProbePort > 0 {
		rules = append(rules,
			map[string]interface{}{
				"type":        "field",
				"inboundTag":  []string{ProbeInboundTag},
				"domain":      append([]string(nil), StartupProbeDomains...),
				"outboundTag": "proxy",
			},
			map[string]interface{}{
				"type":        "field",
				"inboundTag":  []string{ProbeInboundTag},
				"outboundTag": xrayBlockOutboundTag,
			},
		)
	}

	for _, entry := range cg.XrayRoutingPlan() {
		if entry.Kind == "default" {
			finalOutbound = EffectiveOutbound(entry.Outbound)
			continue
		}
		if entry.Skip != "" {
			log.Printf("⚠️  routing rule %s: %s; skipping (traffic keeps the default outbound)", planEntryLabel(entry), entry.Skip)
			continue
		}
		if rule := planEntryToXray(entry); rule != nil {
			rules = append(rules, rule)
		}
	}

	// xray evaluates routing in two passes under IPIfNonMatch: domain conditions
	// first, then IP conditions for the resolved address. A condition-less field
	// rule matches in the first pass, so one would hide every geoip/ip_cidr rule
	// from a domain destination. For the default proxy final the rule is
	// redundant anyway — xray's dispatcher uses outbounds[0] (the proxy) on
	// ErrNoClue — and omitting it restores the second pass. A direct, deny or
	// named final still needs an explicit rule, so it is expressed with an
	// all-addresses IP condition: that condition is evaluated only in the second
	// pass, after every domain and IP rule the operator wrote.
	if finalOutbound != "proxy" {
		rules = append(rules, map[string]interface{}{
			"type":        "field",
			"network":     "tcp,udp",
			"ip":          []string{"0.0.0.0/0", "::/0"},
			"outboundTag": finalOutbound,
		})
	}

	return map[string]interface{}{
		"domainStrategy": "IPIfNonMatch",
		"rules":          rules,
	}
}

func planEntryLabel(entry PlanEntry) string {
	switch {
	case entry.Kind == "geoip":
		return "geoip:" + entry.Value
	case entry.Kind == "geosite":
		return "geosite:" + entry.Value
	case entry.Value != "":
		return entry.Kind + ":" + entry.Value
	default:
		return entry.Scope
	}
}

func planEntryToXray(entry PlanEntry) map[string]interface{} {
	tag := EffectiveOutbound(entry.Outbound)
	rule := map[string]interface{}{"type": "field", "outboundTag": tag}
	switch entry.Kind {
	case "private":
		rule["ip"] = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "fc00::/7", "::1/128"}
	case "domain_suffix_list":
		// xray treats a bare entry as a substring keyword, so a look-alike host
		// would match. Every suffix list gets the label-boundary prefix.
		domains := make([]string, len(entry.Domains))
		for i, d := range entry.Domains {
			domains[i] = "domain:" + d
		}
		rule["domain"] = domains
	case "geoip":
		rule["ip"] = []string{"geoip:" + entry.Value}
	case "geosite":
		resolved := entry.Resolved
		if resolved == "" {
			resolved = entry.Value
		}
		rule["domain"] = []string{"geosite:" + resolved}
	case "domain":
		rule["domain"] = []string{"full:" + entry.Value}
	case "domain_suffix":
		rule["domain"] = []string{"domain:" + entry.Value}
	case "ip_cidr":
		rule["ip"] = []string{entry.Value}
	default:
		return nil
	}
	return rule
}
