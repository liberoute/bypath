package tunnel

import (
	"fmt"
	"log"
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

// XrayRoutingPlan builds the ordered plan the xray generator emits. When
// RoutingRules is set it takes precedence over the legacy whitelist fields,
// exactly as in the generator.
func (cg *ConfigGenerator) XrayRoutingPlan() []PlanEntry {
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
		for i, rule := range cg.RoutingRules {
			plan = append(plan, cg.planFromRule(i, rule))
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
	for _, country := range cg.WhitelistCountries {
		entry := PlanEntry{
			Scope:       "country",
			Kind:        "geoip",
			Value:       country,
			Outbound:    "direct",
			SourceIndex: -1,
		}
		if !xrayGeoipAvailable(country) {
			entry.Skip = fmt.Sprintf("geoip.dat is missing or has no %q category", strings.ToUpper(country))
		}
		plan = append(plan, entry)
	}
	return appendDefault(plan, "proxy")
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

func (cg *ConfigGenerator) planFromRule(index int, rule RoutingRule) PlanEntry {
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
	case "geoip":
		if !xrayGeoipAvailable(val) {
			entry.Skip = fmt.Sprintf("geoip.dat is missing or has no %q category", strings.ToUpper(val))
		}
	case "geosite":
		resolved, ok := xrayGeositeTag(val)
		if !ok {
			entry.Skip = fmt.Sprintf("geosite.dat is missing or has no %q category", val)
			break
		}
		entry.Resolved = resolved
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

	rules = append(rules, map[string]interface{}{
		"type":        "field",
		"network":     "tcp,udp",
		"outboundTag": finalOutbound,
	})

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
		domains := make([]string, len(entry.Domains))
		for i, d := range entry.Domains {
			if entry.Scope == "local-dns" {
				domains[i] = "domain:" + d
			} else {
				domains[i] = d
			}
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
