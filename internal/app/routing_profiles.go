package app

import (
	"strings"

	"github.com/liberoute/bypath/internal/config"
)

// routingProfiles lists the named compatibility policies the panel offers.
//
// A profile is only "available" when its behaviour is deterministic and covered
// by automated tests. Profiles only ever describe the editable exception layer;
// the core DIRECT/PROXY policy is never replaced by a profile.
func routingProfiles(cfg *config.Config) []RoutingProfile {
	current := editableFromRules(cfg.Routing.Rules)
	profiles := []RoutingProfile{
		{
			ID:          "builtin-policy",
			Name:        "Rule order and default outbound",
			Description: "Rules are evaluated in order and the first match wins. Traffic that matches no rule follows the default outbound. This ordering is engine configuration, not an exception list, so it is always on and cannot be disabled here.",
			Status:      "active",
			Verified:    "Covered by the routing test suite",
			Enabled:     true,
		},
		{
			ID:          "ip-check-hosts",
			Name:        "IP-check hosts DIRECT",
			Description: "Routes common public-IP check hosts directly so they report this gateway's own address instead of the tunnel exit. Useful when an outside service must see the local uplink.",
			Status:      "available",
			Verified:    "Covered by the routing test suite",
			Edit: &RoutingEdit{
				Direct: []RoutingRuleInput{
					{Match: "domain_suffix:cloudflare.com", Outbound: "direct"},
					{Match: "domain_suffix:ip-api.com", Outbound: "direct"},
					{Match: "domain_suffix:ipinfo.io", Outbound: "direct"},
					{Match: "domain_suffix:api.myip.com", Outbound: "direct"},
				},
			},
			Warnings: []string{
				"These hosts then see this gateway's address, not the tunnel exit, and the ISP can see that you query them.",
				"Suffix rules match every name under those zones, not only the exact check host. IP ranges that merely host those services are not affected.",
			},
		},
	}
	for i := range profiles {
		if profiles[i].Edit != nil && profiles[i].Status == "available" {
			profiles[i].Enabled = editActive(*profiles[i].Edit, current)
		}
	}
	return profiles
}

// editActive reports whether every rule of a profile is already in effect.
func editActive(edit, current RoutingEdit) bool {
	if len(edit.Force) > len(current.Force) || len(edit.Direct) > len(current.Direct) {
		return false
	}
	has := func(list []RoutingRuleInput, rule RoutingRuleInput) bool {
		for _, have := range list {
			if normalizeMatcher(have.Match) == normalizeMatcher(rule.Match) &&
				strings.EqualFold(strings.TrimSpace(have.Outbound), strings.TrimSpace(rule.Outbound)) {
				return true
			}
		}
		return false
	}
	for _, rule := range edit.Force {
		if !has(current.Force, rule) {
			return false
		}
	}
	for _, rule := range edit.Direct {
		if !has(current.Direct, rule) {
			return false
		}
	}
	return true
}
