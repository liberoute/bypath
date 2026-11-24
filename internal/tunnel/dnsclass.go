package tunnel

import (
	"log"
	"path/filepath"
	"strings"

	"github.com/liberoute/bypath/internal/geo"
)

// NameClass is the path a hostname's traffic takes under the routing plan.
type NameClass string

const (
	NameClassDirect NameClass = "direct"
	NameClassProxy  NameClass = "proxy"
	NameClassBlock  NameClass = "block"
)

// NameClassifier answers "where does this name go?" by walking the same ordered
// plan the engine evaluates. It exists so the gateway's LAN DNS forwarder can
// send a name down the direct path only when the routing plan sends that name
// direct; anything it cannot decide stays on the tunnel resolver.
type NameClassifier struct {
	entries []nameClassEntry
}

type nameClassEntry struct {
	kind   string // domain, suffix, geosite, geosite-dat or default
	values []string
	set    *geo.RuleSet
	dat    string // geosite.dat path for the xray flavour
	datTag string // category code inside dat
	class  NameClass
}

// NameClassifier builds a classifier for the named engine. Address-only
// matchers are skipped: a hostname query cannot be decided by a geoip or CIDR
// rule, and the engine decides those after resolution. Skipped plan entries are
// skipped here too, so the classifier never claims a path the generator would
// not emit.
func (cg *ConfigGenerator) NameClassifier(engine string) *NameClassifier {
	xray := strings.EqualFold(strings.TrimSpace(engine), "xray")
	c := &NameClassifier{}
	for _, entry := range cg.RoutingPlan(engine) {
		if entry.Skip != "" {
			continue
		}
		item := nameClassEntry{class: nameClassForOutbound(entry.Outbound)}
		switch entry.Kind {
		case "default":
			item.kind = "default"
		case "domain":
			item.kind, item.values = "domain", []string{entry.Value}
		case "domain_suffix":
			item.kind, item.values = "suffix", []string{entry.Value}
		case "domain_suffix_list":
			item.kind, item.values = "suffix", entry.Domains
		case "geosite":
			tag := entry.Resolved
			if tag == "" {
				tag = entry.Value
			}
			if xray {
				// The xray gate resolved the exact category spelling that
				// geosite.dat carries; match it the same way xray loads it.
				path := cg.xrayGeoAssetPath("geosite.dat")
				if path == "" {
					log.Printf("⚠️  DNS classification: geosite.dat is not installed; names keep the default path")
					continue
				}
				item.kind, item.dat, item.datTag = "geosite-dat", path, tag
				break
			}
			// Resolved is the rule-set tag the sing-box gate validated, e.g.
			// "geosite-ir", and names the same file the engine loads.
			set, err := geo.LoadSRS(filepath.Join(cg.geoDir(), tag+".srs"))
			if err != nil {
				// The generator skips a matcher it cannot load, so the classifier
				// must too rather than widen the direct set from a guess.
				log.Printf("⚠️  DNS classification: geosite:%s is not loadable (%v); names keep the default path", tag, err)
				continue
			}
			item.kind, item.set = "geosite", set
		case "private", "geoip", "ip_cidr":
			continue
		default:
			continue
		}
		c.entries = append(c.entries, item)
	}
	return c
}

// Classify returns the class of host using first-match-wins, the order the
// engine evaluates. A name no entry matches takes the default outbound, and an
// empty classifier keeps everything on the tunnel.
func (c *NameClassifier) Classify(host string) NameClass {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return NameClassProxy
	}
	for _, entry := range c.entries {
		switch entry.kind {
		case "domain":
			for _, value := range entry.values {
				if host == strings.ToLower(value) {
					return entry.class
				}
			}
		case "suffix":
			for _, value := range entry.values {
				value = strings.ToLower(strings.Trim(value, "."))
				if value != "" && (host == value || strings.HasSuffix(host, "."+value)) {
					return entry.class
				}
			}
		case "geosite":
			if entry.set != nil && entry.set.MatchDomain(host) {
				return entry.class
			}
		case "geosite-dat":
			if matched, found := geo.LookupGeoSite(entry.dat, entry.datTag, host); found && matched {
				return entry.class
			}
		case "default":
			return entry.class
		}
	}
	return NameClassProxy
}

// nameClassForOutbound maps a configured outbound to a DNS class. Only DIRECT
// traffic may use the direct resolver; every other outbound, including an
// external one, keeps resolving through the tunnel.
func nameClassForOutbound(outbound string) NameClass {
	switch EffectiveOutbound(outbound) {
	case "direct":
		return NameClassDirect
	case xrayBlockOutboundTag:
		return NameClassBlock
	default:
		return NameClassProxy
	}
}
