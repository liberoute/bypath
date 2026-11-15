package geo

import (
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
)

// RuleSet is a sing-box binary rule set reduced to the matchers the panel can
// evaluate locally: exact domains, domain suffixes and IP prefixes. It is built
// from the same reader sing-box uses, so the panel's answer for a geosite/geoip
// rule describes the file the engine will actually load.
type RuleSet struct {
	domains  map[string]struct{}
	suffixes []string
	prefixes []netip.Prefix
	// complete is false when the file also carries keyword, regex, AdGuard or
	// logical entries. A negative answer is then not proof of absence, and the
	// panel says so instead of presenting it as certain.
	complete bool
}

// LoadSRS decompiles a binary rule set. A malformed file is an error rather
// than an empty set: an unreadable asset must not look like "no match".
func LoadSRS(path string) (*RuleSet, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	compat, err := srs.Read(file, true)
	if err != nil {
		return nil, err
	}
	set := &RuleSet{domains: make(map[string]struct{}), complete: true}
	for _, rule := range compat.Options.Rules {
		if rule.Type != C.RuleTypeDefault {
			set.complete = false
			continue
		}
		options := rule.DefaultOptions
		if options.Invert {
			set.complete = false
		}
		for _, domain := range options.Domain {
			set.domains[normalizeRuleName(domain)] = struct{}{}
		}
		for _, suffix := range options.DomainSuffix {
			set.suffixes = append(set.suffixes, normalizeRuleName(suffix))
		}
		for _, cidr := range options.IPCIDR {
			if prefix, err := netip.ParsePrefix(cidr); err == nil {
				set.prefixes = append(set.prefixes, prefix)
			}
		}
		if len(options.DomainKeyword) > 0 || len(options.DomainRegex) > 0 ||
			len(options.AdGuardDomain) > 0 || options.AdGuardDomainMatcher != nil {
			set.complete = false
		}
	}
	return set, nil
}

// Complete reports whether every entry in the file was evaluated. A false value
// means a "no match" answer is inconclusive (keyword/regex entries exist).
func (s *RuleSet) Complete() bool { return s.complete }

// MatchDomain applies exact and suffix matching with the same label-boundary
// rule sing-box uses. A suffix that starts with a dot comes from a rule set's
// nested form (".ir", for example): it matches every host under that name but
// never the bare name itself.
func (s *RuleSet) MatchDomain(host string) bool {
	host = normalizeRuleName(host)
	if host == "" {
		return false
	}
	if _, ok := s.domains[host]; ok {
		return true
	}
	for _, suffix := range s.suffixes {
		if suffix == "" {
			continue
		}
		if suffix[0] == '.' {
			if strings.HasSuffix(host, suffix) {
				return true
			}
			continue
		}
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

// MatchIP reports whether the address is inside one of the file's prefixes.
func (s *RuleSet) MatchIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	for _, prefix := range s.prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func normalizeRuleName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}
