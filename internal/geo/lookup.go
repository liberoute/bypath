package geo

import (
	"bufio"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
)

// maxCategoryEntry bounds one decoded category body. The largest published
// geosite category is a few megabytes; a malformed length prefix must not make
// the daemon allocate gigabytes.
const maxCategoryEntry = 64 << 20

// LookupGeoSite reports whether domain belongs to the geosite category code.
// found reports that the category exists in the file at all, so a caller can
// distinguish "not in this list" from "this list is missing".
//
// The matcher mirrors xray's geosite loader: Domain_Plain is a substring,
// Domain_Regex a regular expression, Domain_Domain a label-boundary suffix and
// Domain_Full an exact name. Matching is case-insensitive and ignores a
// trailing dot.
func LookupGeoSite(path, code, domain string) (matched, found bool) {
	domain = normalizeDomain(domain)
	if domain == "" {
		return false, false
	}
	want := strings.ToLower(strings.TrimSpace(code))
	if want == "" {
		return false, false
	}
	scanCategoryEntry(path, func(entryCodeValue string, body []byte) bool {
		if !sameCategory(entryCodeValue, want) {
			return false
		}
		found = true
		walkFields(body, func(f pbField) bool {
			if f.num != 2 || f.wire != 2 {
				return false
			}
			if geositeDomainMatches(f.data, domain) {
				matched = true
				return true
			}
			return false
		})
		return true
	})
	return matched, found
}

// LookupGeoIP reports whether ip belongs to the geoip category code.
func LookupGeoIP(path, code string, ip net.IP) (matched, found bool) {
	if ip == nil {
		return false, false
	}
	want := strings.ToLower(strings.TrimSpace(code))
	if want == "" {
		return false, false
	}
	scanCategoryEntry(path, func(entryCodeValue string, body []byte) bool {
		if !sameCategory(entryCodeValue, want) {
			return false
		}
		found = true
		walkFields(body, func(f pbField) bool {
			if f.num != 2 || f.wire != 2 {
				return false
			}
			if cidrContains(f.data, ip) {
				matched = true
				return true
			}
			return false
		})
		return true
	})
	return matched, found
}

// sameCategory accepts both v2fly's "CATEGORY-XX" spelling and a bare country code.
func sameCategory(actual, want string) bool {
	lc := strings.ToLower(strings.TrimSpace(actual))
	return lc == want || lc == "category-"+want
}

func normalizeDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	domain = strings.TrimSuffix(domain, ".")
	domain = strings.ToLower(domain)
	if domain == "" || strings.ContainsAny(domain, " \t\r\n\x00/") {
		return ""
	}
	return domain
}

// geositeDomainMatches decodes one Domain message and applies the type's
// matching rule.
func geositeDomainMatches(data []byte, domain string) bool {
	var typ uint64
	var value string
	var haveValue bool
	walkFields(data, func(f pbField) bool {
		switch {
		case f.num == 1 && f.wire == 0:
			typ = f.v
		case f.num == 2 && f.wire == 2:
			value = string(f.data)
			haveValue = true
		}
		return false
	})
	if !haveValue {
		return false
	}
	value = strings.ToLower(strings.TrimSuffix(value, "."))
	if value == "" {
		return false
	}
	switch typ {
	case 0: // Domain_Plain
		return strings.Contains(domain, value)
	case 1: // Domain_Regex
		return safeRegexMatch(value, domain)
	case 2: // Domain_Domain: value or any subdomain of value
		return domain == value || strings.HasSuffix(domain, "."+value)
	case 3: // Domain_Full
		return domain == value
	default:
		return false
	}
}

var (
	regexCacheMu sync.Mutex
	regexCache   = map[string]*regexp.Regexp{}
)

// safeRegexMatch compiles untrusted list expressions with a size guard. A bad
// expression in a downloaded list must not take the daemon down; it simply
// does not match.
func safeRegexMatch(expr, domain string) bool {
	if len(expr) > 512 {
		return false
	}
	regexCacheMu.Lock()
	re, ok := regexCache[expr]
	regexCacheMu.Unlock()
	if !ok {
		compiled, err := regexp.Compile(expr)
		if err != nil {
			return false
		}
		re = compiled
		regexCacheMu.Lock()
		if len(regexCache) > 256 {
			regexCache = map[string]*regexp.Regexp{}
		}
		regexCache[expr] = re
		regexCacheMu.Unlock()
	}
	return re.MatchString(domain)
}

// cidrContains decodes one CIDR message (ip bytes, prefix length) and tests
// containment.
func cidrContains(data []byte, ip net.IP) bool {
	var raw []byte
	var prefix int
	var havePrefix bool
	walkFields(data, func(f pbField) bool {
		switch {
		case f.num == 1 && f.wire == 2:
			raw = f.data
		case f.num == 2 && f.wire == 0:
			prefix = int(f.v)
			havePrefix = true
		}
		return false
	})
	if len(raw) != net.IPv4len && len(raw) != net.IPv6len {
		return false
	}
	base := net.IP(raw)
	if v4 := base.To4(); v4 != nil {
		base = v4
		if ip.To4() == nil {
			return false
		}
		ip = ip.To4()
	} else {
		base = base.To16()
		ip = ip.To16()
	}
	if !havePrefix {
		return false
	}
	bits := len(base) * 8
	if prefix < 0 || prefix > bits {
		return false
	}
	mask := net.CIDRMask(prefix, bits)
	return base.Mask(mask).Equal(ip.Mask(mask))
}

// pbField is one protobuf field decoded from an entry body.
type pbField struct {
	num  int
	wire int
	v    uint64
	data []byte
}

// walkFields decodes protobuf fields sequentially, skipping unknown wire types
// by their declared length. It stops when fn returns true or the buffer ends.
func walkFields(b []byte, fn func(f pbField) bool) {
	for len(b) > 0 {
		key, n := readUvarint(b)
		if n <= 0 {
			return
		}
		b = b[n:]
		num, wire := int(key>>3), int(key&7)
		if num <= 0 {
			return
		}
		switch wire {
		case 0:
			v, n := readUvarint(b)
			if n <= 0 {
				return
			}
			b = b[n:]
			if fn(pbField{num: num, wire: wire, v: v}) {
				return
			}
		case 1:
			if len(b) < 8 {
				return
			}
			b = b[8:]
		case 2:
			l, n := readUvarint(b)
			if n <= 0 || l > uint64(len(b)-n) {
				return
			}
			b = b[n:]
			if fn(pbField{num: num, wire: wire, data: b[:l]}) {
				return
			}
			b = b[l:]
		case 5:
			if len(b) < 4 {
				return
			}
			b = b[4:]
		default:
			return
		}
	}
}

func readUvarint(b []byte) (uint64, int) {
	var x uint64
	for i := 0; i < len(b) && i < 10; i++ {
		c := b[i]
		if c < 0x80 {
			if i == 9 && c > 1 {
				return 0, -1
			}
			return x | uint64(c)<<(7*uint(i)), i + 1
		}
		x |= uint64(c&0x7f) << (7 * uint(i))
	}
	return 0, -1
}

// scanCategoryEntry walks the top-level entries of a geoip.dat/geosite.dat
// list. fn receives the entry's code and raw body. It returns true when fn
// stopped the scan. Malformed input ends the scan quietly: the caller reports
// "not found", which generates a narrower direct rule, never a wider one.
func scanCategoryEntry(path string, fn func(code string, body []byte) bool) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	br := bufio.NewReaderSize(f, 64*1024)
	for {
		tag, err := br.ReadByte()
		if err != nil {
			return false
		}
		if tag != 0x0a { // top level: repeated field 1 (entry message)
			return false
		}
		bodyLen, err := readVarint(br)
		if err != nil || bodyLen < 2 || bodyLen > maxCategoryEntry {
			return false
		}
		body := make([]byte, bodyLen)
		if _, err := io.ReadFull(br, body); err != nil {
			return false
		}
		code, ok := entryCode(body)
		if !ok {
			return false
		}
		if fn(code, body) {
			return true
		}
	}
}
