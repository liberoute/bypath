package layer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"

	"github.com/liberoute/bypath/internal/profile"
)

// jsonUnmarshal/jsonMarshalIndent keep the storage code readable without
// scattering encoding/json imports through every file.
func jsonUnmarshal(data []byte, v interface{}) error { return json.Unmarshal(data, v) }
func jsonMarshalIndent(v interface{}) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}

// Identity is the source-scoped fingerprint of one connection. All fields are
// derived; none of them contains a secret in clear.
type Identity struct {
	SourceID   string
	Protocol   string
	Address    string
	Port       int
	Transport  string
	SecretHash string
	RawHash    string
	Remark     string
}

// IdentityFor computes the identity of a link in a bucket.
func IdentityFor(link *profile.Link, bucket string) Identity {
	source := strings.TrimSpace(link.SourceID)
	if source == "" {
		source = "manual:" + bucket
	} else {
		source = "sub:" + source
	}
	return Identity{
		SourceID:   source,
		Protocol:   link.Protocol,
		Address:    strings.ToLower(strings.TrimSpace(link.Address)),
		Port:       link.Port,
		Transport:  transportTuple(link),
		SecretHash: secretHash(link),
		RawHash:    rawHash(link.RawURI),
		Remark:     strings.TrimSpace(link.Remark),
	}
}

// transportTuple names the connection-visible transport parameters. Two links
// with the same tuple and a different secret are a credential rotation; two
// links with the same tuple and the same secret are the same entry.
func transportTuple(link *profile.Link) string {
	return strings.Join([]string{
		strings.ToLower(link.Network),
		strings.ToLower(link.SNI),
		link.Path,
		strings.ToLower(link.Host),
		link.Flow,
		strings.ToLower(link.TransportMode),
	}, "\x1f")
}

// secretHash digests the secret-bearing fields. The digest is the only value
// the layer stores; the fields themselves are never copied.
func secretHash(link *profile.Link) string {
	h := sha256.New()
	h.Write([]byte("bypath-secret-v1\x00"))
	for _, part := range []string{
		link.UUID,
		link.Security,
		link.Encryption,
		link.RealityPublicKey,
		link.RealityShortID,
		link.PublicKey,
		link.PrivateKey,
		link.SSHPassword,
		link.SSHKeyPath,
		link.OVPNAuthUserPassFile,
		link.OVPNPath,
	} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// rawHash normalises the raw URI just enough to survive case-only differences
// in the scheme and host. Everything that identifies the profile is kept.
func rawHash(raw string) string {
	raw = strings.TrimSpace(raw)
	if i := strings.Index(raw, "://"); i > 0 {
		scheme := strings.ToLower(raw[:i])
		rest := raw[i+3:]
		// Lower-case only the authority (up to the first '/', '?' or '#').
		end := len(rest)
		for j, r := range rest {
			if r == '/' || r == '?' || r == '#' {
				end = j
				break
			}
		}
		auth := strings.ToLower(rest[:end])
		raw = scheme + "://" + auth + rest[end:]
	}
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// Item is one live link seen during an index pass.
type Item struct {
	Link     *profile.Link
	Bucket   string
	Index    int
	ID       Identity
	DupCount int
}

// Match is the decision for one item.
type Match struct {
	Item               Item
	Entry              *Entry
	New                bool
	CredentialsChanged bool
	MatchedByRemark    bool
	Ambiguous          bool
}

// MatchResult is the complete match set plus entries that no longer exist.
type MatchResult struct {
	Matches  []Match
	Orphaned []Entry
	// Ambiguous counts entries that had plausible candidates but could not be
	// matched safely; they are kept orphaned and a new id is minted.
	Ambiguous int
}

// MatchEntries applies T1 (exact raw), T2 (single credential rotation) and T3
// (single remark) inside each source. Anything ambiguous never merges.
func MatchEntries(existing []Entry, items []Item) MatchResult {
	// Deduplicate identical raw URIs inside one source: one connection, dup_count.
	items = dedupeItems(items)

	t1 := map[string]*Entry{}
	t2 := map[string][]*Entry{}
	t3 := map[string][]*Entry{}
	for i := range existing {
		e := &existing[i]
		t1[e.SourceID+"\x00"+e.RawHash] = e
		key := tupleKey(e.SourceID, e.Protocol, e.Address, e.Port, e.Transport)
		t2[key] = append(t2[key], e)
		t3[e.SourceID+"\x00"+e.Remark] = append(t3[e.SourceID+"\x00"+e.Remark], e)
	}
	itemsByTuple := map[string][]Item{}
	for _, it := range items {
		key := tupleKey(it.ID.SourceID, it.ID.Protocol, it.ID.Address, it.ID.Port, it.ID.Transport)
		itemsByTuple[key] = append(itemsByTuple[key], it)
	}
	used := map[string]bool{}
	var out MatchResult

	for _, it := range items {
		if e := t1[it.ID.SourceID+"\x00"+it.ID.RawHash]; e != nil && !used[e.ID] {
			used[e.ID] = true
			out.Matches = append(out.Matches, Match{Item: it, Entry: e})
			continue
		}
		key := tupleKey(it.ID.SourceID, it.ID.Protocol, it.ID.Address, it.ID.Port, it.ID.Transport)
		var candidates []*Entry
		for _, e := range t2[key] {
			if !used[e.ID] {
				candidates = append(candidates, e)
			}
		}
		if len(candidates) == 1 && len(itemsByTuple[key]) == 1 {
			e := candidates[0]
			used[e.ID] = true
			out.Matches = append(out.Matches, Match{
				Item: it, Entry: e,
				CredentialsChanged: e.SecretHash != it.ID.SecretHash,
			})
			continue
		}
		// T3: provider remark, but only when exactly one entry and one item
		// carry it in this source.
		var remarkCandidates []*Entry
		for _, e := range t3[it.ID.SourceID+"\x00"+it.ID.Remark] {
			if !used[e.ID] {
				remarkCandidates = append(remarkCandidates, e)
			}
		}
		if len(remarkCandidates) == 1 && countRemark(items, it.ID.SourceID, it.ID.Remark) == 1 {
			e := remarkCandidates[0]
			used[e.ID] = true
			out.Matches = append(out.Matches, Match{
				Item: it, Entry: e, MatchedByRemark: true,
				CredentialsChanged: e.SecretHash != it.ID.SecretHash,
			})
			continue
		}
		ambiguous := len(candidates) > 0 || len(remarkCandidates) > 0
		if ambiguous {
			out.Ambiguous++
		}
		out.Matches = append(out.Matches, Match{Item: it, New: true, Ambiguous: ambiguous})
	}
	for i := range existing {
		e := existing[i]
		if !used[e.ID] {
			out.Orphaned = append(out.Orphaned, e)
		}
	}
	return out
}

func countRemark(items []Item, source, remark string) int {
	n := 0
	for _, it := range items {
		if it.ID.SourceID == source && it.ID.Remark == remark {
			n++
		}
	}
	return n
}

func tupleKey(source, protocol, address string, port int, transport string) string {
	return strings.Join([]string{source, protocol, address, itoa(port), transport}, "\x00")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func dedupeItems(items []Item) []Item {
	seen := map[string]int{} // source+raw -> index in out
	var out []Item
	for _, it := range items {
		key := it.ID.SourceID + "\x00" + it.ID.RawHash
		if idx, ok := seen[key]; ok {
			out[idx].DupCount++
			continue
		}
		seen[key] = len(out)
		it.DupCount = 1
		out = append(out, it)
	}
	return out
}

// ItemFromLink builds an Item for one bucket link.
func ItemFromLink(link *profile.Link, bucket string, index int) Item {
	return Item{Link: link, Bucket: bucket, Index: index, ID: IdentityFor(link, bucket)}
}

// SortBuckets returns profile group names in a deterministic order.
func SortBuckets(names []string) []string {
	out := make([]string, len(names))
	copy(out, names)
	sort.Strings(out)
	return out
}

// LinkMatch is the refresh decision for one fetched link.
type LinkMatch struct {
	Fetched            *profile.Link
	Current            *profile.Link
	New                bool
	CredentialsChanged bool
	MatchedByRemark    bool
	Ambiguous          bool
}

// MatchLinks matches the links a subscription just returned against the links
// it previously produced. It uses the same T1/T2/T3 rules as the index so a
// refresh preserves ids, names and history.
func MatchLinks(bucket string, current, fetched []*profile.Link) (matches []LinkMatch, orphaned []*profile.Link, ambiguous int) {
	entries := make([]Entry, len(current))
	for i, l := range current {
		id := IdentityFor(l, bucket)
		entries[i] = Entry{
			ID: itoa(i), SourceID: id.SourceID, Protocol: id.Protocol,
			Address: id.Address, Port: id.Port, Transport: id.Transport,
			SecretHash: id.SecretHash, RawHash: id.RawHash, Bucket: bucket, Remark: id.Remark,
		}
	}
	var items []Item
	for i, l := range fetched {
		items = append(items, ItemFromLink(l, bucket, i))
	}
	res := MatchEntries(entries, items)
	ambiguous = res.Ambiguous
	seen := map[int]bool{}
	for _, m := range res.Matches {
		lm := LinkMatch{
			Fetched: m.Item.Link, New: m.Entry == nil,
			CredentialsChanged: m.CredentialsChanged,
			MatchedByRemark:    m.MatchedByRemark,
			Ambiguous:          m.Ambiguous,
		}
		if m.Entry != nil {
			idx := atoi(m.Entry.ID)
			if idx >= 0 && idx < len(current) {
				lm.Current = current[idx]
				seen[idx] = true
			}
		}
		matches = append(matches, lm)
	}
	for i, l := range current {
		if !seen[i] {
			orphaned = append(orphaned, l)
		}
	}
	return matches, orphaned, ambiguous
}

func atoi(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return -1
		}
		n = n*10 + int(r-'0')
	}
	return n
}
