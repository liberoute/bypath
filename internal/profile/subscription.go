package profile

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// bypathDNSActive returns true when bypath has taken over /etc/resolv.conf
// (pointing it to 127.0.0.1 = the local dns2socks). In that state the SOCKS
// proxy must be used for outbound HTTP, otherwise direct DNS to 8.8.8.8 is
// intercepted by the ISP and subscription URLs can't be resolved.
func bypathDNSActive() bool {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "127.0.0.1")
}

// socksListening reports whether a local SOCKS port accepts TCP connections.
func socksListening(port int) bool {
	if port <= 0 {
		return false
	}
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 300*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// normalizeSubURL strips fragments and trims whitespace from subscription URLs.
func normalizeSubURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		// Fallback: drop anything after '#'
		if i := strings.Index(raw, "#"); i >= 0 {
			return raw[:i]
		}
		return raw
	}
	u.Fragment = ""
	u.RawFragment = ""
	return u.String()
}

// envProxyURL returns the first configured outbound proxy from the environment.
func envProxyURL() string {
	for _, key := range []string{"ALL_PROXY", "all_proxy", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		if v := os.Getenv(key); v != "" {
			return strings.Replace(v, "socks5h://", "socks5://", 1)
		}
	}
	return ""
}

// FetchSubscription downloads and parses a subscription URL.
//
// Tries in order:
//  1. Env proxy (ALL_PROXY / HTTPS_PROXY / …)
//  2. Local bypath SOCKS if the port is actually listening (running tunnel)
//  3. Direct with Go DNS via 8.8.8.8 (bypass stale resolv.conf)
//
// Direct fetch often fails in IR (TLS timeout on panel ports like :2083);
// run bypath on a working link first, then `sub update` through SOCKS.
func FetchSubscription(subURL string, socksPort int) ([]*Link, error) {
	subURL = normalizeSubURL(subURL)
	if subURL == "" {
		return nil, fmt.Errorf("empty subscription URL")
	}

	var lastErr error
	for _, attempt := range subFetchAttempts(socksPort) {
		links, err := fetchSubscriptionOnce(subURL, attempt)
		if err == nil {
			if attempt.label != "direct" {
				log.Printf("  ✅ Fetched via %s", attempt.label)
			}
			return links, nil
		}
		lastErr = err
		log.Printf("  ⚠️  %s failed: %v", attempt.label, err)
	}
	return nil, fmt.Errorf("fetching subscription: %w", lastErr)
}

type subFetchAttempt struct {
	label   string
	proxy   string // socks5://... or http://... ; empty = direct
	useDoH  bool   // pin dialer DNS to 8.8.8.8 when direct
}

func subFetchAttempts(socksPort int) []subFetchAttempt {
	var out []subFetchAttempt
	if p := envProxyURL(); p != "" {
		out = append(out, subFetchAttempt{label: "env-proxy", proxy: p})
	}
	// Prefer tunnel whenever SOCKS is up — not only when resolv.conf points at 127.0.0.1.
	// (proxy-only mode / partial start still has SOCKS without DNS takeover.)
	if socksListening(socksPort) {
		out = append(out, subFetchAttempt{
			label: fmt.Sprintf("socks5://127.0.0.1:%d", socksPort),
			proxy: fmt.Sprintf("socks5://127.0.0.1:%d", socksPort),
		})
	} else if socksPort > 0 && bypathDNSActive() {
		// DNS taken over but port check failed — still try (race during restart).
		out = append(out, subFetchAttempt{
			label: fmt.Sprintf("socks5://127.0.0.1:%d", socksPort),
			proxy: fmt.Sprintf("socks5://127.0.0.1:%d", socksPort),
		})
	}
	out = append(out, subFetchAttempt{label: "direct", useDoH: true})
	return out
}

func fetchSubscriptionOnce(subURL string, attempt subFetchAttempt) ([]*Link, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSHandshakeTimeout = 15 * time.Second
	transport.ResponseHeaderTimeout = 20 * time.Second

	if attempt.proxy != "" {
		u, err := url.Parse(attempt.proxy)
		if err != nil {
			return nil, fmt.Errorf("bad proxy URL: %w", err)
		}
		transport.Proxy = http.ProxyURL(u)
	} else if attempt.useDoH {
		transport.Proxy = nil
		transport.DialContext = (&net.Dialer{
			Timeout:   12 * time.Second,
			KeepAlive: 30 * time.Second,
			Resolver: &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
					return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "udp", "8.8.8.8:53")
				},
			},
		}).DialContext
	}

	client := &http.Client{
		Timeout:   45 * time.Second,
		Transport: transport,
	}

	req, err := http.NewRequest(http.MethodGet, subURL, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid subscription URL: %w", err)
	}
	req.Header.Set("User-Agent", "v2rayN/6.45")
	req.Header.Set("Accept", "text/plain, */*")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("reading body: %w", err)
	}

	return parseSubscriptionBody(string(body))
}

func parseSubscriptionBody(content string) ([]*Link, error) {
	// Try to decode as base64 (most subscriptions are base64-encoded)
	trimmed := strings.TrimSpace(content)
	if decoded, err := base64.StdEncoding.DecodeString(trimmed); err == nil {
		content = string(decoded)
	} else if decoded, err := base64.RawStdEncoding.DecodeString(trimmed); err == nil {
		content = string(decoded)
	} else if decoded, err := base64.URLEncoding.DecodeString(trimmed); err == nil {
		content = string(decoded)
	} else if decoded, err := base64.RawURLEncoding.DecodeString(trimmed); err == nil {
		content = string(decoded)
	}

	lines := strings.Split(content, "\n")
	var links []*Link
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		link, err := ParseURI(line)
		if err != nil {
			log.Printf("  ⚠️  Skipping unparseable link: %v", err)
			continue
		}
		links = append(links, link)
	}
	if len(links) == 0 {
		return nil, fmt.Errorf("no valid links found in subscription")
	}
	return links, nil
}

// ImportSubscriptionFile loads a local subscription dump (plain URIs or base64) into a group.
// Use when the Pi cannot reach the panel (TLS timeout) — fetch on a free network and scp the file.
func (m *Manager) ImportSubscriptionFile(groupName, filePath string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	g, ok := m.groups[groupName]
	if !ok {
		return 0, fmt.Errorf("group '%s' not found", groupName)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return 0, fmt.Errorf("reading %s: %w", filePath, err)
	}

	links, err := parseSubscriptionBody(string(data))
	if err != nil {
		return 0, err
	}
	for _, link := range links {
		link.Group = groupName
	}
	g.Links = links
	if err := m.saveGroup(g); err != nil {
		return 0, err
	}
	return len(links), nil
}

// UpdateSubscriptions fetches all subscriptions for a group and updates its links.
// socksPort is the bypath SOCKS port (from config); pass 0 if unknown.
func (m *Manager) UpdateSubscriptions(groupName string, socksPort int) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	g, ok := m.groups[groupName]
	if !ok {
		return 0, fmt.Errorf("group '%s' not found", groupName)
	}

	if len(g.Subscriptions) == 0 {
		return 0, fmt.Errorf("group '%s' has no subscriptions", groupName)
	}

	var allLinks []*Link

	for _, subURL := range g.Subscriptions {
		log.Printf("  📡 Fetching: %s", truncate(subURL, 50))
		links, err := FetchSubscription(subURL, socksPort)
		if err != nil {
			log.Printf("  ⚠️  Failed: %v", err)
			continue
		}
		for _, link := range links {
			link.Group = groupName
		}
		allLinks = append(allLinks, links...)
	}

	if len(allLinks) == 0 {
		return 0, fmt.Errorf("no links fetched from any subscription")
	}

	// Replace all links in the group
	g.Links = allLinks

	if err := m.saveGroup(g); err != nil {
		return 0, err
	}

	return len(allLinks), nil
}

// ErrSubscriptionExists is returned when the same subscription URL is already registered.
var ErrSubscriptionExists = errors.New("subscription already exists")

// FindSubscription returns the group name that already holds this subscription URL
// (compared after normalizeSubURL: strip fragment, trim, etc.). ok=false if none.
func (m *Manager) FindSubscription(subURL string) (groupName string, ok bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	want := normalizeSubURL(subURL)
	if want == "" {
		return "", false
	}
	for name, g := range m.groups {
		for _, existing := range g.Subscriptions {
			if normalizeSubURL(existing) == want {
				return name, true
			}
		}
	}
	return "", false
}

// AddSubscriptionResult describes what AddSubscription did.
type AddSubscriptionResult struct {
	Group    string
	URL      string
	Existed  bool   // true if URL was already present (no change)
	Created  bool   // true if the target group was created in this call path (set by CLI)
	Message  string
}

// AddSubscription adds a subscription URL to a group.
// Duplicate URLs (same after normalize, including across other groups) are rejected
// with ErrSubscriptionExists — caller should surface the existing group name via FindSubscription.
func (m *Manager) AddSubscription(groupName, subURL string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	g, ok := m.groups[groupName]
	if !ok {
		return fmt.Errorf("group '%s' not found", groupName)
	}

	subURL = normalizeSubURL(subURL)
	if subURL == "" {
		return fmt.Errorf("empty subscription URL")
	}

	// Global duplicate check (same panel URL must not land in two groups).
	for name, other := range m.groups {
		for _, existing := range other.Subscriptions {
			if normalizeSubURL(existing) == subURL {
				if name == groupName {
					return fmt.Errorf("%w in group '%s'", ErrSubscriptionExists, groupName)
				}
				return fmt.Errorf("%w in group '%s' (not adding again to '%s')", ErrSubscriptionExists, name, groupName)
			}
		}
	}

	g.Subscriptions = append(g.Subscriptions, subURL)
	return m.saveGroup(g)
}

// DedupeSubscriptions normalizes and unique-ifies subscription URLs in every group.
// Returns how many duplicate entries were removed.
func (m *Manager) DedupeSubscriptions() (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	removed := 0
	seenGlobal := map[string]string{} // normalized URL → first group name

	for _, name := range sortedGroupNames(m.groups) {
		g := m.groups[name]
		if g == nil || len(g.Subscriptions) == 0 {
			continue
		}
		var kept []string
		changed := false
		for _, raw := range g.Subscriptions {
			n := normalizeSubURL(raw)
			if n == "" {
				removed++
				changed = true
				continue
			}
			if owner, ok := seenGlobal[n]; ok {
				// Drop local dupes and cross-group dups (keep first owner).
				removed++
				changed = true
				if owner != name {
					log.Printf("  ℹ️  Dropped duplicate sub in '%s' (already in '%s')", name, owner)
				}
				continue
			}
			seenGlobal[n] = name
			if raw != n {
				changed = true
			}
			kept = append(kept, n)
		}
		if changed {
			g.Subscriptions = kept
			if err := m.saveGroup(g); err != nil {
				return removed, err
			}
		}
	}
	return removed, nil
}

func sortedGroupNames(groups map[string]*Group) []string {
	names := make([]string, 0, len(groups))
	for n := range groups {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// RemoveSubscription removes a subscription URL from a group by index.
func (m *Manager) RemoveSubscription(groupName string, idx int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	g, ok := m.groups[groupName]
	if !ok {
		return fmt.Errorf("group '%s' not found", groupName)
	}

	if idx < 0 || idx >= len(g.Subscriptions) {
		return fmt.Errorf("subscription index %d out of range (group has %d subscriptions)", idx+1, len(g.Subscriptions))
	}

	g.Subscriptions = append(g.Subscriptions[:idx], g.Subscriptions[idx+1:]...)
	return m.saveGroup(g)
}
