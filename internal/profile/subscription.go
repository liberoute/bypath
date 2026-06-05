package profile

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
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

// FetchSubscription downloads and parses a subscription URL.
//
//   - socksPort > 0 and bypath is running: route through the bypath SOCKS proxy
//     so DNS and HTTP both go through the tunnel (ISP can't intercept).
//   - Otherwise: use direct DNS (8.8.8.8) to bypass a stale resolv.conf left
//     by a previous bypath run, allowing sub update when bypath is stopped.
func FetchSubscription(subURL string, socksPort int) ([]*Link, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()

	if socksPort > 0 && bypathDNSActive() {
		// bypath is running: use its SOCKS proxy so requests go through the tunnel.
		if u, err := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", socksPort)); err == nil {
			transport.Proxy = http.ProxyURL(u)
		}
	} else {
		// bypath not running (or no port given): direct DNS to bypass stale resolv.conf.
		transport.DialContext = (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
			Resolver: &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "udp", "8.8.8.8:53")
				},
			},
		}).DialContext
	}

	// Check for proxy from environment (supports socks5h:// via ALL_PROXY)
	proxyURL := os.Getenv("ALL_PROXY")
	if proxyURL == "" {
		proxyURL = os.Getenv("all_proxy")
	}
	if proxyURL == "" {
		proxyURL = os.Getenv("https_proxy")
	}
	if proxyURL == "" {
		proxyURL = os.Getenv("HTTPS_PROXY")
	}
	if proxyURL != "" {
		// Convert socks5h:// to socks5:// for Go's proxy support
		proxyURL = strings.Replace(proxyURL, "socks5h://", "socks5://", 1)
		if u, err := url.Parse(proxyURL); err == nil {
			transport.Proxy = http.ProxyURL(u)
		}
	}
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}

	resp, err := client.Get(subURL)
	if err != nil {
		return nil, fmt.Errorf("fetching subscription: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("subscription returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading subscription body: %w", err)
	}

	// Try to decode as base64 (most subscriptions are base64-encoded)
	content := string(body)
	if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(content)); err == nil {
		content = string(decoded)
	} else if decoded, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(content)); err == nil {
		content = string(decoded)
	}

	// Parse each line as a URI
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

// AddSubscription adds a subscription URL to a group.
func (m *Manager) AddSubscription(groupName, subURL string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	g, ok := m.groups[groupName]
	if !ok {
		return fmt.Errorf("group '%s' not found", groupName)
	}

	// Check for duplicates
	for _, existing := range g.Subscriptions {
		if existing == subURL {
			return fmt.Errorf("subscription already exists in group '%s'", groupName)
		}
	}

	g.Subscriptions = append(g.Subscriptions, subURL)
	return m.saveGroup(g)
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
