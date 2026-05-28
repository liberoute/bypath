package profile

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// FetchSubscription downloads and parses a subscription URL.
// Returns a list of parsed links.
func FetchSubscription(subURL string) ([]*Link, error) {
	client := &http.Client{Timeout: 30 * time.Second}

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
func (m *Manager) UpdateSubscriptions(groupName string) (int, error) {
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
		links, err := FetchSubscription(subURL)
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
