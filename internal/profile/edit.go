package profile

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SourceIDFor returns the stable, non-secret identifier used to mark links that
// came from one subscription URL.
func SourceIDFor(subURL string) string {
	sum := sha256.Sum256([]byte(normalizeSubURL(subURL)))
	return hex.EncodeToString(sum[:8])
}

// RenameLink changes a link's display name inside one group and keeps the
// persisted active selection pointing at it.
func (m *Manager) RenameLink(group, oldRemark, newRemark string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	newRemark = strings.TrimSpace(newRemark)
	if oldRemark == "" || newRemark == "" {
		return fmt.Errorf("link name cannot be empty")
	}
	if oldRemark == newRemark {
		return nil
	}
	g, ok := m.groups[group]
	if !ok {
		return fmt.Errorf("group '%s' not found", group)
	}
	for _, l := range g.Links {
		if l.Remark == newRemark {
			return fmt.Errorf("a connection named '%s' already exists in group '%s'", newRemark, group)
		}
	}
	var target *Link
	for _, l := range g.Links {
		if l.Remark == oldRemark {
			target = l
			break
		}
	}
	if target == nil {
		return fmt.Errorf("connection '%s' not found in group '%s'", oldRemark, group)
	}

	target.Remark = newRemark
	if err := m.saveGroup(g); err != nil {
		target.Remark = oldRemark
		return err
	}
	m.rewriteActive(func(activeGroup, activeRemark string) (string, string) {
		if activeGroup == group && activeRemark == oldRemark {
			return group, newRemark
		}
		return activeGroup, activeRemark
	})
	return nil
}

// ClearActiveIf removes the persisted active selection when it points at the
// given link, so a deleted connection cannot remain "active".
func (m *Manager) ClearActiveIf(group, remark string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	path := filepath.Join(m.directory, ".active")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) >= 2 && strings.TrimSpace(lines[0]) == group && strings.TrimSpace(lines[1]) == remark {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if m.activeLink != nil && m.activeLink.Group == group && m.activeLink.Remark == remark {
		m.activeLink = nil
	}
	return nil
}

// rewriteActive applies fn to the persisted active pair, if readable.
func (m *Manager) rewriteActive(fn func(group, remark string) (string, string)) {
	path := filepath.Join(m.directory, ".active")
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	group, remark := strings.TrimSpace(lines[0]), ""
	if len(lines) >= 2 {
		remark = strings.TrimSpace(lines[1])
	}
	ng, nr := fn(group, remark)
	if ng == group && nr == remark {
		return
	}
	_ = os.WriteFile(path, []byte(ng+"\n"+nr), 0600)
}

// RecordSubscription stores the outcome of one refresh without touching links.
func (m *Manager) RecordSubscription(group, subURL, lastRefresh, lastError string, count int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.groups[group]
	if !ok {
		return fmt.Errorf("group '%s' not found", group)
	}
	setSubscriptionMeta(g, normalizeSubURL(subURL), SubscriptionInfo{
		URL:         normalizeSubURL(subURL),
		LastRefresh: lastRefresh,
		LastError:   lastError,
		LinkCount:   count,
	})
	return m.saveGroup(g)
}

// ReplaceSubscription atomically swaps the links owned by one subscription.
// Manual links and links from other subscriptions in the same group are kept.
// On a failed fetch (fetched == nil, lastError != "") existing links stay in
// place and only the error is recorded: a transient outage must not destroy a
// working profile set.
func (m *Manager) ReplaceSubscription(group, subURL, sourceID string, fetched []*Link, lastRefresh, lastError string) (added, removed int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	g, ok := m.groups[group]
	if !ok {
		return 0, 0, fmt.Errorf("group '%s' not found", group)
	}
	normalized := normalizeSubURL(subURL)

	if fetched != nil {
		kept := make([]*Link, 0, len(g.Links)+len(fetched))
		for _, l := range g.Links {
			if sourceID != "" && l.SourceID == sourceID {
				removed++
				continue
			}
			kept = append(kept, l)
		}
		seen := make(map[string]bool, len(kept)+len(fetched))
		for _, l := range kept {
			seen[l.RawURI+"|"+l.Address+"|"+fmt.Sprint(l.Port)] = true
		}
		for _, l := range fetched {
			key := l.RawURI + "|" + l.Address + "|" + fmt.Sprint(l.Port)
			if seen[key] {
				continue
			}
			seen[key] = true
			l.Group = group
			l.SourceID = sourceID
			kept = append(kept, l)
			added++
		}
		g.Links = kept
	}
	if lastRefresh == "" {
		lastRefresh = time.Now().UTC().Format(time.RFC3339)
	}
	setSubscriptionMeta(g, normalized, SubscriptionInfo{
		URL:         normalized,
		LastRefresh: lastRefresh,
		LastError:   lastError,
		LinkCount:   added,
	})
	if err := m.saveGroup(g); err != nil {
		return 0, 0, err
	}
	return added, removed, nil
}

// AddLinks appends several links to a group in one save. Used by subscription
// and bulk imports so a hundred imported servers do not write the file a
// hundred times.
func (m *Manager) AddLinks(group string, links []*Link) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.groups[group]
	if !ok {
		g = &Group{Name: group, Type: "basic", Links: make([]*Link, 0)}
		m.groups[group] = g
	}
	for _, l := range links {
		l.Group = group
		g.Links = append(g.Links, l)
	}
	return m.saveGroup(g)
}

// DropSubscription removes a subscription URL, its refresh metadata and every
// link it produced, in one save.
func (m *Manager) DropSubscription(group, subURL string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.groups[group]
	if !ok {
		return fmt.Errorf("group '%s' not found", group)
	}
	want := normalizeSubURL(subURL)
	sourceID := SourceIDFor(want)
	keptSubs := make([]string, 0, len(g.Subscriptions))
	for _, u := range g.Subscriptions {
		if normalizeSubURL(u) != want {
			keptSubs = append(keptSubs, u)
		}
	}
	keptMeta := make([]SubscriptionInfo, 0, len(g.SubscriptionMeta))
	for _, info := range g.SubscriptionMeta {
		if normalizeSubURL(info.URL) != want {
			keptMeta = append(keptMeta, info)
		}
	}
	keptLinks := make([]*Link, 0, len(g.Links))
	for _, l := range g.Links {
		if l.SourceID == sourceID && l.SourceID != "" {
			continue
		}
		keptLinks = append(keptLinks, l)
	}
	g.Subscriptions = keptSubs
	g.SubscriptionMeta = keptMeta
	g.Links = keptLinks
	return m.saveGroup(g)
}

// ReplaceSource swaps the links owned by one source while keeping every other
// link in the group untouched. It is the layer-aware refresh path: the caller
// supplies the final set for that source (including entries the provider
// removed, which stay usable and are flagged orphaned by the layer).
func (m *Manager) ReplaceSource(group, sourceID, subURL, lastRefresh, lastError string, links []*Link) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	g, ok := m.groups[group]
	if !ok {
		return fmt.Errorf("group '%s' not found", group)
	}
	kept := make([]*Link, 0, len(g.Links)+len(links))
	for _, l := range g.Links {
		if sourceID != "" && l.SourceID == sourceID {
			continue
		}
		kept = append(kept, l)
	}
	for _, l := range links {
		if l == nil {
			continue
		}
		l.Group = group
		if sourceID != "" {
			l.SourceID = sourceID
		}
		kept = append(kept, l)
	}
	g.Links = kept
	if lastRefresh == "" {
		lastRefresh = time.Now().UTC().Format(time.RFC3339)
	}
	setSubscriptionMeta(g, normalizeSubURL(subURL), SubscriptionInfo{
		URL:         normalizeSubURL(subURL),
		LastRefresh: lastRefresh,
		LastError:   lastError,
		LinkCount:   len(links),
	})
	return m.saveGroup(g)
}

func setSubscriptionMeta(g *Group, url string, info SubscriptionInfo) {
	for i := range g.SubscriptionMeta {
		if normalizeSubURL(g.SubscriptionMeta[i].URL) == url {
			g.SubscriptionMeta[i] = info
			return
		}
	}
	g.SubscriptionMeta = append(g.SubscriptionMeta, info)
}

// SubscriptionMetaFor returns the recorded refresh state for one URL.
func (m *Manager) SubscriptionMetaFor(group, subURL string) (SubscriptionInfo, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	g, ok := m.groups[group]
	if !ok {
		return SubscriptionInfo{}, false
	}
	want := normalizeSubURL(subURL)
	for _, info := range g.SubscriptionMeta {
		if normalizeSubURL(info.URL) == want {
			return info, true
		}
	}
	return SubscriptionInfo{}, false
}
