package app

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/liberoute/bypath/internal/layer"
	"github.com/liberoute/bypath/internal/profile"
)

const (
	// refreshTimeout bounds one subscription refresh so a wedged panel cannot
	// hold a UI or API request open forever.
	refreshTimeout = 120 * time.Second
)

var subscriptionURLInError = regexp.MustCompile(`https?://[^\s"']+`)

// redactSubscriptionError strips panel URLs (which carry tokens) from fetch
// errors before they are stored or displayed.
func redactSubscriptionError(err error) string {
	if err == nil {
		return ""
	}
	return Redact(subscriptionURLInError.ReplaceAllString(err.Error(), "<redacted-url>"))
}

// ListSubscriptions returns every registered subscription with its recorded
// refresh state. URLs are redacted for display.
func (s *Local) ListSubscriptions(ctx context.Context) ([]Subscription, error) {
	s.refreshMu.Lock()
	running := make(map[string]bool, len(s.refresh))
	for k := range s.refresh {
		running[k] = true
	}
	s.refreshMu.Unlock()

	var out []Subscription
	for _, name := range s.profiles.ListGroups() {
		g, err := s.profiles.GetGroup(name)
		if err != nil {
			continue
		}
		for _, raw := range g.Subscriptions {
			sub := Subscription{Group: name, URL: raw, RedactedURL: redactURL(raw)}
			for _, info := range g.SubscriptionMeta {
				if strings.TrimSpace(info.URL) == raw || info.URL == raw {
					sub.LastRefresh = info.LastRefresh
					sub.LastError = info.LastError
				}
			}
			// Count the links that actually exist. The metadata count is only a
			// hint from the last fetch and double-counts when both are added.
			sourceID := profile.SourceIDFor(raw)
			for _, l := range g.Links {
				if l.SourceID == sourceID {
					sub.LinkCount++
					if len(sub.Connection) < 8 {
						sub.Connection = append(sub.Connection, l.Remark)
					}
				}
			}
			sub.Refreshing = running[name+"|"+raw]
			out = append(out, s.describeSubscription(sub))
		}
	}
	return out, nil
}

// PreviewSubscription fetches a subscription with a bounded context and
// describes what it contains without storing anything. The returned entries are
// secret-free: no raw URI, UUID or key material leaves the service.
func (s *Local) PreviewSubscription(ctx context.Context, rawURL string) (SubscriptionPreview, error) {
	rawURL = strings.TrimSpace(rawURL)
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return SubscriptionPreview{}, errorf(CodeInvalid, "subscription URL must be an absolute http(s) URL")
	}
	ctx, cancel := context.WithTimeout(ctx, refreshTimeout)
	defer cancel()
	text, err := profile.FetchSubscriptionTextContext(ctx, rawURL, s.Config().Server.SOCKSPort)
	if err != nil {
		msg := redactSubscriptionError(err)
		if ctx.Err() != nil {
			msg = "preview cancelled or timed out"
		}
		return SubscriptionPreview{}, &Error{Code: CodeUnavailable, Message: "subscription preview failed: " + msg, Err: err}
	}
	out, perr := s.previewFromText(text, s.proposedSubscriptionName(groupLabelForURL(rawURL)), redactURL(rawURL))
	if perr != nil {
		return SubscriptionPreview{}, perr
	}
	return out, nil
}

// PreviewSubscriptionText describes a pasted or uploaded dump without storing
// it. The parser is the same one used by URL refreshes.
func (s *Local) PreviewSubscriptionText(ctx context.Context, text string) (SubscriptionPreview, error) {
	return s.previewFromText(text, s.proposedSubscriptionName("imported"), "<pasted subscription dump>")
}

// previewFromText classifies rejected entries so a Shadowrocket-style import
// shows parse_failure and unsupported_configuration before anything is stored.
func (s *Local) previewFromText(text, group, redacted string) (SubscriptionPreview, error) {
	links, diagnostics, perr := profile.ParseSubscriptionDetailed(text)
	out := s.buildPreview(links, group, redacted)
	out.Rejected = diagnostics
	out.RejectedCount = len(diagnostics)
	if len(links) == 0 && len(diagnostics) == 0 {
		return SubscriptionPreview{}, &Error{Code: CodeInvalid, Message: "no valid links found in subscription", Err: perr}
	}
	return out, nil
}

const maxPreviewLinks = 100

func (s *Local) buildPreview(links []*profile.Link, group, redacted string) SubscriptionPreview {
	existing := s.existingURIs()
	out := SubscriptionPreview{Group: group, RedactedURL: redacted, Total: len(links)}
	for _, l := range links {
		if existing[strings.TrimSpace(l.RawURI)] {
			out.Duplicates++
			continue
		}
		if len(out.Links) >= maxPreviewLinks {
			out.Truncated = true
			continue
		}
		out.Links = append(out.Links, SubscriptionLink{
			Remark:         l.Remark,
			Protocol:       l.Protocol,
			Address:        l.Address,
			Port:           l.Port,
			Network:        l.Network,
			Engine:         EngineFor(l),
			TLS:            l.TLS,
			Reality:        l.RealityPublicKey != "",
			EncryptedVLESS: l.EncryptedVLESS(),
			CDN:            profile.IsCDNPattern(l),
		})
	}
	return out
}

// AddSubscription registers a subscription URL. Only http(s) URLs are accepted;
// any other scheme (file:, ftp:, ssh:) is rejected so the panel cannot be turned
// into a local file reader.
func (s *Local) AddSubscription(ctx context.Context, group, rawURL string) (Subscription, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return Subscription{}, errorf(CodeInvalid, "subscription URL is empty")
	}
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return Subscription{}, errorf(CodeInvalid, "subscription URL must be an absolute http(s) URL")
	}
	s.switchMu.Lock()
	defer s.switchMu.Unlock()
	if owner, exists := s.profiles.FindSubscription(rawURL); exists {
		return Subscription{}, errorf(CodeConflict, "subscription already exists in import list %q", owner)
	}
	if group == "" {
		group = s.proposedSubscriptionName(groupLabelForURL(rawURL))
	}
	if err := validGroupName(group); err != nil {
		return Subscription{}, err
	}
	u.Fragment, u.RawFragment = "", ""
	rawURL = u.String()
	_, err = s.applySubscriptionChange(group, subscriptionIdentity(rawURL), group, false, nil, func() error {
		if _, err := s.profiles.GetGroup(group); err != nil {
			if err := s.profiles.CreateGroup(group, "subscription"); err != nil {
				return err
			}
		}
		return s.profiles.AddSubscription(group, rawURL)
	})
	if err != nil {
		return Subscription{}, err
	}
	return s.describeSubscription(Subscription{Group: group, URL: rawURL, RedactedURL: redactURL(rawURL)}), nil
}

// RefreshSubscription fetches one subscription with a bounded, cancellable
// context. Existing links survive a failed fetch; only the error is recorded.
func (s *Local) RefreshSubscription(ctx context.Context, group, rawURL string, progress func(RefreshProgress)) (Subscription, error) {
	s.switchMu.Lock()
	registered, registrationErr := s.registeredSubscription(group, rawURL)
	s.switchMu.Unlock()
	if registrationErr != nil {
		return Subscription{}, registrationErr
	}
	rawURL = registered
	key := group + "|" + rawURL
	s.refreshMu.Lock()
	if _, busy := s.refresh[key]; busy {
		s.refreshMu.Unlock()
		return Subscription{}, errorf(CodeConflict, "a refresh for this subscription is already running")
	}
	ctx, cancel := context.WithTimeout(ctx, refreshTimeout)
	s.refresh[key] = cancel
	s.refreshMu.Unlock()

	defer func() {
		cancel()
		s.refreshMu.Lock()
		delete(s.refresh, key)
		s.refreshMu.Unlock()
	}()

	notify := func(p RefreshProgress) {
		if progress != nil {
			progress(p)
		}
	}
	notify(RefreshProgress{Group: group, URL: rawURL})

	links, err := profile.FetchSubscriptionContext(ctx, rawURL, s.Config().Server.SOCKSPort)
	now := time.Now().UTC().Format(time.RFC3339)
	if err == nil {
		if keyErr := rejectRemoteKeyPaths(links); keyErr != nil {
			_ = s.profiles.RecordSubscription(group, rawURL, now, "refused: SSH key path", 0)
			notify(RefreshProgress{Group: group, URL: rawURL, Done: true, Err: "refused: SSH key path"})
			return Subscription{Group: group, URL: rawURL, RedactedURL: redactURL(rawURL), LastRefresh: now, LastError: "refused: SSH key path"}, keyErr
		}
	}
	if err != nil {
		msg := redactSubscriptionError(err)
		if ctx.Err() != nil {
			msg = "refresh cancelled or timed out"
		}
		_ = s.profiles.RecordSubscription(group, rawURL, now, msg, 0)
		notify(RefreshProgress{Group: group, URL: rawURL, Done: true, Err: msg})
		return Subscription{Group: group, URL: rawURL, RedactedURL: redactURL(rawURL), LastRefresh: now, LastError: msg}, &Error{
			Code:    CodeUnavailable,
			Message: "subscription refresh failed: " + msg,
			Err:     err,
		}
	}

	s.switchMu.Lock()
	if _, err := s.registeredSubscription(group, rawURL); err != nil {
		s.switchMu.Unlock()
		return Subscription{}, err
	}
	sourceID := profile.SourceIDFor(rawURL)
	merged, _, orphaned := s.mergeFetchedSourceLinks(group, sourceID, links)
	_, saveErr := s.applySubscriptionChange(group, subscriptionIdentity(rawURL), "", false, orphaned, func() error {
		return s.profiles.ReplaceSource(group, sourceID, rawURL, now, "", merged)
	})
	s.switchMu.Unlock()
	if saveErr != nil {
		return Subscription{}, saveErr
	}
	notify(RefreshProgress{Group: group, URL: rawURL, Done: true, Links: len(merged)})
	return s.describeSubscription(Subscription{
		Group:       group,
		URL:         rawURL,
		RedactedURL: redactURL(rawURL),
		LinkCount:   len(merged),
		LastRefresh: now,
	}), nil
}

// mergeFetchedLinks reconciles a fetch with the links this source already
// produced. A connection the provider dropped is kept (orphaned) instead of
// deleted, and every matched connection keeps its stored remark so the
// persisted .active selection cannot be invalidated by a refresh.
func (s *Local) mergeFetchedLinks(group, sourceID string, fetched []*profile.Link) ([]*profile.Link, []string) {
	merged, orphanedIDs, _ := s.mergeFetchedSourceLinks(group, sourceID, fetched)
	return merged, orphanedIDs
}

func (s *Local) mergeFetchedSourceLinks(group, sourceID string, fetched []*profile.Link) ([]*profile.Link, []string, []string) {
	var current []*profile.Link
	if g, err := s.profiles.GetGroup(group); err == nil {
		for _, l := range g.Links {
			if l.SourceID == sourceID {
				current = append(current, l)
			}
		}
	}
	// Fetched links carry no provenance until they are stored, and identity is
	// keyed by source. Stamp them before matching: an unstamped link is treated
	// as a manual link in this bucket, so nothing a refresh fetches can ever
	// match what the same source produced last time.
	for _, l := range fetched {
		if l == nil {
			continue
		}
		l.Group = group
		l.SourceID = sourceID
	}
	matches, orphaned, _ := layer.MatchLinks(group, current, fetched)
	used := s.usedRemarks(group)
	var merged []*profile.Link
	for _, m := range matches {
		l := m.Fetched
		if l == nil {
			continue
		}
		l.Group = group
		l.SourceID = sourceID
		if m.Current != nil {
			l.Remark = m.Current.Remark
			if l.HTTPSCapable == 0 {
				l.HTTPSCapable = m.Current.HTTPSCapable
			}
			used[l.Remark] = true
		} else {
			l.Remark = uniqueName(used, l.Remark)
			used[l.Remark] = true
		}
		merged = append(merged, l)
	}
	var orphanedIDs, orphanedRemarks []string
	for _, old := range orphaned {
		orphanedRemarks = append(orphanedRemarks, old.Remark)
		old.Group = group
		old.SourceID = sourceID
		merged = append(merged, old)
		used[old.Remark] = true
		if s.layer != nil {
			if e, ok := s.layer.EntryForLink(group, old.Remark); ok {
				orphanedIDs = append(orphanedIDs, e.ID)
			}
		}
	}
	return merged, orphanedIDs, orphanedRemarks
}

// rejectRemoteKeyPaths refuses subscription links that name a private-key file.
// A subscription is untrusted input; the daemon runs as root and must not let
// its author choose the key file its ssh client authenticates with.
func rejectRemoteKeyPaths(links []*profile.Link) error {
	for _, l := range links {
		if l != nil && l.SSHKeyPath != "" {
			return errorf(CodeInvalid, "link %q names an SSH key file; key-file authentication is not accepted from subscriptions", l.Remark)
		}
	}
	return nil
}

// ImportSubscriptionText imports a pasted or uploaded subscription dump. Links
// are deduplicated against the whole installation; the same server is never
// stored twice.
func (s *Local) ImportSubscriptionText(ctx context.Context, group, text string) (ImportResult, error) {
	s.switchMu.Lock()
	defer s.switchMu.Unlock()
	if group == "" {
		group = s.proposedSubscriptionName("imported")
	}
	if err := validGroupName(group); err != nil {
		return ImportResult{}, err
	}
	links, diagnostics, err := profile.ParseSubscriptionDetailed(text)
	if len(links) == 0 {
		if err == nil {
			err = &profile.ParseError{Category: "parse_failure", Message: "no valid links found in subscription"}
		}
		return ImportResult{Group: group, Diagnostics: diagnostics}, &Error{Code: CodeInvalid, Message: err.Error(), Err: err}
	}
	if err := rejectRemoteKeyPaths(links); err != nil {
		return ImportResult{}, err
	}
	seen := s.existingURIs()
	usedNames := s.usedRemarks(group)
	var batch []*profile.Link
	result := ImportResult{Group: group, Diagnostics: diagnostics}
	for _, l := range links {
		if seen[l.RawURI] {
			result.Skipped = append(result.Skipped, Skipped{Name: l.Remark, Reason: "identical link already exists"})
			continue
		}
		seen[l.RawURI] = true
		l.Remark = uniqueName(usedNames, l.Remark)
		usedNames[l.Remark] = true
		batch = append(batch, l)
		l.Group = group
	}
	if len(batch) == 0 {
		return result, nil
	}
	if _, err := s.applySubscriptionChange(group, "manual:"+group, group, false, nil, func() error {
		if _, err := s.profiles.GetGroup(group); err != nil {
			if err := s.profiles.CreateGroup(group, "subscription"); err != nil {
				return err
			}
		}
		return s.profiles.AddLinks(group, batch)
	}); err != nil {
		return ImportResult{}, err
	}
	for _, l := range batch {
		result.Created = append(result.Created, s.viewConnection(l, ConnectionID(group, l.Remark), s.activeID(), nil))
	}
	return result, nil
}

func (s *Local) existingURIs() map[string]bool {
	seen := make(map[string]bool)
	for _, name := range s.profiles.ListGroups() {
		g, err := s.profiles.GetGroup(name)
		if err != nil {
			continue
		}
		for _, l := range g.Links {
			seen[strings.TrimSpace(l.RawURI)] = true
		}
	}
	return seen
}

func (s *Local) usedRemarks(group string) map[string]bool {
	used := make(map[string]bool)
	for _, l := range s.groupLinks(group) {
		used[l.Remark] = true
	}
	return used
}

func uniqueName(used map[string]bool, name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "server"
	}
	if !used[name] {
		return name
	}
	for i := 2; ; i++ {
		candidate := fmt.Sprintf("%s (%d)", name, i)
		if !used[candidate] {
			return candidate
		}
	}
}

// groupLabelForURL derives a group name from a subscription URL fragment or
// host, mirroring the CLI convention.
func groupLabelForURL(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "sub"
	}
	if frag := strings.TrimSpace(u.Fragment); frag != "" {
		if name := safeLabel(frag); name != "" {
			return name
		}
	}
	if host := u.Hostname(); host != "" {
		// An IP host has no registrable label: splitting 127.0.0.1 yielded "0".
		if net.ParseIP(host) != nil {
			return "sub"
		}
		parts := strings.Split(host, ".")
		if len(parts) >= 2 {
			if name := safeLabel(parts[len(parts)-2]); name != "" {
				return name
			}
		}
		if name := safeLabel(parts[0]); name != "" {
			return name
		}
	}
	return "sub"
}

func safeLabel(name string) string {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 || name == "." || name == ".." {
		return ""
	}
	repl := strings.NewReplacer("/", "_", "\\", "_", ":", "_", "*", "_", "?", "_", "\"", "_", "<", "_", ">", "_", "|", "_")
	name = strings.Trim(repl.Replace(name), " ._")
	if name == "" || strings.EqualFold(name, "default") {
		return ""
	}
	return name
}
