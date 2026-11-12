package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/liberoute/bypath/internal/layer"
	"github.com/liberoute/bypath/internal/profile"
)

func subscriptionIdentity(rawURL string) string {
	return "sub:" + profile.SourceIDFor(rawURL)
}

func (s *Local) describeSubscription(sub Subscription) Subscription {
	sub.ProposedGroup = sub.Group
	if sub.Group == "default" {
		sub.ProposedGroup = groupLabelForURL(sub.URL)
	}
	if s.layer != nil {
		if g, ok := s.layer.SourceGroup(sub.Group, subscriptionIdentity(sub.URL)); ok {
			sub.LayerGroupID, sub.LayerGroup = g.ID, g.Name
		}
	}
	return sub
}

func (s *Local) proposedSubscriptionName(name string) string {
	used := map[string]bool{}
	// Unreadable/unparsed bucket files are still user data, not free names.
	if entries, err := os.ReadDir(s.profiles.Directory()); err == nil {
		for _, entry := range entries {
			if ext := filepath.Ext(entry.Name()); strings.EqualFold(ext, ".json") {
				used[strings.ToLower(strings.TrimSuffix(entry.Name(), ext))] = true
			}
		}
	}
	for _, bucket := range s.profiles.ListGroups() {
		used[strings.ToLower(bucket)] = true
	}
	if s.layer != nil {
		for _, g := range s.layer.Groups() {
			used[strings.ToLower(g.Name)] = true
		}
	}
	base := name
	for n := 2; used[strings.ToLower(name)]; n++ {
		suffix := fmt.Sprintf(" (%d)", n)
		stem := base
		for len(stem)+len(suffix) > 64 {
			_, size := utf8.DecodeLastRuneInString(stem)
			stem = stem[:len(stem)-size]
		}
		name = stem + suffix
	}
	return name
}

// OrganizeSubscription changes labels only. It deliberately never refreshes,
// renames a bucket, repairs .active, or applies anything to the running tunnel.
func (s *Local) OrganizeSubscription(ctx context.Context, bucket, rawURL, name string) (Subscription, error) {
	s.switchMu.Lock()
	defer s.switchMu.Unlock()
	rawURL, err := s.registeredSubscription(bucket, rawURL)
	if err != nil {
		return Subscription{}, err
	}
	if name == "" {
		name = bucket
		if name == "default" {
			name = groupLabelForURL(rawURL)
		}
	}
	if err := validGroupName(name); err != nil {
		return Subscription{}, err
	}
	if _, err := s.applySubscriptionChange(bucket, subscriptionIdentity(rawURL), name, true, nil, nil); err != nil {
		return Subscription{}, err
	}
	list, err := s.ListSubscriptions(ctx)
	if err != nil {
		return Subscription{}, err
	}
	for _, sub := range list {
		if sub.Group == bucket && profile.SourceIDFor(sub.URL) == profile.SourceIDFor(rawURL) {
			return sub, nil
		}
	}
	return Subscription{}, errorf(CodeNotFound, "subscription not found")
}

func (s *Local) registeredSubscription(bucket, rawURL string) (string, error) {
	g, err := s.profiles.GetGroup(bucket)
	if err != nil {
		return "", errorf(CodeNotFound, "source import list not found")
	}
	want := profile.SourceIDFor(rawURL)
	for _, raw := range g.Subscriptions {
		if profile.SourceIDFor(raw) == want {
			return raw, nil
		}
	}
	return "", errorf(CodeNotFound, "subscription not registered in this import list")
}

// applySubscriptionChange rolls back the caller-owned bucket if a sidecar write
// fails. It preserves original bytes rather than serialising a restored group.
// The layer keeps its own lock throughout the callback and sidecar rollback.
func (s *Local) applySubscriptionChange(bucket, source, name string, organize bool, orphaned []string, mutate func() error) (layer.Group, error) {
	if s.layer == nil {
		return layer.Group{}, errorf(CodeUnavailable, "organisation layer is not available")
	}
	path := filepath.Join(s.profiles.Directory(), bucket+".json")
	var original []byte
	var mode os.FileMode
	var saved profile.Group
	g, getErr := s.profiles.GetGroup(bucket)
	if mutate != nil {
		info, err := os.Lstat(path)
		if err != nil && !os.IsNotExist(err) {
			return layer.Group{}, asAppError(err, CodeInternal, "reading import list")
		}
		if err == nil {
			if getErr != nil {
				return layer.Group{}, errorf(CodeConflict, "import list already exists on disk but cannot be loaded")
			}
			if !info.Mode().IsRegular() {
				return layer.Group{}, errorf(CodeInternal, "import list is not a regular file")
			}
			mode = info.Mode()
			original, err = os.ReadFile(path)
			if err != nil {
				return layer.Group{}, asAppError(err, CodeInternal, "reading import list")
			}
		}
		if getErr == nil {
			saved = *g
			saved.Subscriptions = append([]string(nil), g.Subscriptions...)
			saved.SubscriptionMeta = append([]profile.SubscriptionInfo(nil), g.SubscriptionMeta...)
			saved.Links = append([]*profile.Link(nil), g.Links...)
		}
	}
	group, err := s.layer.ApplySource(s.profiles, bucket, source, name, organize, orphaned, mutate)
	if err != nil {
		if mutate != nil {
			var rollbackErr error
			if getErr == nil {
				*g = saved
			} else if _, e := s.profiles.GetGroup(bucket); e == nil {
				rollbackErr = s.profiles.DeleteGroup(bucket)
				if os.IsNotExist(rollbackErr) {
					rollbackErr = nil
				}
			}
			if original != nil {
				rollbackErr = errors.Join(rollbackErr, restoreSubscriptionBucket(path, original, mode))
			}
			if rollbackErr != nil {
				err = errors.Join(err, fmt.Errorf("subscription bucket rollback failed: %w", rollbackErr))
			}
		}
		s.setLayerError(err)
		return layer.Group{}, asAppError(err, CodeInternal, "organising subscription")
	}
	s.setLayerError(nil)
	return group, nil
}

func restoreSubscriptionBucket(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".subscription-rollback-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(mode.Perm()); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
