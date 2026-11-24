package app

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/liberoute/bypath/internal/credential"
	"github.com/liberoute/bypath/internal/openvpn"
	"github.com/liberoute/bypath/internal/profile"
	"github.com/liberoute/bypath/internal/securefile"
)

// ListConnections returns every stored link as a secret-free view.
func (s *Local) ListConnections(ctx context.Context, filter ConnectionFilter) ([]Connection, error) {
	active := s.activeID()
	search := strings.ToLower(strings.TrimSpace(filter.Search))
	subLabels := s.subscriptionLabels()

	var out []Connection
	for _, name := range s.profiles.ListGroups() {
		if filter.Group != "" && name != filter.Group {
			continue
		}
		g, err := s.profiles.GetGroup(name)
		if err != nil {
			continue
		}
		for _, link := range g.Links {
			if link.Port < 10 || link.Address == "" || link.Address == "0.0.0.0" {
				continue
			}
			if filter.Protocol != "" && link.Protocol != filter.Protocol {
				continue
			}
			if search != "" && !strings.Contains(strings.ToLower(link.Remark), search) &&
				!strings.Contains(strings.ToLower(link.Address), search) &&
				!strings.Contains(strings.ToLower(name), search) {
				continue
			}
			view := s.viewConnection(link, ConnectionID(name, link.Remark), active, subLabels)
			if view.Hidden && !filter.IncludeHidden {
				continue
			}
			out = append(out, view)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Group != out[j].Group {
			return out[i].Group < out[j].Group
		}
		return out[i].Remark < out[j].Remark
	})
	return out, nil
}

// GetConnection returns one connection with diagnostics.
func (s *Local) GetConnection(ctx context.Context, id string) (ConnectionDetail, error) {
	link, g, err := s.findLink(id)
	if err != nil {
		return ConnectionDetail{}, err
	}
	view := s.viewConnection(link, ConnectionID(g.Name, link.Remark), s.activeID(), s.subscriptionLabels())
	detail := ConnectionDetail{
		Connection: view,
		OVPN:       link.Protocol == "openvpn",
		OVPNPath:   link.OVPNPath,
	}
	if link.SourceID != "" {
		detail.Source = "subscription"
	}
	if link.Protocol == "openvpn" && link.OVPNPath != "" {
		resolved, resolveErr := s.ovpnPath(link.OVPNPath)
		if resolveErr != nil {
			detail.Warnings = append(detail.Warnings, "OpenVPN profile file is unreadable: "+resolveErr.Error())
		} else if prof, err := openvpn.ParseFile(resolved); err == nil {
			detail.Warnings = append(detail.Warnings, prof.Warnings...)
			if prof.RequiresUserPass && !view.HasCredentials {
				detail.RequiresAuth = true
			}
		} else {
			detail.Warnings = append(detail.Warnings, "OpenVPN profile file is unreadable: "+err.Error())
		}
	}
	if view.CredentialsSaved {
		detail.CredentialStore = "saved"
	} else if view.HasCredentials {
		detail.CredentialStore = "session"
	}
	return detail, nil
}

func (s *Local) viewConnection(link *profile.Link, id, activeID string, subLabels map[string]string) Connection {
	key := credential.KeyFor(link)
	saved := s.creds.HasSaved(key)
	_, session := s.creds.LookupSession(key)
	legacy := link.OVPNAuthUserPassFile != ""
	if legacy {
		if _, err := os.Stat(link.OVPNAuthUserPassFile); err != nil {
			legacy = false
		}
	}
	health := ""
	switch link.HTTPSCapable {
	case 1:
		health = "ok"
	case -1:
		health = "failed"
	}
	selected := false
	if active := s.profiles.GetActiveLink(); active != nil {
		selected = active.Group == link.Group && active.Remark == link.Remark
	}
	c := Connection{
		ID:               id,
		Group:            link.Group,
		Remark:           link.Remark,
		Protocol:         link.Protocol,
		Address:          link.Address,
		Port:             link.Port,
		Network:          link.Network,
		Engine:           EngineFor(link),
		TLS:              link.TLS,
		EncryptedVLESS:   link.EncryptedVLESS(),
		Reality:          link.RealityPublicKey != "",
		Active:           id == activeID,
		Selected:         selected,
		RequiresAuth:     link.RequiresAuth || legacy,
		HasCredentials:   saved || session || legacy,
		CredentialsSaved: saved || legacy,
		CDN:              profile.IsCDNPattern(link),
		Health:           health,
	}
	if link.SourceID != "" {
		c.FromSubscription = subLabels[link.SourceID]
	}
	if s.layer != nil {
		if e, ok := s.layer.EntryForLink(link.Group, link.Remark); ok {
			c.StableID = e.ID
			c.Orphaned = e.Orphaned
			c.Hidden = e.Hidden
			c.DisplayName = s.layer.DisplayName(e.ID)
			if gid := s.layer.GroupForMember(e.ID); gid != "" {
				c.LayerGroupID = gid
				c.LayerGroup = s.layer.GroupName(gid)
			}
		}
	}
	return c
}

// subscriptionLabels maps SourceID to a redacted subscription label.
func (s *Local) subscriptionLabels() map[string]string {
	out := make(map[string]string)
	for _, name := range s.profiles.ListGroups() {
		g, err := s.profiles.GetGroup(name)
		if err != nil {
			continue
		}
		for _, u := range g.Subscriptions {
			out[profile.SourceIDFor(u)] = redactURL(u)
		}
	}
	return out
}

// redactURL keeps the scheme and host but drops path, query and fragment, where
// subscription panels place their tokens.
func redactURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "<redacted>"
	}
	label := u.Scheme + "://" + u.Host + "/…"
	if u.Fragment != "" {
		label = u.Scheme + "://" + u.Host + "/… #" + u.Fragment
	}
	return label
}

// ImportURI stores one proxy URI.
func (s *Local) ImportURI(ctx context.Context, group, rawURI string) (ImportResult, error) {
	rawURI = strings.TrimSpace(rawURI)
	if rawURI == "" {
		return ImportResult{}, errorf(CodeInvalid, "link URI is empty")
	}
	if group == "" {
		group = "default"
	}
	if err := validGroupName(group); err != nil {
		return ImportResult{}, err
	}
	link, err := profile.ParseURI(rawURI)
	if err != nil {
		return ImportResult{}, &Error{Code: CodeInvalid, Message: "invalid link URI: " + Redact(err.Error()), Err: err}
	}

	if existing := s.findDuplicate(rawURI); existing != "" {
		return ImportResult{
			Group: group,
			Skipped: []Skipped{{
				Name:   link.Remark,
				Reason: fmt.Sprintf("an identical link already exists in group %q", existing),
			}},
		}, nil
	}
	if _, err := s.profiles.GetGroup(group); err != nil {
		if err := s.profiles.CreateGroup(group, "basic"); err != nil {
			return ImportResult{}, asAppError(err, CodeInternal, "creating group")
		}
	}
	link.Remark = s.uniqueRemark(group, link.Remark)
	if err := s.profiles.AddLink(group, link); err != nil {
		return ImportResult{}, asAppError(err, CodeInternal, "adding link")
	}
	s.indexLayer()
	return ImportResult{Created: []Connection{s.viewConnection(link, ConnectionID(group, link.Remark), s.activeID(), s.subscriptionLabels())}, Group: group}, nil
}

func (s *Local) findDuplicate(rawURI string) string {
	target := strings.TrimSpace(rawURI)
	for _, name := range s.profiles.ListGroups() {
		g, err := s.profiles.GetGroup(name)
		if err != nil {
			continue
		}
		for _, l := range g.Links {
			if strings.TrimSpace(l.RawURI) == target {
				return name
			}
		}
	}
	return ""
}

// findOVPNDuplicate compares packaged profile content, not just the remote, so
// two entries for the same server with different credentials stay importable.
func (s *Local) findOVPNDuplicate(group string, data []byte) string {
	sum := sha256.Sum256(data)
	for _, l := range s.groupLinks(group) {
		if l.Protocol != "openvpn" || l.OVPNPath == "" {
			continue
		}
		resolved, err := s.ovpnPath(l.OVPNPath)
		if err != nil {
			continue
		}
		existing, err := os.ReadFile(resolved)
		if err != nil {
			continue
		}
		if sha256.Sum256(existing) == sum {
			return l.Remark
		}
	}
	return ""
}

func (s *Local) uniqueRemark(group, remark string) string {
	g, err := s.profiles.GetGroup(group)
	if err != nil {
		return remark
	}
	used := make(map[string]bool, len(g.Links))
	for _, l := range g.Links {
		used[l.Remark] = true
	}
	if !used[remark] {
		return remark
	}
	for i := 2; i <= 100; i++ {
		candidate := fmt.Sprintf("%s (%d)", remark, i)
		if !used[candidate] {
			return candidate
		}
	}
	return remark
}

func validGroupName(name string) error {
	if !profile.ValidGroupName(name) {
		return errorf(CodeInvalid, "group name must be 1-64 characters and must not contain path separators")
	}
	return nil
}

// PreviewOpenVPN parses a profile and returns the safe summary used before an
// import. Nothing is written.
func (s *Local) PreviewOpenVPN(ctx context.Context, src OVPNSource) (OVPNPreview, error) {
	path, cleanup, err := s.stageOVPN(src)
	if err != nil {
		return OVPNPreview{}, err
	}
	defer cleanup()

	// Parse the staged package, not just the pasted text: uploads may carry
	// referenced certificate files that live next to the staged profile.
	prof, err := openvpn.ParseFile(path)
	if err != nil {
		return OVPNPreview{}, &Error{Code: CodeInvalid, Message: "invalid OpenVPN profile: " + err.Error(), Err: err}
	}
	name := strings.TrimSpace(src.Name)
	if name == "" && src.Path != "" {
		name = strings.TrimSuffix(filepath.Base(src.Path), filepath.Ext(src.Path))
	}
	if name == "" {
		name = "openvpn"
	}
	r := prof.Remotes[0]
	return OVPNPreview{
		Name:          name,
		Host:          r.Host,
		Port:          r.Port,
		Network:       r.Network,
		RequiresAuth:  prof.RequiresUserPass && prof.Username == "",
		HasInlineAuth: prof.Username != "",
		CertFiles:     prof.ExternalRefs,
		Warnings:      prof.Warnings,
	}, nil
}

// ImportOpenVPN packages and stores an OpenVPN profile.
func (s *Local) ImportOpenVPN(ctx context.Context, req OVPNImport) (ImportResult, error) {
	group := strings.TrimSpace(req.Group)
	if group == "" {
		group = "default"
	}
	if err := validGroupName(group); err != nil {
		return ImportResult{}, err
	}
	path, cleanup, err := s.stageOVPN(req.OVPNSource)
	if err != nil {
		return ImportResult{}, err
	}
	defer cleanup()

	data, prof, err := openvpn.LoadPackage(path)
	if err != nil {
		return ImportResult{}, &Error{Code: CodeInvalid, Message: "invalid OpenVPN profile: " + err.Error(), Err: err}
	}

	user, pass := strings.TrimSpace(req.Username), req.Password
	if user == "" {
		user, pass = prof.Username, prof.Password
	}
	if prof.RequiresUserPass && user == "" {
		return ImportResult{}, &Error{
			Code:    CodeNeedsCreds,
			Message: "this OpenVPN profile requires a username and password",
			Hint:    "enter credentials and retry the import",
		}
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		if req.Path != "" {
			name = strings.TrimSuffix(filepath.Base(req.Path), filepath.Ext(req.Path))
		}
		if name == "" {
			name = "openvpn"
		}
	}
	// The display name is user-facing and may contain spaces; only the stored
	// artifact filename has to be portable.
	artifact := sanitizeName(name)

	if _, err := s.profiles.GetGroup(group); err != nil {
		if err := s.profiles.CreateGroup(group, "basic"); err != nil {
			return ImportResult{}, asAppError(err, CodeInternal, "creating group")
		}
	}
	for _, l := range s.groupLinks(group) {
		if l.Remark == name {
			return ImportResult{}, &Error{
				Code:    CodeConflict,
				Message: fmt.Sprintf("a connection named %q already exists in group %q", name, group),
				Hint:    "choose another display name",
			}
		}
	}
	r := prof.Remotes[0]
	if existing := s.findOVPNDuplicate(group, data); existing != "" {
		return ImportResult{
			Group: group,
			Skipped: []Skipped{{
				Name:   name,
				Reason: fmt.Sprintf("an identical OpenVPN profile already exists as %q in group %q", existing, group),
			}},
		}, nil
	}

	dest, err := s.writeArtifact(artifact+".ovpn", data)
	if err != nil {
		return ImportResult{}, asAppError(err, CodeInternal, "storing OpenVPN profile")
	}
	link := &profile.Link{
		Protocol:     "openvpn",
		Remark:       name,
		Address:      r.Host,
		Port:         r.Port,
		Network:      r.Network,
		RawURI:       fmt.Sprintf("openvpn://%s:%d", r.Host, r.Port),
		OVPNPath:     dest,
		RequiresAuth: prof.RequiresUserPass,
	}
	if err := s.profiles.AddLink(group, link); err != nil {
		_ = os.Remove(dest)
		return ImportResult{}, asAppError(err, CodeInternal, "adding OpenVPN profile")
	}
	s.indexLayer()

	if user != "" {
		key := credential.KeyFor(link)
		var credErr error
		if req.SaveCredential {
			credErr = s.creds.Save(key, credential.Credentials{Username: user, Password: pass})
		} else {
			credErr = s.creds.SetSession(key, credential.Credentials{Username: user, Password: pass})
		}
		if credErr != nil {
			_ = s.profiles.RemoveLink(group, name)
			_ = os.Remove(dest)
			return ImportResult{}, asAppError(credErr, CodeInternal, "storing credentials")
		}
	}
	return ImportResult{Created: []Connection{s.viewConnection(link, ConnectionID(group, link.Remark), s.activeID(), s.subscriptionLabels())}, Group: group}, nil
}

// stageOVPN materialises pasted text in an owner-only temp directory so the
// same confined parser runs for both file and pasted imports.
func (s *Local) stageOVPN(src OVPNSource) (string, func(), error) {
	noop := func() {}
	if src.Text != "" {
		if len(src.Text) > 4<<20 {
			return "", noop, errorf(CodeInvalid, "OpenVPN profile text is larger than 4 MiB")
		}
		dir, err := os.MkdirTemp(s.paths.TmpDir, "ovpn-import-")
		if err != nil {
			return "", noop, asAppError(err, CodeInternal, "creating import directory")
		}
		path := filepath.Join(dir, "profile.ovpn")
		if err := securefile.WriteFile(path, []byte(src.Text)); err != nil {
			os.RemoveAll(dir)
			return "", noop, asAppError(err, CodeInternal, "staging pasted profile")
		}
		if err := writeOVPNRefs(dir, src.Refs); err != nil {
			os.RemoveAll(dir)
			return "", noop, err
		}
		return path, func() { os.RemoveAll(dir) }, nil
	}
	if strings.TrimSpace(src.Path) == "" {
		return "", noop, errorf(CodeInvalid, "no OpenVPN file or profile text provided")
	}
	return src.Path, noop, nil
}

// ValidateOVPNRefs checks uploaded reference names and sizes before anything is
// staged. Names must be plain file names so they cannot escape the staging
// directory or alias a path on the host.
func ValidateOVPNRefs(refs []OVPNRef) error {
	if len(refs) == 0 {
		return nil
	}
	if len(refs) > 24 {
		return errorf(CodeInvalid, "an OpenVPN profile may reference at most 24 files")
	}
	seen := make(map[string]bool, len(refs))
	for _, ref := range refs {
		name := strings.TrimSpace(ref.Name)
		if !safeRefName(name) {
			return errorf(CodeInvalid, "referenced file name %q is not a plain file name", name)
		}
		if seen[strings.ToLower(name)] {
			return errorf(CodeInvalid, "referenced file %q was uploaded twice", name)
		}
		seen[strings.ToLower(name)] = true
		if len(ref.Content) > 512<<10 {
			return errorf(CodeInvalid, "referenced file %q is larger than 512 KiB", name)
		}
	}
	return nil
}

// writeOVPNRefs stores uploaded references next to the staged profile so the
// confined resolver can inline them.
func writeOVPNRefs(dir string, refs []OVPNRef) error {
	if err := ValidateOVPNRefs(refs); err != nil {
		return err
	}
	for _, ref := range refs {
		name := strings.TrimSpace(ref.Name)
		dest := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
			return asAppError(err, CodeInternal, "creating referenced-file directory")
		}
		if err := securefile.WriteFile(dest, []byte(ref.Content)); err != nil {
			return asAppError(err, CodeInternal, "staging referenced file")
		}
	}
	return nil
}

// safeRefName accepts a relative reference such as "keys/ca.crt". OpenVPN
// profiles routinely keep material in subdirectories; the reference must stay
// a clean relative path inside the profile directory, with no empty, "." or
// ".." component and no absolute/Windows/UNC form.
func safeRefName(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 128 || name == "." || name == ".." {
		return false
	}
	if strings.HasPrefix(name, "/") || filepath.IsAbs(name) || filepath.VolumeName(name) != "" {
		return false
	}
	if strings.ContainsAny(name, `\:`+"\x00") {
		return false
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	if path.Clean(name) != name {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func (s *Local) groupLinks(group string) []*profile.Link {
	g, err := s.profiles.GetGroup(group)
	if err != nil {
		return nil
	}
	return g.Links
}

// RenameConnection changes a display name without touching the server or
// credential record.
func (s *Local) RenameConnection(ctx context.Context, id, name string) error {
	_, g, err := s.findLink(id)
	if err != nil {
		return err
	}
	_, remark, _ := SplitID(id)
	if err := s.profiles.RenameLink(g.Name, remark, name); err != nil {
		return &Error{Code: CodeConflict, Message: err.Error(), Err: err}
	}
	s.indexLayer()
	return nil
}

// SetCredentials stores credentials either persistently (encrypted) or for the
// current run only. It never writes them to group JSON.
func (s *Local) SetCredentials(ctx context.Context, id string, creds Credentials, persist bool) error {
	link, g, err := s.findLink(id)
	if err != nil {
		return err
	}
	if strings.TrimSpace(creds.Username) == "" {
		return errorf(CodeInvalid, "username is required")
	}
	key := credential.KeyFor(link)
	if persist {
		if err := s.creds.Save(key, credential.Credentials{Username: creds.Username, Password: creds.Password}); err != nil {
			return asAppError(err, CodeInternal, "saving credentials")
		}
	} else if err := s.creds.SetSession(key, credential.Credentials{Username: creds.Username, Password: creds.Password}); err != nil {
		return asAppError(err, CodeInternal, "storing session credentials")
	}
	if !link.RequiresAuth {
		link.RequiresAuth = true
		if err := s.profiles.SaveGroup(g.Name); err != nil {
			return asAppError(err, CodeInternal, "saving connection")
		}
	}
	return nil
}

// SetActive saves the selection and states plainly whether a live switch
// happened. A running gateway keeps its existing tunnel until restarted.
func (s *Local) SetActive(ctx context.Context, id string) (ActionResult, error) {
	link, _, err := s.findLink(id)
	if err != nil {
		return ActionResult{}, err
	}
	s.profiles.SetActiveLink(link)
	s.maybeRecordSelection(link)
	if s.runtime == nil {
		return ActionResult{
			Applied:         false,
			RestartRequired: true,
			Message:         "Selection saved. The gateway is not running; it will use this connection on its next start.",
		}, nil
	}
	rs := s.runtime.Status()
	return ActionResult{
		Applied:         false,
		RestartRequired: true,
		Message: fmt.Sprintf("Selection saved. The gateway keeps its current tunnel (%s) until you apply the change.",
			strings.ToLower(rs.State)),
	}, nil
}

// ErrNoCredentials helps callers distinguish a missing-credential failure.
var ErrNoCredentials = errors.New("credentials required")

// credentialsMissing reports whether a link declares user/password auth but no
// credential is available in any of the three stores (saved, session, legacy
// auth-user-pass file). It never inspects or returns secret values.
func (s *Local) credentialsMissing(link *profile.Link) bool {
	if link == nil || !link.RequiresAuth {
		return false
	}
	if _, ok := s.creds.Lookup(credential.KeyFor(link)); ok {
		return false
	}
	if link.OVPNAuthUserPassFile != "" {
		if _, err := os.Stat(link.OVPNAuthUserPassFile); err == nil {
			return false
		}
	}
	return true
}
