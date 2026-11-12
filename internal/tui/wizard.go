package tui

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/liberoute/bypath/internal/app"
	"github.com/liberoute/bypath/internal/openvpn"
)

const maxStageFile = 4 << 20

type wizStep int

const (
	wzPrepare wizStep = iota
	wzSummary
	wzRefs
	wzAuthUser
	wzAuthPass
	wzName
	wzSave
	wzConfirm
	wzImporting
	wzDone
	wzFailed
)

type wizard struct {
	src     app.OVPNSource
	group   string
	viaText bool

	step   wizStep
	errMsg string

	stageDir  string
	stagePath string
	refs      openvpn.Refs
	missing   []string
	refIndex  int
	authGap   bool

	preview  app.OVPNPreview
	username string
	password string
	name     string
	saveIdx  int

	result app.ImportResult
}

type stageInfo struct {
	dir     string
	path    string
	name    string
	missing []string
	authGap bool
	err     error
}

type openVPNPreparedMsg struct {
	info *stageInfo
}
type openVPNPreviewedMsg struct {
	preview app.OVPNPreview
	err     error
}
type openVPNImportedMsg struct {
	result app.ImportResult
	err    error
}

// startOpenVPNWizard begins the import flow. The source is either a path chosen
// in the browser or pasted text; both run through the same confined parser.
func (m *Menu) startOpenVPNWizard(src app.OVPNSource, group string) tea.Cmd {
	if m.svc == nil {
		m.setNotice(true, "Application service is not available: %s", friendlyError(m.svcErr))
		return nil
	}
	if strings.TrimSpace(group) == "" {
		group = "default"
	}
	w := &wizard{src: src, group: group, viaText: strings.TrimSpace(src.Text) != ""}
	if strings.TrimSpace(src.Name) != "" {
		w.name = strings.TrimSpace(src.Name)
	} else if src.Path != "" {
		w.name = strings.TrimSuffix(filepath.Base(src.Path), filepath.Ext(src.Path))
	}
	if w.name == "" {
		w.name = "openvpn"
	}
	m.wiz = w
	m.overlay = overlay{kind: ovWizard}
	return m.prepareWizard()
}

func (m *Menu) prepareWizard() tea.Cmd {
	w := m.wiz
	if w == nil {
		return nil
	}
	w.step = wzPrepare
	src := w.src
	return func() tea.Msg {
		info := stageOpenVPN(src)
		return openVPNPreparedMsg{info: info}
	}
}

// stageOpenVPN copies the profile and its referenced files into a private
// temporary directory. Staging makes the preview and the import read the same
// bytes even if the original folder changes in between.
func stageOpenVPN(src app.OVPNSource) *stageInfo {
	info := &stageInfo{}
	dir, err := os.MkdirTemp("", "bypath-ovpn-")
	if err != nil {
		info.err = fmt.Errorf("creating staging directory: %w", err)
		return info
	}
	if err := os.Chmod(dir, 0700); err != nil {
		os.RemoveAll(dir)
		info.err = fmt.Errorf("restricting staging directory: %w", err)
		return info
	}
	info.dir = dir
	info.path = filepath.Join(dir, "profile.ovpn")
	if strings.TrimSpace(src.Name) == "" && src.Path != "" {
		info.name = strings.TrimSuffix(filepath.Base(src.Path), filepath.Ext(src.Path))
	}

	if strings.TrimSpace(src.Text) != "" {
		if err := writeStageFile(info.path, []byte(src.Text)); err != nil {
			info.err = err
			return info
		}
		if info.name == "" {
			info.name = "openvpn"
		}
		return info
	}

	if strings.TrimSpace(src.Path) == "" {
		info.err = fmt.Errorf("no OpenVPN file or profile text provided")
		return info
	}
	refs, err := openvpn.ScanRefs(src.Path)
	if err != nil {
		info.err = err
		return info
	}
	base := filepath.Dir(src.Path)
	content, err := readCapped(src.Path, 1<<20)
	if err != nil {
		info.err = err
		return info
	}
	for _, ref := range refs.Files {
		srcFile, ok := safeRefPath(base, ref)
		if !ok {
			info.err = fmt.Errorf("profile references an unsafe path %q", ref)
			return info
		}
		if !regularFile(srcFile) {
			info.missing = append(info.missing, ref)
			continue
		}
		if err := copyStageFile(srcFile, info.dir, ref); err != nil {
			info.err = err
			return info
		}
	}
	if refs.AuthFile != "" {
		authFile, ok := safeRefPath(base, refs.AuthFile)
		if !ok {
			info.err = fmt.Errorf("profile references an unsafe auth file path %q", refs.AuthFile)
			return info
		}
		if regularFile(authFile) {
			if err := copyStageFile(authFile, info.dir, refs.AuthFile); err != nil {
				info.err = err
				return info
			}
		} else {
			info.authGap = true
			content = stripAuthFileRef(content)
		}
	}
	if err := writeStageFile(info.path, content); err != nil {
		info.err = err
		return info
	}
	return info
}

// stagedSource reads the staged profile and its referenced files back into an
// upload. The daemon must never open a client-supplied path: it runs as root,
// and the control socket is reachable by the control group.
func stagedSource(stageDir, name string) (app.OVPNSource, error) {
	text, err := readCapped(filepath.Join(stageDir, "profile.ovpn"), 1<<20)
	if err != nil {
		return app.OVPNSource{}, err
	}
	src := app.OVPNSource{Text: string(text), Name: name}
	// References may live in subdirectories (keys/ca.crt). Walk the whole
	// staging tree so those profiles import exactly as they did by path.
	err = filepath.WalkDir(stageDir, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(stageDir, p)
		if err != nil {
			return err
		}
		refName := filepath.ToSlash(rel)
		if refName == "profile.ovpn" {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("staged reference %q is not a regular file", refName)
		}
		content, err := readCapped(p, 512<<10)
		if err != nil {
			return err
		}
		src.Refs = append(src.Refs, app.OVPNRef{Name: refName, Content: string(content)})
		return nil
	})
	if err != nil {
		return app.OVPNSource{}, err
	}
	if err := app.ValidateOVPNRefs(src.Refs); err != nil {
		return app.OVPNSource{}, err
	}
	return src, nil
}

// safeRefPath joins a validated relative reference to base and confirms the
// result stays inside it.
func safeRefPath(base, ref string) (string, bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" || filepath.IsAbs(ref) || strings.HasPrefix(ref, "/") || strings.HasPrefix(ref, `\`) ||
		filepath.VolumeName(ref) != "" || strings.ContainsRune(ref, 0) {
		return "", false
	}
	clean := filepath.Clean(filepath.FromSlash(ref))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", false
	}
	full := filepath.Join(base, clean)
	rel, err := filepath.Rel(base, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", false
	}
	return full, true
}

func regularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func readCapped(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s is larger than the %d byte limit", filepath.Base(path), limit)
	}
	return data, nil
}

func writeStageFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0600)
}

func copyStageFile(src, stageDir, ref string) error {
	clean := filepath.Clean(filepath.FromSlash(ref))
	dest := filepath.Join(stageDir, clean)
	rel, err := filepath.Rel(stageDir, dest)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("refusing to stage %q outside the staging directory", ref)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
		return fmt.Errorf("creating staging subdirectory: %w", err)
	}
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("reading referenced file %q: %w", ref, err)
	}
	defer in.Close()
	stat, err := in.Stat()
	if err != nil || !stat.Mode().IsRegular() {
		return fmt.Errorf("referenced file %q is not a regular file", ref)
	}
	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("staging referenced file %q: %w", ref, err)
	}
	n, copyErr := io.Copy(out, io.LimitReader(in, maxStageFile+1))
	if copyErr == nil && n > maxStageFile {
		copyErr = fmt.Errorf("referenced file %q is larger than %d bytes", ref, maxStageFile)
	}
	if syncErr := out.Sync(); copyErr == nil {
		copyErr = syncErr
	}
	if closeErr := out.Close(); copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		os.Remove(dest)
		return copyErr
	}
	return nil
}

// stripAuthFileRef removes a missing auth-user-pass file reference so the
// profile can be previewed while credentials are collected from the user. It
// never touches inline <auth-user-pass> blocks.
func stripAuthFileRef(content []byte) []byte {
	lines := strings.Split(string(content), "\n")
	inBlock := ""
	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if inBlock != "" {
			if strings.EqualFold(line, "</"+inBlock+">") {
				inBlock = ""
			}
			continue
		}
		if strings.HasPrefix(line, "<") && strings.HasSuffix(line, ">") && !strings.HasPrefix(line, "</") {
			inBlock = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 1 && strings.EqualFold(fields[0], "auth-user-pass") {
			lines[i] = "auth-user-pass"
		}
	}
	return []byte(strings.Join(lines, "\n"))
}

func (m *Menu) handlePrepared(msg openVPNPreparedMsg) (tea.Model, tea.Cmd) {
	w := m.wiz
	if w == nil {
		return m, nil
	}
	info := msg.info
	if info == nil || info.err != nil {
		w.step = wzFailed
		if info != nil && info.err != nil {
			w.errMsg = friendlyError(info.err)
		} else {
			w.errMsg = "the profile could not be prepared"
		}
		if info != nil && info.dir != "" {
			w.stageDir = info.dir
		}
		return m, nil
	}
	w.stageDir = info.dir
	w.stagePath = info.path
	w.missing = info.missing
	w.refIndex = 0
	w.authGap = info.authGap
	if w.name == "" && info.name != "" {
		w.name = info.name
	}
	if len(w.missing) > 0 {
		w.step = wzRefs
		return m, nil
	}
	return m.previewWizard()
}

func (m *Menu) previewWizard() (tea.Model, tea.Cmd) {
	w := m.wiz
	if w == nil {
		return m, nil
	}
	if m.svc == nil {
		w.step = wzFailed
		w.errMsg = "application service is not available"
		return m, nil
	}
	w.step = wzPrepare
	svc := m.svc
	stageDir, name := w.stageDir, w.name
	return m, func() tea.Msg {
		src, err := stagedSource(stageDir, name)
		if err != nil {
			return openVPNPreviewedMsg{err: err}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		preview, err := svc.PreviewOpenVPN(ctx, src)
		return openVPNPreviewedMsg{preview: preview, err: err}
	}
}

func (m *Menu) handlePreviewed(msg openVPNPreviewedMsg) (tea.Model, tea.Cmd) {
	w := m.wiz
	if w == nil {
		return m, nil
	}
	if msg.err != nil {
		w.step = wzFailed
		w.errMsg = friendlyError(msg.err)
		return m, nil
	}
	w.preview = msg.preview
	if w.name == "" {
		w.name = msg.preview.Name
	}
	w.step = wzSummary
	m.openWizard()
	return m, nil
}

func (m *Menu) openWizard() {
	m.overlay = overlay{kind: ovWizard}
}

func (m *Menu) openWizAuthUser() tea.Cmd {
	w := m.wiz
	if w == nil {
		return nil
	}
	w.step = wzAuthUser
	title := "OpenVPN credentials"
	m.overlay = overlay{
		kind:   ovInput,
		title:  title,
		prompt: "Username",
		onSubmit: func(m *Menu, value string) tea.Cmd {
			value = strings.TrimSpace(value)
			if value == "" {
				m.setNotice(true, "A username is required for this profile.")
				m.openWizard()
				return nil
			}
			w.username = value
			return m.openWizAuthPass()
		},
		onCancel: func(m *Menu) tea.Cmd {
			m.openWizard()
			return nil
		},
	}
	return nil
}

func (m *Menu) openWizAuthPass() tea.Cmd {
	w := m.wiz
	if w == nil {
		return nil
	}
	w.step = wzAuthPass
	m.overlay = overlay{
		kind:   ovInput,
		title:  "OpenVPN credentials",
		prompt: "Password (masked, never written to configuration or logs)",
		masked: true,
		onSubmit: func(m *Menu, value string) tea.Cmd {
			w.password = value
			_, cmd := m.openWizName()
			return cmd
		},
		onCancel: func(m *Menu) tea.Cmd {
			m.openWizard()
			return nil
		},
	}
	return nil
}

func (m *Menu) openWizName() (tea.Model, tea.Cmd) {
	w := m.wiz
	if w == nil {
		return m, nil
	}
	w.step = wzName
	name := w.name
	m.overlay = overlay{
		kind:   ovInput,
		title:  "Display name",
		prompt: "Name shown in Connections",
		value:  name,
		cursor: len([]rune(name)),
		onSubmit: func(m *Menu, value string) tea.Cmd {
			value = strings.TrimSpace(value)
			if value == "" {
				value = name
			}
			w.name = value
			if w.preview.RequiresAuth || w.preview.HasInlineAuth {
				w.step = wzSave
				m.openWizard()
				return nil
			}
			w.step = wzConfirm
			m.openWizard()
			return nil
		},
		onCancel: func(m *Menu) tea.Cmd {
			m.openWizard()
			return nil
		},
	}
	return m, nil
}

func (m *Menu) wizardKey(k tea.KeyMsg, key string) tea.Cmd {
	w := m.wiz
	if w == nil {
		m.overlay = overlay{}
		return nil
	}
	switch key {
	case "esc":
		m.closeWizard()
		return nil
	case "ctrl+c":
		m.closeWizard()
		return tea.Quit
	}
	switch w.step {
	case wzSummary:
		if key == "enter" {
			if w.preview.RequiresAuth && w.username == "" && !w.preview.HasInlineAuth {
				return m.openWizAuthUser()
			}
			_, cmd := m.openWizName()
			return cmd
		}
	case wzRefs:
		switch key {
		case "enter":
			if w.refIndex >= len(w.missing) {
				if w.authGap {
					return m.reopenAuthAfterRefs()
				}
				return nil
			}
			ref := w.missing[w.refIndex]
			dir := ""
			if w.src.Path != "" {
				dir = filepath.Dir(w.src.Path)
			}
			m.pickFile("Select file for "+ref, dir, "", func(m *Menu, path string) tea.Cmd {
				if err := copyStageFile(path, w.stageDir, ref); err != nil {
					w.errMsg = friendlyError(err)
					w.step = wzFailed
					return nil
				}
				w.refIndex++
				w.errMsg = ""
				m.openWizard()
				if w.refIndex >= len(w.missing) {
					if w.authGap {
						return m.reopenAuthAfterRefs()
					}
					_, cmd := m.previewWizard()
					return cmd
				}
				return nil
			})
			m.overlay.onCancel = func(m *Menu) tea.Cmd {
				m.openWizard()
				return nil
			}
		case "s":
			m.closeWizard()
		}
	case wzAuthUser:
		if key == "enter" {
			return m.openWizAuthUser()
		}
	case wzAuthPass:
		if key == "enter" {
			return m.openWizAuthPass()
		}
	case wzName:
		if key == "enter" {
			_, cmd := m.openWizName()
			return cmd
		}
	case wzSave:
		switch key {
		case "up", "k", "left":
			w.saveIdx = 0
		case "down", "j", "right", "tab":
			w.saveIdx = 1
		case "enter":
			w.step = wzConfirm
			m.openWizard()
		}
	case wzConfirm:
		if key == "enter" {
			return m.importWizard()
		}
	case wzDone, wzFailed:
		if key == "enter" || key == "esc" {
			m.closeWizard()
		}
	}
	return nil
}

func (m *Menu) reopenAuthAfterRefs() tea.Cmd {
	m.openWizard()
	return m.openWizAuthUser()
}

func (m *Menu) importWizard() tea.Cmd {
	w := m.wiz
	if w == nil || m.svc == nil {
		return nil
	}
	if m.busy != "" {
		return nil
	}
	w.step = wzImporting
	m.busy = "Importing OpenVPN profile"
	m.busySince = time.Now()
	svc := m.svc
	stageDir, name := w.stageDir, w.name
	req := app.OVPNImport{
		Group:          w.group,
		Username:       w.username,
		Password:       w.password,
		SaveCredential: w.saveIdx == 0,
	}
	return tea.Batch(func() tea.Msg {
		src, err := stagedSource(stageDir, name)
		if err != nil {
			return openVPNImportedMsg{err: err}
		}
		req.OVPNSource = src
		ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
		defer cancel()
		res, err := svc.ImportOpenVPN(ctx, req)
		return openVPNImportedMsg{result: res, err: err}
	}, spinnerTick())
}

func (m *Menu) handleImported(msg openVPNImportedMsg) (tea.Model, tea.Cmd) {
	m.busy = ""
	w := m.wiz
	if w == nil {
		return m, nil
	}
	if msg.err != nil {
		w.step = wzFailed
		w.errMsg = friendlyError(msg.err)
		return m, nil
	}
	w.step = wzDone
	w.result = msg.result
	m.lastImport = importResultMessage(msg.result)
	m.cleanupWizardStage()
	return m, tea.Batch(m.loadConnections(), m.loadStatus())
}

func (m *Menu) cleanupWizardStage() {
	if m.wiz == nil || m.wiz.stageDir == "" {
		return
	}
	os.RemoveAll(m.wiz.stageDir)
	m.wiz.stageDir = ""
	m.wiz.stagePath = ""
}

func (m *Menu) closeWizard() {
	m.cleanupWizardStage()
	m.wiz = nil
	m.overlay = overlay{}
}

func (m *Menu) wizardFooter() string {
	w := m.wiz
	if w == nil {
		return "esc cancel"
	}
	switch w.step {
	case wzSummary:
		return "enter continue · esc cancel"
	case wzRefs:
		return "enter choose file · s skip import · esc cancel"
	case wzSave:
		return "↑/↓ choose · enter continue · esc cancel"
	case wzConfirm:
		return "enter import · esc cancel"
	case wzDone, wzFailed:
		return "enter close"
	}
	return "esc cancel"
}

func (m *Menu) wizardView(h int) string {
	w := m.wiz
	if w == nil {
		return ""

	}
	title := "Import OpenVPN profile"
	switch w.step {
	case wzPrepare:
		return m.dialogBox(title, []string{styleMuted.Render("Reading, validating and packaging the profile…")},
			h)
	case wzSummary:
		p := w.preview
		netw := p.Network
		if netw == "" {
			netw = "udp"
		}
		auth := "certificate only"
		if p.RequiresAuth || p.HasInlineAuth {
			auth = "username/password"
		}
		body := []string{
			"Profile validated. Review before continuing.",
			"",
			kv("Name", p.Name, 14),
			kv("Server", fmt.Sprintf("%s:%d", p.Host, p.Port), 14),
			kv("Transport", netw, 14),
			kv("Authentication", auth, 14),
			kv("Referenced files", fmt.Sprintf("%d (inlined on import)", len(p.CertFiles)), 14),
		}
		if len(p.Warnings) > 0 {
			body = append(body, "")
			for _, warning := range p.Warnings {
				body = append(body, styleWarn.Render("• "+warning))
			}
		}
		body = append(body, "", styleMuted.Render("No credentials are requested unless the profile requires them."))
		return m.dialogBox(title, body, h)
	case wzRefs:
		rows := []string{styleMuted.Render("This profile references files next to it. Missing files must be selected before import."), ""}
		for i, ref := range w.missing {
			mark := styleWarn.Render("missing")
			if i < w.refIndex {
				mark = styleOK.Render("staged ")
			}
			rows = append(rows, fmt.Sprintf("%s  %s", mark, ref))
		}
		rows = append(rows, "", fmt.Sprintf("Select file %d of %d for: %s", w.refIndex+1, len(w.missing), w.missing[w.refIndex]))
		rows = append(rows, "", styleMuted.Render("CA/cert/key files are copied into a private staging directory, then inlined into the packaged profile."))
		return m.dialogBox(title, rows, h)
	case wzAuthUser:
		return m.dialogBox(title, []string{"This profile requires a username and password.", "", styleMuted.Render("Press enter to enter credentials.")}, h)
	case wzAuthPass:
		return m.dialogBox(title, []string{"Password entry is masked.", "", styleMuted.Render("Press enter to enter the password.")}, h)
	case wzName:
		return m.dialogBox(title, []string{fmt.Sprintf("Display name: %s", w.name), "", styleMuted.Render("Press enter to edit the name.")}, h)
	case wzSave:
		body := []string{
			"Save the credentials?",
			"",
			styleMuted.Render("Yes stores an AES-256-GCM encrypted record under the profile directory. No keeps them in memory for this run and discards them when the gateway stops."),
			"",
		}
		options := []string{"Save securely (encrypted at rest)", "Session only (never persisted)"}
		for i, opt := range options {
			if i == w.saveIdx {
				body = append(body, styleActive.Render(" "+padTo(opt, maxInt(20, m.contentWidth()-8))+" "))
			} else {
				body = append(body, " "+opt)
			}
		}
		return m.dialogBox(title, body, h)
	case wzConfirm:
		p := w.preview
		netw := p.Network
		if netw == "" {
			netw = "udp"
		}
		auth := "none (certificate only)"
		if p.RequiresAuth || p.HasInlineAuth {
			auth = "username/password"
			if w.username != "" {
				auth += " (entered now)"
			}
		}
		save := "not applicable"
		if p.RequiresAuth || p.HasInlineAuth {
			save = onOff(w.saveIdx == 0, "saved encrypted at rest", "session only")
		}
		body := []string{
			"Ready to import.",
			"",
			kv("Name", w.name, 12),
			kv("Group", w.group, 12),
			kv("Server", fmt.Sprintf("%s:%d", p.Host, p.Port), 12),
			kv("Transport", netw, 12),
			kv("Authentication", auth, 12),
			kv("Credentials", save, 12),
			kv("Referenced files", fmt.Sprintf("%d", len(p.CertFiles)), 12),
		}
		if len(p.Warnings) > 0 {
			body = append(body, "")
			for _, warning := range p.Warnings {
				body = append(body, styleWarn.Render("• "+warning))
			}
		}
		return m.dialogBox(title, body, h)
	case wzImporting:
		spinner := spinnerFrames[m.spinner%len(spinnerFrames)]
		return m.dialogBox(title, []string{styleMuted.Render(spinner + " Importing and storing the profile…")}, h)
	case wzDone:
		body := []string{styleOK.Render("Import completed."), ""}
		body = append(body, importResultMessage(w.result))
		return m.dialogBox(title, body, h)
	case wzFailed:
		return m.dialogBox(title, []string{styleErr.Render("Import failed."), "", w.errMsg, "",
			styleMuted.Render("The staged copy is removed when you close this dialog. Fix the profile and try again.")},
			h)
	}
	return ""
}
