package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

type ovKind int

const (
	ovNone ovKind = iota
	ovInput
	ovChoice
	ovText
	ovFiles
	ovInfo
	ovWizard
)

type choice struct {
	label  string
	detail string
	danger bool
}

type overlay struct {
	kind   ovKind
	title  string
	help   string
	prompt string
	info   string

	value  string
	masked bool
	cursor int

	choices   []choice
	choiceIdx int
	onSelect  func(m *Menu, idx int) tea.Cmd
	onSubmit  func(m *Menu, value string) tea.Cmd
	onCancel  func(m *Menu) tea.Cmd

	scroll int

	browser *browserState
	onFile  func(m *Menu, path string) tea.Cmd
}

func (m *Menu) promptInput(title, prompt, initial string, masked bool, onSubmit func(*Menu, string) tea.Cmd) {
	m.overlay = overlay{
		kind:     ovInput,
		title:    title,
		prompt:   prompt,
		value:    initial,
		masked:   masked,
		cursor:   len([]rune(initial)),
		onSubmit: onSubmit,
	}
}

func (m *Menu) promptText(title, help string, onSubmit func(*Menu, string) tea.Cmd) {
	m.overlay = overlay{kind: ovText, title: title, help: help, onSubmit: onSubmit}
}

func (m *Menu) confirmAction(title, detail, okLabel string, danger bool, fn func(*Menu) tea.Cmd) {
	choices := []choice{{label: "Cancel"}, {label: okLabel, danger: danger}}
	m.confirmChoice(title, detail, choices, func(m *Menu, idx int) tea.Cmd {
		if idx == 1 {
			return fn(m)
		}
		return nil
	})
}

func (m *Menu) confirmChoice(title, detail string, choices []choice, onSelect func(*Menu, int) tea.Cmd) {
	m.overlay = overlay{
		kind:      ovChoice,
		title:     title,
		info:      detail,
		choices:   choices,
		choiceIdx: 0,
		onSelect:  onSelect,
	}
}

func (m *Menu) showInfo(title, body string) {
	m.overlay = overlay{kind: ovInfo, title: title, info: body}
}

func (m *Menu) pickFile(title, dir, filter string, onFile func(*Menu, string) tea.Cmd) {
	if strings.TrimSpace(dir) == "" {
		dir = defaultBrowseDir()
	}
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	m.overlay = overlay{
		kind:    ovFiles,
		title:   title,
		browser: newBrowser(dir, filter),
		onFile:  onFile,
	}
}

func defaultBrowseDir() string {
	if home, err := os.UserHomeDir(); err == nil {
		return home
	}
	return mustGetwd()
}

// --- key handling ---

func (m *Menu) overlayKey(k tea.KeyMsg) tea.Cmd {
	key := k.String()
	ov := &m.overlay
	switch ov.kind {
	case ovInput:
		switch key {
		case "esc":
			cancel := ov.onCancel
			m.overlay = overlay{}
			if cancel != nil {
				return cancel(m)
			}
		case "enter":
			value := ov.value
			submit := ov.onSubmit
			m.overlay = overlay{}
			if submit != nil {
				return submit(m, value)
			}
		case "left":
			if ov.cursor > 0 {
				ov.cursor--
			}
		case "right":
			if ov.cursor < len([]rune(ov.value)) {
				ov.cursor++
			}
		case "home", "ctrl+a":
			ov.cursor = 0
		case "end", "ctrl+e":
			ov.cursor = len([]rune(ov.value))
		case "backspace", "ctrl+h":
			ov.deleteBack()
		case "delete":
			ov.deleteForward()
		case "ctrl+u":
			runes := []rune(ov.value)
			ov.value = string(runes[ov.cursor:])
			ov.cursor = 0
		case "ctrl+w":
			ov.deleteWord()
		default:
			if text, ok := typedText(k); ok {
				ov.insert(text)
			}
		}
	case ovText:
		switch key {
		case "esc":
			m.overlay = overlay{}
		case "ctrl+s":
			value := ov.value
			submit := ov.onSubmit
			m.overlay = overlay{}
			if submit != nil {
				return submit(m, value)
			}
		case "backspace", "ctrl+h":
			ov.deleteBack()
		case "ctrl+u":
			ov.value = ""
			ov.cursor = 0
		case "ctrl+w":
			ov.deleteWord()
		case "enter":
			ov.insert("\n")
		default:
			if text, ok := typedText(k); ok {
				ov.insert(text)
			}
		}
	case ovChoice:
		switch key {
		case "esc":
			m.overlay = overlay{}
		case "up", "k", "shift+tab":
			ov.choiceIdx = clampInt(ov.choiceIdx-1, 0, len(ov.choices)-1)
		case "down", "j", "tab":
			ov.choiceIdx = clampInt(ov.choiceIdx+1, 0, len(ov.choices)-1)
		case "enter":
			idx := ov.choiceIdx
			sel := ov.onSelect
			m.overlay = overlay{}
			if sel != nil {
				return sel(m, idx)
			}
		}
	case ovInfo:
		switch key {
		case "esc", "q", "enter":
			m.overlay = overlay{}
		case "up", "k":
			ov.scroll = maxInt(0, ov.scroll-1)
		case "down", "j":
			ov.scroll++
		case "pgup":
			ov.scroll = maxInt(0, ov.scroll-10)
		case "pgdown":
			ov.scroll += 10
		}
	case ovFiles:
		return m.browserKey(k, key)
	case ovWizard:
		return m.wizardKey(k, key)
	}
	return nil
}

// typedText reports printable input. Bubbletea reports the space bar as
// KeySpace rather than KeyRunes, so a rune-only check silently swallowed
// spaces in names, prompts and pasted profiles.
func typedText(k tea.KeyMsg) (string, bool) {
	if k.Paste || k.Type == tea.KeyRunes {
		return string(k.Runes), true
	}
	if k.Type == tea.KeySpace {
		if len(k.Runes) > 0 {
			return string(k.Runes), true
		}
		return " ", true
	}
	return "", false
}

func (ov *overlay) insert(text string) {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	runes := []rune(ov.value)
	ins := []rune(text)
	next := make([]rune, 0, len(runes)+len(ins))
	next = append(next, runes[:ov.cursor]...)
	next = append(next, ins...)
	next = append(next, runes[ov.cursor:]...)
	ov.value = string(next)
	ov.cursor += len(ins)
}

func (ov *overlay) deleteBack() {
	runes := []rune(ov.value)
	if ov.cursor <= 0 || ov.cursor > len(runes) {
		return
	}
	ov.value = string(append(runes[:ov.cursor-1], runes[ov.cursor:]...))
	ov.cursor--
}

func (ov *overlay) deleteForward() {
	runes := []rune(ov.value)
	if ov.cursor < 0 || ov.cursor >= len(runes) {
		return
	}
	ov.value = string(append(runes[:ov.cursor], runes[ov.cursor+1:]...))
}

func (ov *overlay) deleteWord() {
	runes := []rune(ov.value)
	i := ov.cursor
	for i > 0 && runes[i-1] == ' ' {
		i--
	}
	for i > 0 && runes[i-1] != ' ' && runes[i-1] != '\n' {
		i--
	}
	ov.value = string(append(runes[:i], runes[ov.cursor:]...))
	ov.cursor = i
}

// --- rendering ---

func (m *Menu) overlayView(h int) string {
	switch m.overlay.kind {
	case ovInput:
		return m.inputView(h)
	case ovChoice:
		return m.choiceView(h)
	case ovText:
		return m.textView(h)
	case ovInfo:
		return m.infoView(h)
	case ovFiles:
		return m.filesView(h)
	case ovWizard:
		return m.wizardView(h)
	}
	return ""
}

func (m *Menu) overlayFooter() string {
	switch m.overlay.kind {
	case ovInput:
		return "enter confirm · esc cancel · ←/→ move · ctrl+u clear"
	case ovText:
		return "ctrl+s import · esc cancel · enter newline · backspace edit"
	case ovChoice:
		return "↑/↓ choose · enter confirm · esc cancel"
	case ovInfo:
		return "↑/↓ scroll · esc close"
	case ovFiles:
		return "↑/↓ move · enter open/select · backspace parent · . hidden · / path · esc cancel"
	case ovWizard:
		return m.wizardFooter()
	}
	return "esc close"
}

func (m *Menu) dialogBox(title string, body []string, h int) string {
	w := m.contentWidth()
	rows := []string{"", " " + styleTitle.Render(title), ""}
	inner := maxInt(24, w-4)
	for _, line := range body {
		for _, wrapped := range wrapLines(line, inner) {
			rows = append(rows, " "+wrapped)
		}
	}
	// Key hints live in the single global footer; repeating them inside the
	// dialog pushed the body up and duplicated every hint.
	return m.layoutRows(rows, h)
}

func (m *Menu) inputView(h int) string {
	body := []string{}
	if m.overlay.prompt != "" {
		body = append(body, styleMuted.Render(m.overlay.prompt))
	}
	body = append(body, "", " "+m.inputLine(m.contentWidth()-4))
	return m.dialogBox(m.overlay.title, body, h)
}

func (m *Menu) inputLine(width int) string {
	if width < 8 {
		width = 8
	}
	runes := []rune(m.overlay.value)
	cursor := clampInt(m.overlay.cursor, 0, len(runes))
	start := 0
	if cursor > width-2 {
		start = cursor - (width - 2)
	}
	if start > len(runes) {
		start = len(runes)
	}
	var b strings.Builder
	if start > 0 {
		b.WriteString(styleMuted.Render("…"))
	}
	for i := start; i < len(runes); i++ {
		ch := string(runes[i])
		if m.overlay.masked {
			ch = "•"
		}
		if i == cursor {
			b.WriteString(styleAccent.Render(ch))
		} else {
			b.WriteString(ch)
		}
	}
	if cursor >= len(runes) {
		b.WriteString(styleAccent.Render("▏"))
	}
	return b.String()
}

func (m *Menu) choiceView(h int) string {
	body := wrapLines(m.overlay.info, maxInt(24, m.contentWidth()-4))
	body = append(body, "")
	for i, c := range m.overlay.choices {
		prefix := "  "
		label := c.label
		if c.danger {
			label = styleDanger.Render(label)
		}
		if i == m.overlay.choiceIdx {
			body = append(body, styleActive.Render(" "+prefix+padTo(c.label, maxInt(12, m.contentWidth()-8))+" "))
		} else {
			body = append(body, " "+prefix+label)
		}
	}
	return m.dialogBox(m.overlay.title, body, h)
}

func (m *Menu) textView(h int) string {
	value := m.overlay.value
	lines := strings.Split(value, "\n")
	lineCount := len(lines)
	charCount := len([]rune(value))
	body := []string{
		styleMuted.Render(fmt.Sprintf("%d line(s), %d character(s)", lineCount, charCount)),
		"",
	}
	width := maxInt(20, m.contentWidth()-4)
	// Show the tail of the buffer; the caret is always at the end.
	var shown []string
	for _, line := range lines {
		shown = append(shown, wrapLines(line, width)...)
		if line == "" {
			shown = append(shown, "")
		}
	}
	maxShown := h - 7
	if maxShown < 4 {
		maxShown = 4
	}
	if len(shown) > maxShown {
		shown = shown[len(shown)-maxShown:]
	}
	for _, line := range shown {
		body = append(body, " "+clipLine(line, width))
	}
	body = append(body, "", " "+styleMuted.Render(m.overlay.help))
	return m.dialogBox(m.overlay.title, body, h)
}

func (m *Menu) infoView(h int) string {
	width := maxInt(24, m.contentWidth()-4)
	lines := wrapLines(m.overlay.info, width)
	if m.overlay.scroll > len(lines)-1 {
		m.overlay.scroll = maxInt(0, len(lines)-1)
	}
	visible := h - 5
	if visible < 3 {
		visible = 3
	}
	end := minInt(len(lines), m.overlay.scroll+visible)
	body := lines[m.overlay.scroll:end]
	return m.dialogBox(m.overlay.title, body, h)
}

// wrapLines breaks text into lines no wider than width, preserving explicit
// line breaks.
func wrapLines(text string, width int) []string {
	if width <= 4 {
		return []string{text}
	}
	var out []string
	for _, raw := range strings.Split(text, "\n") {
		if raw == "" {
			out = append(out, "")
			continue
		}
		words := strings.Fields(raw)
		line := ""
		for _, word := range words {
			if line == "" {
				line = word
				continue
			}
			if len(line)+1+len(word) > width {
				out = append(out, line)
				line = word
				continue
			}
			line += " " + word
		}
		if line != "" {
			out = append(out, line)
		}
	}
	if len(out) == 0 {
		out = []string{""}
	}
	return out
}

// --- file browser ---

type browseEntry struct {
	name string
	path string
	dir  bool
	size int64
}

type browserState struct {
	dir        string
	filter     string
	entries    []browseEntry
	cursor     int
	offset     int
	showHidden bool
	err        string
}

func newBrowser(dir, filter string) *browserState {
	b := &browserState{dir: dir, filter: filter}
	b.reload()
	return b
}

func (b *browserState) reload() {
	entries, err := os.ReadDir(b.dir)
	if err != nil {
		b.err = err.Error()
		b.entries = nil
		b.cursor, b.offset = 0, 0
		return
	}
	b.err = ""
	var list []browseEntry
	for _, entry := range entries {
		name := entry.Name()
		if !b.showHidden && strings.HasPrefix(name, ".") {
			continue
		}
		full := filepath.Join(b.dir, name)
		var info os.FileInfo
		info, err = entry.Info()
		if err != nil {
			continue
		}
		isDir := info.IsDir()
		if info.Mode()&os.ModeSymlink != 0 {
			if target, statErr := os.Stat(full); statErr == nil {
				isDir = target.IsDir()
				info = target
			}
		}
		if !isDir && b.filter != "" && !strings.EqualFold(filepath.Ext(name), b.filter) {
			continue
		}
		list = append(list, browseEntry{name: name, path: full, dir: isDir, size: info.Size()})
	}
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].dir != list[j].dir {
			return list[i].dir
		}
		return strings.ToLower(list[i].name) < strings.ToLower(list[j].name)
	})
	b.entries = list
	if b.cursor >= len(list) {
		b.cursor = maxInt(0, len(list)-1)
	}
}

func (m *Menu) browserKey(k tea.KeyMsg, key string) tea.Cmd {
	b := m.overlay.browser
	if b == nil {
		m.overlay = overlay{}
		return nil
	}
	switch key {
	case "esc":
		cancel := m.overlay.onCancel
		m.overlay = overlay{}
		if cancel != nil {
			return cancel(m)
		}
	case "up", "k":
		b.cursor = clampInt(b.cursor-1, 0, maxInt(0, len(b.entries)-1))
	case "down", "j":
		b.cursor = clampInt(b.cursor+1, 0, maxInt(0, len(b.entries)-1))
	case "pgup":
		b.cursor = clampInt(b.cursor-10, 0, maxInt(0, len(b.entries)-1))
	case "pgdown":
		b.cursor = clampInt(b.cursor+10, 0, maxInt(0, len(b.entries)-1))
	case "home", "g":
		b.cursor = 0
	case "end", "G":
		b.cursor = maxInt(0, len(b.entries)-1)
	case "backspace", "left", "h":
		parent := filepath.Dir(b.dir)
		if parent != b.dir {
			b.dir = parent
			b.cursor, b.offset = 0, 0
			b.reload()
		}
	case "right", "l":
		if b.cursor < len(b.entries) && b.entries[b.cursor].dir {
			b.dir = b.entries[b.cursor].path
			b.cursor, b.offset = 0, 0
			b.reload()
		}
	case ".":
		b.showHidden = !b.showHidden
		b.reload()
	case "/":
		title, onFile, cancel := m.overlay.title, m.overlay.onFile, m.overlay.onCancel
		start := b.dir
		m.promptInput("Go to path", "Directory or file path", start, false, func(m *Menu, value string) tea.Cmd {
			value = expandHome(strings.TrimSpace(value))
			if value == "" {
				return nil
			}
			if info, err := os.Stat(value); err == nil && !info.IsDir() {
				if onFile != nil {
					return onFile(m, value)
				}
				return nil
			}
			b.dir = value
			b.cursor, b.offset = 0, 0
			b.reload()
			m.overlay = overlay{kind: ovFiles, title: title, browser: b, onFile: onFile, onCancel: cancel}
			return nil
		})
		m.overlay.onCancel = func(m *Menu) tea.Cmd {
			m.overlay = overlay{kind: ovFiles, title: title, browser: b, onFile: onFile, onCancel: cancel}
			return nil
		}
	case "enter":
		if b.cursor >= len(b.entries) {
			return nil
		}
		entry := b.entries[b.cursor]
		if entry.dir {
			b.dir = entry.path
			b.cursor, b.offset = 0, 0
			b.reload()
			return nil
		}
		onFile := m.overlay.onFile
		m.overlay = overlay{}
		if onFile != nil {
			return onFile(m, entry.path)
		}
	}
	return nil
}

func (m *Menu) filesView(h int) string {
	b := m.overlay.browser
	if b == nil {
		return ""
	}
	w := m.contentWidth()
	rows := []string{"", " " + styleTitle.Render(m.overlay.title), "", " " + styleMuted.Render("Path: ") + tailTruncate(b.dir, maxInt(12, w-8))}
	if b.err != "" {
		rows = append(rows, " "+styleErr.Render(truncatePlain(b.err, w-2)))
	}
	rows = append(rows, "")
	visible := h - len(rows) - 2
	if visible < 3 {
		visible = 3
	}
	if b.cursor < b.offset {
		b.offset = b.cursor
	}
	if b.cursor >= b.offset+visible {
		b.offset = b.cursor - visible + 1
	}
	end := minInt(len(b.entries), b.offset+visible)
	if len(b.entries) == 0 && b.err == "" {
		hint := "Empty directory"
		if b.filter != "" && !b.showHidden {
			hint = fmt.Sprintf("No %s files here (press . for hidden files, / to type a path)", b.filter)
		}
		rows = append(rows, " "+styleMuted.Render(hint))
	}
	for i := b.offset; i < end; i++ {
		e := b.entries[i]
		name := e.name
		if e.dir {
			name += "/"
		}
		size := ""
		if !e.dir {
			size = humanSize(e.size)
		}
		line := " " + padTo(truncatePlain(name, maxInt(10, w-14)), maxInt(10, w-14)) + " " + styleMuted.Render(size)
		if i == b.cursor {
			line = styleActive.Render(" " + padTo(truncatePlain(name, maxInt(10, w-14))+"  "+size, w-2) + " ")
		}
		rows = append(rows, line)
	}
	if end < len(b.entries) {
		rows = append(rows, " "+styleMuted.Render(fmt.Sprintf("… %d more", len(b.entries)-end)))
	}
	rows = append(rows, "", " "+styleMuted.Render(m.overlayFooter()))
	return m.layoutRows(rows, h)
}

func tailTruncate(s string, width int) string {
	if width <= 0 || len(s) <= width {
		return s
	}
	if width <= 1 {
		return "…"
	}
	return "…" + s[len(s)-(width-1):]
}

func humanSize(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
