package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/liberoute/bypath/internal/app"
)

// TestFooterWrapsInsteadOfClipping proves narrow SSH terminals keep every key
// hint visible rather than cutting the line mid-word.
func TestFooterWrapsInsteadOfClipping(t *testing.T) {
	m := &Menu{section: secConnections}
	for _, width := range []int{40, 80, 100} {
		lines := m.footerLines(width)
		joined := strings.Join(lines, " ")
		for _, want := range []string{"x delete", "/ search", "n import"} {
			if !strings.Contains(joined, want) {
				t.Fatalf("width %d: footer %q lost %q", width, joined, want)
			}
		}
		for _, line := range lines {
			if lipgloss.Width(line) > width {
				t.Fatalf("width %d: footer line %q overflows", width, line)
			}
		}
	}
	if lines := m.footerLines(80); len(lines) < 2 {
		t.Fatalf("80 columns should wrap the connections footer, got %d line(s)", len(lines))
	}
}

// TestSectionsFitNarrowTerminal renders every section at the common 80-column
// SSH width and a wider window, asserting no line overflows.
func TestSectionsFitNarrowTerminal(t *testing.T) {
	for _, width := range []int{80, 120} {
		for s := section(0); s < secCount; s++ {
			m := &Menu{section: s, width: width, height: 24}
			for i, line := range strings.Split(m.View(), "\n") {
				if got := lipgloss.Width(line); got > width {
					t.Fatalf("%s at width %d: line %d is %d columns: %q", sectionTitles[s], width, i, got, line)
				}
			}
		}
	}
}

func TestMutedLinesKeepFullSentence(t *testing.T) {
	const text = "Configuration changes are validated and written atomically. Secrets are never displayed."
	lines := wrapPlain(text, 79)
	if len(lines) < 2 {
		t.Fatalf("expected wrapping at 80 columns, got %d line(s)", len(lines))
	}
	var words []string
	for _, line := range lines {
		words = append(words, strings.Fields(line)...)
	}
	if got := strings.Join(words, " "); got != text {
		t.Fatalf("wrapped copy changed: %q", got)
	}
}

// TestInputAcceptsSpaces proves the space bar reaches text prompts instead of
// being swallowed by the key filter.
func TestInputAcceptsSpaces(t *testing.T) {
	var got string
	m := &Menu{}
	m.promptInput("Rename", "New name", "Old", false, func(_ *Menu, value string) tea.Cmd {
		got = value
		return nil
	})
	for _, r := range "New Name" {
		msg := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}}
		if r == ' ' {
			msg = tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}}
		}
		m.handleKey(msg)
	}
	m.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	if got != "OldNew Name" {
		t.Fatalf("submitted %q, want %q", got, "OldNew Name")
	}
}

// TestDNSSectionLoadsSettings proves the DNS page reads its mode and upstreams
// from the shared service instead of showing empty values until Settings is
// visited.
func TestDNSSectionLoadsSettings(t *testing.T) {
	stub := &stubService{settings: app.Settings{DNSMode: "strict", DNSUpstream: []string{"1.1.1.1"}}}
	m := &Menu{svc: stub, width: 80, height: 24}
	m.goSection(secDNS)
	cmd := m.reloadCurrent()
	if cmd == nil {
		t.Fatal("DNS section returned no reload command")
	}
	msg := cmd()
	batch, ok := msg.(tea.BatchMsg)
	if !ok {
		t.Fatalf("DNS reload is not a batch: %T", msg)
	}
	for _, sub := range batch {
		if sm, ok := sub().(settingsMsg); ok {
			if sm.err != nil || len(sm.settings.DNSUpstream) != 1 {
				t.Fatalf("DNS reload did not return settings: %+v", sm)
			}
			return
		}
	}
	t.Fatal("DNS reload never loaded settings")
}

func TestFooterHeightMatchesRenderedLines(t *testing.T) {
	m := &Menu{section: secSettings, width: 80, height: 24}
	if got, want := m.footerHeight(), lipgloss.Height(m.viewFooter()); got != want {
		t.Fatalf("footerHeight = %d, rendered = %d", got, want)
	}
}
