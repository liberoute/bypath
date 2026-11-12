package app

import (
	"io"
	"regexp"
	"strings"
	"sync"
	"time"
)

// LogBuffer is a bounded in-memory log sink shared by the gateway logger, the
// API, the TUI and the web panel. It is an io.Writer so it can be attached with
// io.MultiWriter next to the file logger.
type LogBuffer struct {
	mu      sync.RWMutex
	entries []LogEntry
	max     int
	now     func() time.Time
}

// NewLogBuffer creates a ring buffer holding at most max entries.
func NewLogBuffer(max int) *LogBuffer {
	if max <= 0 {
		max = 2000
	}
	return &LogBuffer{max: max, now: time.Now}
}

// Write implements io.Writer. Each call is treated as one or more log lines.
func (b *LogBuffer) Write(p []byte) (int, error) {
	if b == nil {
		return len(p), nil
	}
	text := Redact(string(p))
	for _, line := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		entry := LogEntry{
			Time:    b.now().UTC().Format(time.RFC3339),
			Level:   levelOf(line),
			Message: line,
		}
		b.mu.Lock()
		b.entries = append(b.entries, entry)
		if len(b.entries) > b.max {
			b.entries = append([]LogEntry(nil), b.entries[len(b.entries)-b.max:]...)
		}
		b.mu.Unlock()
	}
	return len(p), nil
}

// Recent returns the newest entries up to limit, oldest first.
func (b *LogBuffer) Recent(limit int) []LogEntry {
	if b == nil {
		return nil
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if limit <= 0 || limit > len(b.entries) {
		limit = len(b.entries)
	}
	out := make([]LogEntry, limit)
	copy(out, b.entries[len(b.entries)-limit:])
	return out
}

// Len reports the number of buffered entries.
func (b *LogBuffer) Len() int {
	if b == nil {
		return 0
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.entries)
}

func levelOf(line string) string {
	l := strings.ToLower(line)
	switch {
	case strings.Contains(l, "❌") || strings.Contains(l, "error") || strings.Contains(l, "failed"):
		return "error"
	case strings.Contains(l, "⚠") || strings.Contains(l, "warn") || strings.Contains(l, "degraded"):
		return "warn"
	default:
		return "info"
	}
}

var redactions = []struct {
	re   *regexp.Regexp
	repl string
}{
	{regexp.MustCompile(`(?i)(authorization:\s*bearer\s+)\S+`), "${1}<redacted>"},
	{regexp.MustCompile(`(?i)\b(api[_-]?token|password|passwd|secret|private[_-]?key|auth)(\s*[:=]\s*)("?)[^\s",]+`), "${1}${2}${3}<redacted>"},
	{regexp.MustCompile(`(?i)\b(vmess|vless|trojan|ss|wireguard|wg|ssh)://\S+`), "${1}://<redacted>"},
	{regexp.MustCompile(`(?i)\b(socks5h?|https?)://[^/@\s]+@\S+`), "${1}://<redacted>@"},
}

// Redact removes credentials, proxy URIs and tokens from a log line before it
// is stored, displayed, exported or returned by any API.
func Redact(line string) string {
	out := line
	for _, r := range redactions {
		out = r.re.ReplaceAllString(out, r.repl)
	}
	return out
}

var _ io.Writer = (*LogBuffer)(nil)
