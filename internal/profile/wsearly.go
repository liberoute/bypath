package profile

import (
	"strconv"
	"strings"
)

// EarlyDataHeaderDefault is the header Xray and sing-box use for WebSocket
// early data when the profile does not name one.
const EarlyDataHeaderDefault = "Sec-WebSocket-Protocol"

// SplitWSPathEarlyData removes the Xray WebSocket early-data hint ("?ed=NNN")
// from a request path and returns its value. Xray consumes the hint itself,
// but sing-box sends the path verbatim, the server compares it exactly, and
// the upgrade is rejected with HTTP 404. Callers translate the hint into an
// explicit early-data field instead. Other query parameters are preserved.
func SplitWSPathEarlyData(rawPath string) (string, int) {
	base, query, found := strings.Cut(rawPath, "?")
	if !found {
		return rawPath, 0
	}
	parts := strings.Split(query, "&")
	kept := make([]string, 0, len(parts))
	ed := 0
	for _, part := range parts {
		if key, value, ok := strings.Cut(part, "="); ok && key == "ed" {
			if n, err := strconv.Atoi(value); err == nil && n > 0 {
				ed = n
				continue
			}
		}
		kept = append(kept, part)
	}
	if ed == 0 {
		return rawPath, 0
	}
	if len(kept) == 0 {
		return base, ed
	}
	return base + "?" + strings.Join(kept, "&"), ed
}
