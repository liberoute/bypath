package profile

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// TestHTTPS checks if a proxy can relay HTTPS traffic.
// It curls an HTTPS endpoint through the given SOCKS proxy port.
// Returns true if the HTTPS request succeeds (HTTP status 200 or 204).
func TestHTTPS(ctx context.Context, proxyPort int) bool {
	testCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	cmd := exec.CommandContext(testCtx, "curl", "-s",
		"-x", fmt.Sprintf("socks5h://127.0.0.1:%d", proxyPort),
		"--connect-timeout", "6",
		"-o", "/dev/null",
		"-w", "%{http_code}",
		"https://cp.cloudflare.com")
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	code := strings.TrimSpace(string(out))
	return code == "200" || code == "204"
}
