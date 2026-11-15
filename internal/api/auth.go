package api

import (
	"crypto/subtle"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// AuthMiddleware enforces the management-plane access policy for the TCP API.
//
// A tokenless TCP listener is not a supported operating mode: every request is
// refused whether or not it comes from loopback. Loopback trust was removed
// because a browser page on the same machine (DNS rebinding) can originate
// loopback requests that an address check cannot tell apart from an operator.
// Local management stays available through the filesystem-authorized control
// socket and the panel, which keeps its own session authentication.
//
// On top of the token, the request shape is constrained: a cross-site Origin is
// refused, a tokenless request must carry a loopback Host, and a state-changing
// request with a body must declare application/json. An HTML form can produce
// neither a loopback Host nor a JSON content type, so a web page can no longer
// drive the API through a victim browser.
type AuthMiddleware struct {
	token      string
	privileged bool
	// loopbackTrusted is set only on platforms with no control socket, where
	// the loopback API is the sole local management channel. It is never set on
	// Unix, where the tokenless mode is unsupported and the control socket is
	// the authorized channel. Even then a request must carry a loopback Host,
	// no cross-site Origin and a JSON body where one is sent.
	loopbackTrusted bool
}

// NewAuthMiddleware creates a middleware that requires the token.
func NewAuthMiddleware(token string) *AuthMiddleware {
	return &AuthMiddleware{token: token}
}

// NewAuthMiddlewareFor records whether the daemon holds privileges. The flag
// selects the diagnostic hint only; it never grants access without a token.
func NewAuthMiddlewareFor(token string, privileged bool) *AuthMiddleware {
	return &AuthMiddleware{token: token, privileged: privileged}
}

// newAuthMiddlewareLocalTrust allows tokenless loopback access. The server sets
// it only when the platform has no control socket.
func newAuthMiddlewareLocalTrust(token string, privileged bool) *AuthMiddleware {
	return &AuthMiddleware{token: token, privileged: privileged, loopbackTrusted: true}
}

// Middleware returns an HTTP middleware that checks for a valid token.
func (a *AuthMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !originAllowed(r) {
			errorResponse(w, http.StatusForbidden, "cross-site requests are not accepted by the management API")
			return
		}
		if a.token == "" {
			if !loopbackHostRequest(r) {
				errorResponse(w, http.StatusForbidden, "the management API only accepts a loopback Host header without a token")
				return
			}
			if a.loopbackTrusted {
				next.ServeHTTP(w, r)
				return
			}
			if a.privileged {
				errorResponse(w, http.StatusUnauthorized,
					"API authentication is not configured for this privileged daemon; set server.api_token (the local TUI/CLI use the control socket)")
				return
			}
			errorResponse(w, http.StatusUnauthorized,
				"a tokenless management API is not supported; set server.api_token, or use the local control socket or the web panel")
			return
		}

		// Check the Authorization header ("Bearer <token>"); the raw
		// X-API-Key header is accepted as an alternative.
		presented := ""
		if authHeader := r.Header.Get("Authorization"); authHeader != "" {
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
				errorResponse(w, http.StatusUnauthorized, "invalid authorization header format")
				return
			}
			presented = parts[1]
		} else if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
			presented = apiKey
		} else {
			errorResponse(w, http.StatusUnauthorized, "missing authentication token")
			return
		}

		if !secureCompare(presented, a.token) {
			errorResponse(w, http.StatusUnauthorized, "invalid authentication token")
			return
		}
		if !jsonBodyDeclared(r) {
			errorResponse(w, http.StatusUnsupportedMediaType, "state-changing requests with a body must use Content-Type: application/json")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// secureCompare performs a constant-time comparison to prevent timing attacks.
func secureCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// originAllowed rejects browser requests that came from another site. Clients
// without an Origin header (CLI, TUI, curl, server-side probes) are decided by
// the token. "null" (sandboxed or opaque documents) is never trusted.
func originAllowed(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return loopbackHostname(u.Hostname())
}

// loopbackHostRequest reports whether the Host header names this machine. A
// DNS-rebinding request reaches 127.0.0.1 but keeps the attacker's hostname in
// Host, which this check refuses.
func loopbackHostRequest(r *http.Request) bool {
	return loopbackHostname(requestHostname(r.Host))
}

func requestHostname(hostport string) string {
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return host
	}
	return strings.Trim(hostport, "[]")
}

func loopbackHostname(host string) bool {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// jsonBodyDeclared rejects a state-changing request whose body is not JSON.
// Body-less POSTs (probes, connect/disconnect) stay valid because they carry no
// payload a form could smuggle.
func jsonBodyDeclared(r *http.Request) bool {
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
	default:
		return true
	}
	if r.Body == nil || r.Body == http.NoBody {
		return true
	}
	if r.ContentLength == 0 && len(r.TransferEncoding) == 0 {
		return true
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return false
	}
	return strings.EqualFold(mediaType, "application/json")
}
