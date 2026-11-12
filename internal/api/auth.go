package api

import (
	"crypto/subtle"
	"net"
	"net/http"
	"strings"
)

// AuthMiddleware provides simple token-based authentication for the API.
// Without a token, only loopback clients may manage an unprivileged gateway; a
// privileged (root) daemon refuses unauthenticated TCP access entirely, since
// loopback trust would let every local account control host networking.
type AuthMiddleware struct {
	token      string
	privileged bool
}

// NewAuthMiddleware creates a new auth middleware for an unprivileged process.
// If token is empty, loopback clients are trusted.
func NewAuthMiddleware(token string) *AuthMiddleware {
	return &AuthMiddleware{token: token}
}

// NewAuthMiddlewareFor creates the middleware and states whether the daemon
// holds privileges that must not be reachable through an unauthenticated
// loopback API. The TUI/CLI use the permissioned control socket instead.
func NewAuthMiddlewareFor(token string, privileged bool) *AuthMiddleware {
	return &AuthMiddleware{token: token, privileged: privileged}
}

// Middleware returns an HTTP middleware that checks for a valid token.
func (a *AuthMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If no token is configured, only loopback clients are trusted.
		if a.token == "" {
			if a.privileged {
				errorResponse(w, http.StatusUnauthorized,
					"API authentication is not configured for this privileged daemon; set server.api_token (the local TUI/CLI use the control socket)")
				return
			}
			if !remoteIsLoopback(r) {
				errorResponse(w, http.StatusUnauthorized,
					"API authentication is not configured; set server.api_token or connect from this machine")
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		// Check Authorization header: "Bearer <token>"
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			// Also check X-API-Key header
			authHeader = r.Header.Get("X-API-Key")
			if authHeader == "" {
				errorResponse(w, http.StatusUnauthorized, "missing authentication token")
				return
			}
			// X-API-Key is the raw token
			if !secureCompare(authHeader, a.token) {
				errorResponse(w, http.StatusUnauthorized, "invalid authentication token")
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		// Parse "Bearer <token>"
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			errorResponse(w, http.StatusUnauthorized, "invalid authorization header format")
			return
		}

		if !secureCompare(parts[1], a.token) {
			errorResponse(w, http.StatusUnauthorized, "invalid authentication token")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// secureCompare performs a constant-time comparison to prevent timing attacks.
func secureCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// remoteIsLoopback reports whether the TCP peer is on this machine. Proxy
// headers are deliberately ignored so a remote client cannot claim loopback.
func remoteIsLoopback(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}
