package api

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// AuthMiddleware provides simple token-based authentication for the API.
// If no token is configured, all requests are allowed (backward compatible).
type AuthMiddleware struct {
	token string
}

// NewAuthMiddleware creates a new auth middleware.
// If token is empty, authentication is disabled.
func NewAuthMiddleware(token string) *AuthMiddleware {
	return &AuthMiddleware{token: token}
}

// Middleware returns an HTTP middleware that checks for a valid token.
func (a *AuthMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If no token configured, allow all requests
		if a.token == "" {
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
