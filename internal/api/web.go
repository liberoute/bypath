package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/liberoute/bypath/internal/app"
	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/securefile"
	"golang.org/x/crypto/scrypt"
)

// webUIAssets is the panel itself: plain HTML, CSS and JavaScript served from
// the binary, so no build step or CDN is required on the gateway host.
//
//go:embed webui
var webUIAssets embed.FS

const (
	sessionCookieName = "bypath_session"
	sessionIdleLimit  = 12 * time.Hour
	sessionMaxAge     = 24 * time.Hour
	maxSessions       = 128

	scryptN      = 1 << 15
	scryptR      = 8
	scryptP      = 1
	scryptKeyLen = 32

	minPasswordLength = 12
	maxPasswordBytes  = 1024
)

type webSession struct {
	username string
	csrf     string
	created  time.Time
	lastSeen time.Time
}

type loginAttempt struct {
	failures     int
	blockedUntil time.Time
	last         time.Time
}

// webAPI is the browser-facing management surface. It authenticates operators
// with a local admin account, then exposes the same application handlers the
// CLI and TUI use. It owns only auth/session state, never profile state.
type webAPI struct {
	cfg       *config.Config
	svc       *app.Local
	router    *mux.Router
	adminPath string
	token     string

	// privileged marks a root daemon. First-admin setup then proves authority
	// with the API token or the one-time setup code, not merely with a loopback
	// source address: any local account could otherwise claim a root-equivalent
	// administrator.
	privileged    bool
	setupCode     string
	setupCodePath string

	listenHost     string
	allowedHosts   map[string]bool
	allowedOrigins []string

	mu       sync.Mutex
	sessions map[[32]byte]*webSession
	attempts map[string]*loginAttempt

	now func() time.Time
}

// adminRecord is the on-disk administrator credential. It stores a scrypt hash,
// never the password.
type adminRecord struct {
	Version   int    `json:"version"`
	Username  string `json:"username"`
	KDF       string `json:"kdf"`
	Salt      string `json:"salt"`
	N         int    `json:"n"`
	R         int    `json:"r"`
	P         int    `json:"p"`
	Hash      string `json:"hash"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

func newWebAPI(cfg *config.Config, svc *app.Local) (*webAPI, error) {
	if err := config.ValidateWeb(cfg.Server.Web); err != nil {
		return nil, err
	}
	adminPath := filepath.Join(filepath.Dir(cfg.Profiles.Directory), "web", "admin.json")
	web := &webAPI{
		cfg:          cfg,
		svc:          svc,
		adminPath:    adminPath,
		token:        cfg.Server.APIToken,
		privileged:   os.Geteuid() == 0,
		listenHost:   strings.TrimSpace(cfg.Server.Web.Listen),
		allowedHosts: make(map[string]bool),
		sessions:     make(map[[32]byte]*webSession),
		attempts:     make(map[string]*loginAttempt),
		now:          time.Now,
	}
	if web.privileged {
		web.setupCodePath = filepath.Join(filepath.Dir(adminPath), "setup-code")
		if _, err := os.Stat(adminPath); errors.Is(err, os.ErrNotExist) {
			code, codeErr := ensureSetupCode(web.setupCodePath)
			if codeErr != nil {
				// Fail closed: without a code, a privileged daemon only accepts
				// first-admin setup with the API token.
				log.Printf("⚠️  Web setup code unavailable: %v", codeErr)
			}
			web.setupCode = code
		}
	}
	for _, origin := range cfg.Server.Web.AllowedOrigins {
		u, err := url.Parse(strings.TrimSpace(origin))
		if err != nil || u.Host == "" {
			continue
		}
		normalized := strings.ToLower(u.Scheme + "://" + u.Host)
		web.allowedOrigins = append(web.allowedOrigins, normalized)
		web.allowedHosts[strings.ToLower(u.Hostname())] = true
	}
	if web.listenHost != "" && !isAnyHost(web.listenHost) {
		web.allowedHosts[strings.ToLower(web.listenHost)] = true
	}

	web.router = web.buildRouter()
	return web, nil
}

func (s *webAPI) buildRouter() *mux.Router {
	r := mux.NewRouter()
	r.Use(s.securityHeaders)
	r.Use(s.hostGuard)

	r.HandleFunc("/api/v1/web/health", s.health).Methods("GET")
	r.HandleFunc("/api/v1/web/session", s.sessionInfo).Methods("GET")
	r.HandleFunc("/api/v1/web/setup", s.setup).Methods("POST")
	r.HandleFunc("/api/v1/web/login", s.login).Methods("POST")
	r.HandleFunc("/api/v1/web/logout", s.logout).Methods("POST")
	r.HandleFunc("/api/v1/web/password", s.changePassword).Methods("POST")

	appRouter := r.PathPrefix("/api/v1/app").Subrouter()
	appRouter.Use(s.requireSession)
	appRouter.Use(s.requireCSRF)
	server := &Server{config: s.cfg, svc: s.svc}
	server.registerAppRoutesOn(appRouter)

	assets, err := fs.Sub(webUIAssets, "webui")
	if err != nil {
		// The directory is compiled into the binary; this only fails if the
		// embed directive and the source tree disagree.
		panic(fmt.Sprintf("web panel assets are missing: %v", err))
	}
	// Registered last: every API route above matches first, so this only
	// serves the panel and honest 404s for unknown API paths.
	r.PathPrefix("/").Handler(s.spaHandler(assets))
	return r
}

// spaHandler serves the embedded files and returns index.html for unknown
// document paths, so a hash route or reload always lands on the panel. Unknown
// /api paths stay JSON 404s instead of turning into HTML.
func (s *webAPI) spaHandler(assets fs.FS) http.Handler {
	index, err := fs.ReadFile(assets, "index.html")
	if err != nil {
		panic(fmt.Sprintf("web panel index is missing: %v", err))
	}
	files := http.FileServer(http.FS(assets))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			webError(w, http.StatusNotFound, "not_found", "no such endpoint")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			webError(w, http.StatusMethodNotAllowed, "method_not_allowed", "this endpoint accepts GET only")
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" || path == "index.html" {
			writeIndex(w, r, index)
			return
		}
		if info, statErr := fs.Stat(assets, path); statErr != nil || info.IsDir() {
			writeIndex(w, r, index)
			return
		}
		files.ServeHTTP(w, r)
	})
}

func writeIndex(w http.ResponseWriter, r *http.Request, index []byte) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(index)
}

// --- middleware ---

func (s *webAPI) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self'; "+
				"img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "+
				"base-uri 'none'; form-action 'self'")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// hostGuard defeats DNS rebinding and cross-site writes. Host names are only
// accepted when they are IP literals, loopback, the configured bind host or an
// explicitly allowed reverse-proxy origin.
func (s *webAPI) hostGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.hostAllowed(r.Host) {
			webError(w, http.StatusForbidden, "host_not_allowed", "this host name is not allowed to reach the panel")
			return
		}
		if isWriteMethod(r.Method) {
			if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
				if !s.originAllowed(origin, r.Host) {
					webError(w, http.StatusForbidden, "origin_not_allowed", "cross-origin requests are not accepted")
					return
				}
			}
			switch r.Header.Get("Sec-Fetch-Site") {
			case "", "same-origin", "none":
			default:
				webError(w, http.StatusForbidden, "origin_not_allowed", "cross-site requests are not accepted")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *webAPI) hostAllowed(rawHost string) bool {
	host := strings.ToLower(hostnameOf(rawHost))
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		// A DNS name resolving to this machine would arrive as that name, not
		// as an IP literal, so literal IPs cannot be used for rebinding.
		return true
	}
	return s.allowedHosts[host]
}

func (s *webAPI) originAllowed(origin, requestHost string) bool {
	u, err := url.Parse(strings.TrimSpace(origin))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	if strings.EqualFold(u.Host, requestHost) {
		return true
	}
	normalized := strings.ToLower(u.Scheme + "://" + u.Host)
	for _, allowed := range s.allowedOrigins {
		if normalized == allowed {
			return true
		}
	}
	return false
}

type sessionCtxKey struct{}

func contextWithSession(ctx context.Context, sess *webSession) context.Context {
	return context.WithValue(ctx, sessionCtxKey{}, sess)
}

func sessionFromContext(r *http.Request) *webSession {
	sess, _ := r.Context().Value(sessionCtxKey{}).(*webSession)
	return sess
}

func (s *webAPI) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, _ := s.sessionFromRequest(r)
		if sess == nil {
			webError(w, http.StatusUnauthorized, "unauthenticated", "sign in to manage this gateway")
			return
		}
		next.ServeHTTP(w, r.WithContext(contextWithSession(r.Context(), sess)))
	})
}

func (s *webAPI) requireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isWriteMethod(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		sess := sessionFromContext(r)
		if sess == nil {
			webError(w, http.StatusUnauthorized, "unauthenticated", "sign in to manage this gateway")
			return
		}
		provided := r.Header.Get("X-CSRF-Token")
		if provided == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(sess.csrf)) != 1 {
			webError(w, http.StatusForbidden, "csrf", "missing or invalid CSRF token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- session state ---

func (s *webAPI) newSession(username string) (string, *webSession) {
	tokenBytes := make([]byte, 32)
	csrfBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", nil
	}
	if _, err := rand.Read(csrfBytes); err != nil {
		return "", nil
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	now := s.now()
	sess := &webSession{
		username: username,
		csrf:     base64.RawURLEncoding.EncodeToString(csrfBytes),
		created:  now,
		lastSeen: now,
	}
	key := sha256.Sum256([]byte(token))

	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneSessionsLocked(now)
	for len(s.sessions) >= maxSessions {
		s.evictOldestLocked()
	}
	s.sessions[key] = sess
	return token, sess
}

func (s *webAPI) sessionFromRequest(r *http.Request) (*webSession, string) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return nil, ""
	}
	key := sha256.Sum256([]byte(cookie.Value))
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[key]
	if !ok {
		return nil, ""
	}
	if now.Sub(sess.lastSeen) > sessionIdleLimit || now.Sub(sess.created) > sessionMaxAge {
		delete(s.sessions, key)
		return nil, ""
	}
	sess.lastSeen = now
	return sess, cookie.Value
}

func (s *webAPI) deleteSession(token string) {
	if token == "" {
		return
	}
	key := sha256.Sum256([]byte(token))
	s.mu.Lock()
	delete(s.sessions, key)
	s.mu.Unlock()
}

func (s *webAPI) deleteAllSessions() {
	s.mu.Lock()
	s.sessions = make(map[[32]byte]*webSession)
	s.mu.Unlock()
}

func (s *webAPI) pruneSessionsLocked(now time.Time) {
	for key, sess := range s.sessions {
		if now.Sub(sess.lastSeen) > sessionIdleLimit || now.Sub(sess.created) > sessionMaxAge {
			delete(s.sessions, key)
		}
	}
}

func (s *webAPI) evictOldestLocked() {
	var oldestKey [32]byte
	var oldest time.Time
	first := true
	for key, sess := range s.sessions {
		if first || sess.lastSeen.Before(oldest) {
			oldestKey, oldest, first = key, sess.lastSeen, false
		}
	}
	if !first {
		delete(s.sessions, oldestKey)
	}
}

// --- login throttling ---

func (s *webAPI) attemptKey(r *http.Request, username string) string {
	return clientIP(r) + "|" + strings.ToLower(strings.TrimSpace(username))
}

func (s *webAPI) blockedFor(key string) time.Duration {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	attempt, ok := s.attempts[key]
	if !ok {
		return 0
	}
	if now.Sub(attempt.last) > time.Hour {
		delete(s.attempts, key)
		return 0
	}
	if now.Before(attempt.blockedUntil) {
		return attempt.blockedUntil.Sub(now)
	}
	return 0
}

func (s *webAPI) recordFailure(key string) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.attempts) > 4096 {
		for k, a := range s.attempts {
			if now.Sub(a.last) > time.Hour {
				delete(s.attempts, k)
			}
		}
	}
	attempt, ok := s.attempts[key]
	if !ok || now.Sub(attempt.last) > time.Hour {
		attempt = &loginAttempt{}
		s.attempts[key] = attempt
	}
	attempt.failures++
	attempt.last = now
	switch {
	case attempt.failures >= 10:
		attempt.blockedUntil = now.Add(10 * time.Minute)
	case attempt.failures >= 8:
		attempt.blockedUntil = now.Add(2 * time.Minute)
	case attempt.failures >= 5:
		attempt.blockedUntil = now.Add(30 * time.Second)
	}
}

func (s *webAPI) clearFailures(key string) {
	s.mu.Lock()
	delete(s.attempts, key)
	s.mu.Unlock()
}

// --- admin store ---

func (s *webAPI) loadAdmin() (*adminRecord, error) {
	data, err := os.ReadFile(s.adminPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading administrator record: %w", err)
	}
	var rec adminRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("administrator record is corrupt: %w", err)
	}
	if rec.Version != 1 || rec.KDF != "scrypt" || rec.Username == "" {
		return nil, fmt.Errorf("administrator record has an unsupported format")
	}
	if rec.N < 1<<14 || rec.N > 1<<20 || rec.N&(rec.N-1) != 0 || rec.R < 1 || rec.P < 1 {
		return nil, fmt.Errorf("administrator record has invalid scrypt parameters")
	}
	if _, err := base64.RawStdEncoding.DecodeString(rec.Salt); err != nil {
		return nil, fmt.Errorf("administrator record has an invalid salt")
	}
	if _, err := base64.RawStdEncoding.DecodeString(rec.Hash); err != nil {
		return nil, fmt.Errorf("administrator record has an invalid hash")
	}
	return &rec, nil
}

func (s *webAPI) saveAdmin(username, password string, created string) error {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("generating salt: %w", err)
	}
	hash, err := scrypt.Key([]byte(password), salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return fmt.Errorf("deriving password hash: %w", err)
	}
	now := s.now().UTC().Format(time.RFC3339)
	if created == "" {
		created = now
	}
	rec := adminRecord{
		Version:   1,
		Username:  username,
		KDF:       "scrypt",
		Salt:      base64.RawStdEncoding.EncodeToString(salt),
		N:         scryptN,
		R:         scryptR,
		P:         scryptP,
		Hash:      base64.RawStdEncoding.EncodeToString(hash),
		CreatedAt: created,
		UpdatedAt: now,
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.adminPath)
	if err := securefile.MkdirAll(dir); err != nil {
		return fmt.Errorf("creating web state directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".admin-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpName)
	if err := securefile.WriteFile(tmpName, data); err != nil {
		return err
	}
	if err := os.Rename(tmpName, s.adminPath); err != nil {
		return err
	}
	return securefile.RestrictFile(s.adminPath)
}

func verifyPassword(rec *adminRecord, password string) bool {
	salt, err := base64.RawStdEncoding.DecodeString(rec.Salt)
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(rec.Hash)
	if err != nil {
		return false
	}
	got, err := scrypt.Key([]byte(password), salt, rec.N, rec.R, rec.P, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// --- handlers ---

func (s *webAPI) health(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *webAPI) sessionInfo(w http.ResponseWriter, r *http.Request) {
	sess, _ := s.sessionFromRequest(r)
	if sess == nil {
		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"authenticated":       false,
			"setup_required":      s.adminMissing(),
			"setup_code_required": s.privileged && s.setupCode != "",
		})
		return
	}
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"authenticated": true,
		"username":      sess.username,
		"csrf":          sess.csrf,
		"expires_at":    sess.created.Add(sessionMaxAge).UTC().Format(time.RFC3339),
	})
}

func (s *webAPI) adminMissing() bool {
	_, err := os.Stat(s.adminPath)
	return errors.Is(err, os.ErrNotExist)
}

// ensureSetupCode reads or creates the one-time code that authorizes first-admin
// setup on a root daemon. The file is owner-only in the web state directory;
// the operator reads it as root and enters it in the panel.
func ensureSetupCode(path string) (string, error) {
	if b, err := os.ReadFile(path); err == nil {
		code := strings.TrimSpace(string(b))
		if len(code) >= 8 && len(code) <= 64 {
			return code, nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", err
	}
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	code := base64.RawURLEncoding.EncodeToString(buf)
	if err := securefile.WriteFile(path, []byte(code)); err != nil {
		return "", err
	}
	return code, nil
}

func (s *webAPI) setup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username  string `json:"username"`
		Password  string `json:"password"`
		SetupCode string `json:"setup_code"`
	}
	if !decodeBody(w, r, &req, 16<<10) {
		return
	}
	key := s.attemptKey(r, "setup")
	if retry := s.blockedFor(key); retry > 0 {
		webRateLimited(w, retry)
		return
	}

	if !s.setupAllowed(r, req.SetupCode) {
		webError(w, http.StatusForbidden, "setup_forbidden",
			"initial setup needs the setup code from the Bypath data directory (or the API token)")
		return
	}
	if _, err := os.Stat(s.adminPath); err == nil {
		webError(w, http.StatusConflict, "already_configured", "an administrator already exists")
		return
	} else if !errors.Is(err, os.ErrNotExist) {
		webError(w, http.StatusServiceUnavailable, "unavailable", "the administrator record is unreadable")
		return
	}

	// Count every setup attempt, valid or not, so a LAN scan cannot retry
	// indefinitely. A successful setup clears the counter below.
	s.recordFailure(key)

	username := strings.TrimSpace(req.Username)
	if !validAdminUsername(username) {
		webError(w, http.StatusBadRequest, "invalid", "username must be 1-64 letters, digits, dots, dashes or underscores")
		return
	}
	if !validPassword(req.Password) {
		webError(w, http.StatusBadRequest, "invalid", fmt.Sprintf("password must be at least %d characters", minPasswordLength))
		return
	}
	if err := s.saveAdmin(username, req.Password, ""); err != nil {
		log.Printf("❌ Web setup failed: %v", err)
		webError(w, http.StatusInternalServerError, "unavailable", "could not store the administrator record")
		return
	}
	// The code authorized exactly one administrator. It is useless now and
	// must not remain on disk for a later setup window.
	if s.setupCodePath != "" {
		if err := os.Remove(s.setupCodePath); err == nil || errors.Is(err, os.ErrNotExist) {
			s.setupCode = ""
		}
	}
	s.clearFailures(key)
	token, sess := s.newSession(username)
	if sess == nil {
		webError(w, http.StatusInternalServerError, "unavailable", "could not create a session")
		return
	}
	s.setSessionCookie(w, r, token)
	jsonResponse(w, http.StatusCreated, map[string]interface{}{
		"authenticated": true,
		"username":      sess.username,
		"csrf":          sess.csrf,
	})
}

func (s *webAPI) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeBody(w, r, &req, 16<<10) {
		return
	}
	key := s.attemptKey(r, req.Username)
	if retry := s.blockedFor(key); retry > 0 {
		webRateLimited(w, retry)
		return
	}
	rec, err := s.loadAdmin()
	if err != nil {
		log.Printf("❌ Web login unavailable: %v", err)
		webError(w, http.StatusServiceUnavailable, "unavailable", "the administrator record is unreadable")
		return
	}
	if rec == nil {
		webError(w, http.StatusConflict, "setup_required", "no administrator is configured yet")
		return
	}

	usernameOK := subtle.ConstantTimeCompare([]byte(rec.Username), []byte(strings.TrimSpace(req.Username))) == 1
	passwordOK := verifyPassword(rec, req.Password)
	if !usernameOK || !passwordOK {
		s.recordFailure(key)
		webError(w, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
		return
	}
	s.clearFailures(key)
	token, sess := s.newSession(rec.Username)
	if sess == nil {
		webError(w, http.StatusInternalServerError, "unavailable", "could not create a session")
		return
	}
	s.setSessionCookie(w, r, token)
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"authenticated": true,
		"username":      sess.username,
		"csrf":          sess.csrf,
		"expires_at":    sess.created.Add(sessionMaxAge).UTC().Format(time.RFC3339),
	})
}

func (s *webAPI) logout(w http.ResponseWriter, r *http.Request) {
	sess, token := s.sessionFromRequest(r)
	if sess != nil {
		provided := r.Header.Get("X-CSRF-Token")
		if subtle.ConstantTimeCompare([]byte(provided), []byte(sess.csrf)) != 1 {
			webError(w, http.StatusForbidden, "csrf", "missing or invalid CSRF token")
			return
		}
		s.deleteSession(token)
	}
	s.clearSessionCookie(w, r)
	w.WriteHeader(http.StatusNoContent)
}

func (s *webAPI) changePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !decodeBody(w, r, &req, 16<<10) {
		return
	}
	sess, _ := s.sessionFromRequest(r)
	if sess == nil {
		webError(w, http.StatusUnauthorized, "unauthenticated", "sign in to manage this gateway")
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(sess.csrf)) != 1 {
		webError(w, http.StatusForbidden, "csrf", "missing or invalid CSRF token")
		return
	}
	key := s.attemptKey(r, sess.username)
	if retry := s.blockedFor(key); retry > 0 {
		webRateLimited(w, retry)
		return
	}
	rec, err := s.loadAdmin()
	if err != nil || rec == nil {
		webError(w, http.StatusServiceUnavailable, "unavailable", "the administrator record is unreadable")
		return
	}
	if !verifyPassword(rec, req.CurrentPassword) {
		s.recordFailure(key)
		webError(w, http.StatusUnauthorized, "invalid_credentials", "current password is incorrect")
		return
	}
	if !validPassword(req.NewPassword) {
		webError(w, http.StatusBadRequest, "invalid", fmt.Sprintf("password must be at least %d characters", minPasswordLength))
		return
	}
	if err := s.saveAdmin(rec.Username, req.NewPassword, rec.CreatedAt); err != nil {
		log.Printf("❌ Web password change failed: %v", err)
		webError(w, http.StatusInternalServerError, "unavailable", "could not store the new password")
		return
	}
	s.clearFailures(key)
	// Rotate every session so a copied cookie cannot survive a password change.
	s.deleteAllSessions()
	token, fresh := s.newSession(rec.Username)
	if fresh == nil {
		webError(w, http.StatusInternalServerError, "unavailable", "could not create a session")
		return
	}
	s.setSessionCookie(w, r, token)
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"authenticated": true,
		"username":      fresh.username,
		"csrf":          fresh.csrf,
	})
}

func (s *webAPI) setupAllowed(r *http.Request, code string) bool {
	host := hostnameOf(r.RemoteAddr)
	loopback := false
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		loopback = true
	}
	if s.privileged {
		// A loopback source only proves "some local account", not authority.
		// The root-only setup code (or the API token) is required instead.
		if s.setupCode != "" && secureCompare(strings.TrimSpace(code), s.setupCode) {
			return true
		}
	} else if loopback {
		return true
	}
	if s.token != "" {
		auth := r.Header.Get("Authorization")
		if parts := strings.SplitN(auth, " ", 2); len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			return secureCompare(parts[1], s.token)
		}
		if secureCompare(r.Header.Get("X-API-Key"), s.token) {
			return true
		}
	}
	return false
}

func (s *webAPI) setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(sessionMaxAge.Seconds()),
		HttpOnly: true,
		Secure:   requestIsHTTPS(r),
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *webAPI) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   requestIsHTTPS(r),
		SameSite: http.SameSiteStrictMode,
	})
}

// --- helpers ---

func webError(w http.ResponseWriter, status int, code, message string) {
	jsonResponse(w, status, map[string]string{"code": code, "message": message})
}

func webRateLimited(w http.ResponseWriter, retry time.Duration) {
	seconds := int(retry.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	webError(w, http.StatusTooManyRequests, "rate_limited",
		fmt.Sprintf("too many failed attempts; retry in %d seconds", seconds))
}

func validAdminUsername(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '_', r == '-', r == '@':
		default:
			return false
		}
	}
	return true
}

func validPassword(password string) bool {
	return len(password) >= minPasswordLength && len(password) <= maxPasswordBytes
}

func isWriteMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

func requestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
}

func clientIP(r *http.Request) string {
	host := hostnameOf(r.RemoteAddr)
	if host == "" {
		return "unknown"
	}
	return host
}

func hostnameOf(hostport string) string {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = strings.Trim(hostport, "[]")
	}
	return strings.Trim(host, "[]")
}

func isAnyHost(host string) bool {
	host = strings.TrimSpace(host)
	return host == "0.0.0.0" || host == "::" || host == "[::]"
}
