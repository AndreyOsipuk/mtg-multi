package web

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Transport paths. This is our own contract with the bridge page, which we
// serve ourselves, so they can be changed freely: Telegram does not know them.
const (
	pathSession = "/api/v1/session"
	pathUp      = "/api/v1/up"
	pathDown    = "/api/v1/down"
	// Debug endpoint for marks from the bridge page. It is enabled only while
	// troubleshooting: the embedded Telegram webview has no developer tools,
	// and otherwise there is no way to tell at which step the page stalls.
	pathDiag = "/api/v1/diag"
)

// carrierContentType is the content type of a frame body. A strict check
// filters out stray requests before parsing.
const carrierContentType = "application/octet-stream"

// TokenHash is the key a session is addressed by in the table. We store the
// hash rather than the token itself: a memory dump or a log must not allow
// impersonating the client.
type TokenHash [sha256.Size]byte

// BridgeRenderer serves the bridge HTML page with an embedded token.
type BridgeRenderer interface {
	Render(host, bootstrapToken string) (body string, contentSecurityPolicy string)
}

// Decoy is what anyone without business here sees: a browser, a scanner, a
// DPI probe. To an observer we are an ordinary web server, and this is not
// decoration but the core of the camouflage: a distinguishable response to a
// "wrong" request gives the whole proxy away.
type Decoy interface {
	ServeHTTP(w http.ResponseWriter, r *http.Request)
}

// VHost is a single WEB mode domain with its own user table.
type VHost struct {
	Host     string
	Profiles *ProfileTable
	Decoy    Decoy
	// SecretMode is the key form in the links of this vhost; UpdateSecrets
	// derives the new capabilities with it.
	SecretMode SecretMode
}

// ServerConfig holds the HTTP frontend settings.
type ServerConfig struct {
	VHosts []VHost
	// TrustedProxyCIDRs lists where X-Forwarded-For is accepted from. Empty
	// means nowhere, and the connection address is used.
	TrustedProxyCIDRs []*net.IPNet
	// LongPollTimeout is how long /down is held without data.
	LongPollTimeout time.Duration
	// SessionTTL is how much silence makes a session considered abandoned.
	SessionTTL time.Duration
	// MaxBodyBytes caps the request body size.
	MaxBodyBytes int64
	// MaxSessions caps live sessions, MaxPending caps tokens issued by the
	// bridge but not used yet. Without them both tables would grow without
	// bound for anyone hitting the bridge page. When full, we answer with the
	// decoy, like an ordinary site.
	MaxSessions int
	MaxPending  int
	Session     SessionConfig
	Bridge      BridgeRenderer
	// Handle is called for every logical stream; this is Proxy.ServeConn.
	Handle func(*Stream)
	// Diag receives marks from the bridge page. nil disables it, and the
	// request goes to the decoy like any stray one.
	Diag func(clientIP, message string)
}

// DefaultServerConfig returns the default values.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		LongPollTimeout: 25 * time.Second,
		SessionTTL:      2 * time.Minute,
		MaxBodyBytes:    2 * 1024 * 1024,
		MaxSessions:     1024,
		MaxPending:      4096,
		Session:         DefaultSessionConfig(),
	}
}

// Server is the HTTP frontend of the WEB mode.
//
// It sits behind an external TLS terminator (nginx with a real certificate)
// and listens on localhost only; it does not terminate TLS itself. telemt does
// the same, and it greatly reduces the attack surface: certificates are
// handled by software built for that.
type Server struct {
	cfg    ServerConfig
	vhosts map[string]VHost

	mu       sync.Mutex
	sessions map[TokenHash]*Session
	// pending holds tokens issued by the bridge page for which no session has
	// been created yet. They belong to the server, not the package: two
	// frontends in one process must not see each other's tokens.
	pending map[TokenHash]pendingToken

	closeOnce sync.Once
	done      chan struct{}
}

// NewServer builds the frontend and starts collecting abandoned sessions.
func NewServer(cfg ServerConfig) *Server {
	vhosts := make(map[string]VHost, len(cfg.VHosts))
	for _, vhost := range cfg.VHosts {
		vhosts[strings.ToLower(vhost.Host)] = vhost
	}

	srv := &Server{
		cfg:      cfg,
		vhosts:   vhosts,
		sessions: make(map[TokenHash]*Session),
		pending:  make(map[TokenHash]pendingToken),
		done:     make(chan struct{}),
	}

	go srv.collectExpired()

	return srv
}

// UpdateSecrets rebuilds the user table of every vhost from a new secret set,
// so users added, removed or re-keyed at runtime (hot reload, management API)
// get or lose the bridge page without a restart. Live sessions are not
// touched here: their streams are authenticated by the proxy, which closes the
// streams of removed or re-keyed users itself. On error every table keeps its
// current users.
func (s *Server) UpdateSecrets(secrets map[string][]byte) error {
	if len(secrets) == 0 {
		return ErrNoSecrets
	}

	tables := make([]*ProfileTable, 0, len(s.vhosts))
	updates := make([][]Profile, 0, len(s.vhosts))

	for _, vhost := range s.vhosts {
		profiles, err := BuildProfiles(secrets, vhost.Host, vhost.SecretMode)
		if err != nil {
			return err
		}

		// Validate every table before swapping any of them.
		if _, err := NewProfileTable(profiles); err != nil {
			return err
		}

		tables = append(tables, vhost.Profiles)
		updates = append(updates, profiles)
	}

	for i, table := range tables {
		if err := table.Replace(updates[i]); err != nil {
			return err
		}
	}

	return nil
}

// Close terminates all sessions and stops the collector.
func (s *Server) Close() {
	s.closeOnce.Do(func() {
		close(s.done)

		s.mu.Lock()
		sessions := make([]*Session, 0, len(s.sessions))

		for _, session := range s.sessions {
			sessions = append(sessions, session)
		}

		s.sessions = make(map[TokenHash]*Session)
		s.pending = make(map[TokenHash]pendingToken)
		s.mu.Unlock()

		for _, session := range sessions {
			session.Close()
		}
	})
}

// SessionCount reports the number of live sessions.
func (s *Server) sessionsFull() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.cfg.MaxSessions > 0 && len(s.sessions) >= s.cfg.MaxSessions
}

func (s *Server) SessionCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.sessions)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	vhost, ok := s.matchVHost(r)
	if !ok {
		// Unknown Host: there is nothing to answer and no reason to.
		http.NotFound(w, r)

		return
	}

	switch r.URL.Path {
	case pathSession:
		s.handleSession(w, r, vhost)
	case pathUp:
		s.handleUp(w, r, vhost)
	case pathDown:
		s.handleDown(w, r, vhost)
	case pathDiag:
		s.handleDiag(w, r, vhost)
	case "/":
		s.handleRoot(w, r, vhost)
	default:
		vhost.serveDecoy(w, r)
	}
}

// matchVHost looks up the domain by the Host header.
//
// The only port allowed in Host is 443: the WEB link does not carry a port,
// the client always connects to 443, and any other value means it is not our
// client.
func (s *Server) matchVHost(r *http.Request) (VHost, bool) {
	host := strings.ToLower(r.Host)

	if idx := strings.LastIndex(host, ":"); idx != -1 && !strings.HasSuffix(host, "]") {
		if host[idx+1:] != "443" {
			return VHost{}, false
		}

		host = host[:idx]
	}

	vhost, ok := s.vhosts[host]

	return vhost, ok
}

func (v VHost) serveDecoy(w http.ResponseWriter, r *http.Request) {
	if v.Decoy == nil {
		http.NotFound(w, r)

		return
	}

	v.Decoy.ServeHTTP(w, r)
}

// handleRoot serves the bridge page if the request is canonical and the
// capability is known. In every other case it serves the decoy: an error
// instead of static content would tell a prober this is not just a website.
func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request, vhost VHost) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		vhost.serveDecoy(w, r)

		return
	}

	candidate, ok := ParseBridgeQuery(r.URL.RawQuery)
	if !ok {
		vhost.serveDecoy(w, r)

		return
	}

	profile, ok := vhost.Profiles.Match(candidate)
	if !ok {
		vhost.serveDecoy(w, r)

		return
	}

	token, err := newToken()
	if err != nil {
		vhost.serveDecoy(w, r)

		return
	}

	if !s.registerPending(tokenHash(token), profile, clientIP(r, s.cfg.TrustedProxyCIDRs)) {
		vhost.serveDecoy(w, r)

		return
	}

	body, csp := s.cfg.Bridge.Render(vhost.Host, encodeToken(token))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", csp)
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-DNS-Prefetch-Control", "off")
	w.Header().Set("Permissions-Policy", PermissionsPolicy)

	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)

		return
	}

	_, _ = io.WriteString(w, body)
}

// pendingToken is a profile that was issued a token but has no session yet.
type pendingToken struct {
	profile  Profile
	clientIP net.IP
	issued   time.Time
}

// registerPending stores an issued token. It returns false when the table is full.
func (s *Server) registerPending(hash TokenHash, profile Profile, ip net.IP) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cfg.MaxPending > 0 && len(s.pending) >= s.cfg.MaxPending {
		return false
	}

	s.pending[hash] = pendingToken{profile: profile, clientIP: ip, issued: time.Now()}

	return true
}

// takePending consumes an issued token exactly once: reusing the same bridge
// page must not bring up a second session.
func (s *Server) takePending(hash TokenHash) (pendingToken, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	issued, ok := s.pending[hash]
	if ok {
		delete(s.pending, hash)
	}

	return issued, ok
}

// handleSession creates a session from the first body carrying HELLO.
func (s *Server) handleSession(w http.ResponseWriter, r *http.Request, vhost VHost) {
	body, hash, ok := s.readCarrier(w, r, vhost)
	if !ok {
		return
	}

	if !ValidateHello(body, s.cfg.Session.Limits) {
		vhost.serveDecoy(w, r)

		return
	}

	if s.sessionsFull() {
		vhost.serveDecoy(w, r)

		return
	}

	issued, ok := s.takePending(hash)
	if !ok {
		vhost.serveDecoy(w, r)

		return
	}

	session := NewSession(Token(hash), issued.profile, issued.clientIP, s.cfg.Session, s.cfg.Handle)

	s.mu.Lock()
	if s.cfg.MaxSessions > 0 && len(s.sessions) >= s.cfg.MaxSessions {
		s.mu.Unlock()
		session.Close()
		vhost.serveDecoy(w, r)

		return
	}
	s.sessions[hash] = session
	s.mu.Unlock()

	// WELCOME has an EMPTY body. This frame goes straight to Telegram, which
	// expects it exactly like that: with a version byte inside, the client
	// gets something it does not expect and goes silent forever (verified
	// against a real client: the session was created, but not a single frame
	// followed). The asymmetry is intentional: the client's HELLO carries the
	// version, the reply does not.
	writeCarrier(w, Encode(FrameWelcome, 0, nil))
}

// handleUp receives client frames.
func (s *Server) handleUp(w http.ResponseWriter, r *http.Request, vhost VHost) {
	body, hash, ok := s.readCarrier(w, r, vhost)
	if !ok {
		return
	}

	session := s.lookup(hash)
	if session == nil {
		vhost.serveDecoy(w, r)

		return
	}

	if err := session.Accept(body); err != nil {
		// The client does not speak our protocol or exceeded the limits. Tear
		// the session down: continuing a stream whose sync is uncertain is worse.
		s.drop(hash)
		vhost.serveDecoy(w, r)

		return
	}

	writeCarrier(w, nil)
}

// handleDown returns queued frames, holding the request while the queue is empty.
func (s *Server) handleDown(w http.ResponseWriter, r *http.Request, vhost VHost) {
	_, hash, ok := s.readCarrier(w, r, vhost)
	if !ok {
		return
	}

	session := s.lookup(hash)
	if session == nil {
		vhost.serveDecoy(w, r)

		return
	}

	body, err := session.Drain(s.cfg.LongPollTimeout)
	if err != nil {
		s.drop(hash)
		vhost.serveDecoy(w, r)

		return
	}

	writeCarrier(w, body)
}

// handleDiag receives a short text message from the page.
func (s *Server) handleDiag(w http.ResponseWriter, r *http.Request, vhost VHost) {
	if s.cfg.Diag == nil || r.Method != http.MethodPost {
		vhost.serveDecoy(w, r)

		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2048))
	if err != nil {
		vhost.serveDecoy(w, r)

		return
	}

	s.cfg.Diag(clientIP(r, s.cfg.TrustedProxyCIDRs).String(), string(body))
	writeCarrier(w, nil)
}

// readCarrier validates the request shape and reads the body up to a cap.
func (s *Server) readCarrier(w http.ResponseWriter, r *http.Request, vhost VHost) ([]byte, TokenHash, bool) {
	var zero TokenHash

	if r.Method != http.MethodPost || !hasCarrierContentType(r) {
		vhost.serveDecoy(w, r)

		return nil, zero, false
	}

	hash, ok := bearerTokenHash(r)
	if !ok {
		vhost.serveDecoy(w, r)

		return nil, zero, false
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes))
	if err != nil {
		vhost.serveDecoy(w, r)

		return nil, zero, false
	}

	return body, hash, true
}

func writeCarrier(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", carrierContentType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)

	if len(body) > 0 {
		_, _ = w.Write(body)
	}
}

func (s *Server) lookup(hash TokenHash) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.sessions[hash]
}

func (s *Server) drop(hash TokenHash) {
	s.mu.Lock()
	session := s.sessions[hash]
	delete(s.sessions, hash)
	s.mu.Unlock()

	if session != nil {
		session.Close()
	}
}

// collectExpired removes sessions the client forgot about: Telegram may just
// quit, and BYE never reaches us.
func (s *Server) collectExpired() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			deadline := time.Now().Add(-s.cfg.SessionTTL)

			s.mu.Lock()
			expired := make([]*Session, 0)

			for hash, session := range s.sessions {
				if session.LastSeen().Before(deadline) {
					expired = append(expired, session)

					delete(s.sessions, hash)
				}
			}

			s.mu.Unlock()

			for _, session := range expired {
				session.Close()
			}

			// Tokens that never turned into a session are not kept either.
			s.mu.Lock()

			for hash, issued := range s.pending {
				if issued.issued.Before(deadline) {
					delete(s.pending, hash)
				}
			}

			s.mu.Unlock()
		}
	}
}

// ── helpers ─────────────────────────────────────────────────────────────────

func newToken() (Token, error) {
	var token Token

	_, err := rand.Read(token[:])

	return token, err
}

func encodeToken(token Token) string {
	return base64.RawURLEncoding.EncodeToString(token[:])
}

func tokenHash(token Token) TokenHash {
	return sha256.Sum256(token[:])
}

// bearerTokenHash parses the Authorization header in strictly canonical form.
func bearerTokenHash(r *http.Request) (TokenHash, bool) {
	var zero TokenHash

	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return zero, false
	}

	value := values[0]

	const prefix = "Bearer "
	if !strings.HasPrefix(value, prefix) {
		return zero, false
	}

	token := value[len(prefix):]
	if len(token) != 43 || strings.Contains(token, " ") {
		return zero, false
	}

	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(decoded) != sha256.Size {
		return zero, false
	}

	if base64.RawURLEncoding.EncodeToString(decoded) != token {
		return zero, false
	}

	return sha256.Sum256(decoded), true
}

// hasCarrierContentType requires the exact type without parameters.
func hasCarrierContentType(r *http.Request) bool {
	values := r.Header.Values("Content-Type")
	if len(values) != 1 {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(strings.TrimSpace(values[0])), []byte(carrierContentType)) == 1
}

// clientIP returns the client address: from X-Forwarded-For if the request
// came from a trusted proxy, otherwise the connection address.
func clientIP(r *http.Request, trusted []*net.IPNet) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	peer := net.ParseIP(host)

	if !isTrusted(peer, trusted) {
		return peer
	}

	values := r.Header.Values("X-Forwarded-For")
	if len(values) != 1 {
		return peer
	}

	value := strings.TrimSpace(values[0])
	if value == "" || strings.Contains(value, ",") {
		// A proxy chain means someone else sits between us and the client, so
		// the first address cannot be trusted.
		return peer
	}

	if forwarded := net.ParseIP(value); forwarded != nil {
		return forwarded
	}

	return peer
}

func isTrusted(ip net.IP, trusted []*net.IPNet) bool {
	if ip == nil {
		return false
	}

	for _, network := range trusted {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}
