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

// Пути транспорта. Это наш собственный договор со страницей-мостом, которую мы
// же и раздаём, поэтому менять их можно свободно - Telegram о них не знает.
const (
	pathSession = "/api/v1/session"
	pathUp      = "/api/v1/up"
	pathDown    = "/api/v1/down"
	// Отладочный приём отметок от страницы-моста. Включается только на время
	// разбора: во встроенном вебвью Telegram нет инструментов разработчика, и
	// иначе непонятно, на каком шаге страница встаёт.
	pathDiag = "/api/v1/diag"
)

// carrierContentType - тип тела с кадрами. Строгая проверка отсекает случайные
// запросы ещё до разбора.
const carrierContentType = "application/octet-stream"

// TokenHash - то, чем сессия адресуется в таблице. Храним хеш, а не сам токен:
// дамп памяти или лог не должны давать возможность выдать себя за клиента.
type TokenHash [sha256.Size]byte

// BridgeRenderer отдаёт HTML-страницу моста с вшитым токеном.
type BridgeRenderer interface {
	Render(host, bootstrapToken string) (body string, contentSecurityPolicy string)
}

// Decoy - то, что видит любой, кто пришёл не по делу: браузер, сканер, проба
// DPI. Для наблюдателя мы обычный веб-сервер, и это не украшение, а основа
// маскировки: отличимый ответ на «неправильный» запрос выдаёт прокси целиком.
type Decoy interface {
	ServeHTTP(w http.ResponseWriter, r *http.Request)
}

// VHost - один домен WEB-режима со своей таблицей пользователей.
type VHost struct {
	Host     string
	Profiles *ProfileTable
	Decoy    Decoy
}

// ServerConfig - настройки HTTP-входа.
type ServerConfig struct {
	VHosts []VHost
	// TrustedProxyCIDRs - откуда принимаем X-Forwarded-For. Пусто = ниоткуда,
	// тогда берётся адрес соединения.
	TrustedProxyCIDRs []*net.IPNet
	// LongPollTimeout - сколько держим /down без данных.
	LongPollTimeout time.Duration
	// SessionTTL - через сколько молчания сессия считается брошенной.
	SessionTTL time.Duration
	// MaxBodyBytes - потолок тела запроса.
	MaxBodyBytes int64
	Session      SessionConfig
	Bridge       BridgeRenderer
	// Handle вызывается на каждый логический поток: это Proxy.ServeConn.
	Handle func(*Stream)
	// Diag принимает отметки от страницы-моста. nil = приём выключен, и
	// запрос уходит в заглушку, как любой посторонний.
	Diag func(clientIP, message string)
}

// DefaultServerConfig - значения по умолчанию.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		LongPollTimeout: 25 * time.Second,
		SessionTTL:      2 * time.Minute,
		MaxBodyBytes:    2 * 1024 * 1024,
		Session:         DefaultSessionConfig(),
	}
}

// Server - HTTP-вход WEB-режима.
//
// Стоит за внешним терминатором TLS (nginx с настоящим сертификатом) и слушает
// только на localhost: сам TLS не терминирует. Так сделано и в telemt, и это
// сильно сокращает поверхность - сертификатами занимается то, что умеет.
type Server struct {
	cfg    ServerConfig
	vhosts map[string]VHost

	mu       sync.Mutex
	sessions map[TokenHash]*Session
	// pending - токены, выданные страницей-мостом, по которым сессия ещё не
	// создана. Принадлежат серверу, а не пакету: два входа в одном процессе не
	// должны видеть чужие токены.
	pending map[TokenHash]pendingToken

	closeOnce sync.Once
	done      chan struct{}
}

// NewServer собирает вход и запускает уборку брошенных сессий.
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

// Close завершает все сессии и останавливает уборку.
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

// SessionCount сообщает число живых сессий.
func (s *Server) SessionCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.sessions)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	vhost, ok := s.matchVHost(r)
	if !ok {
		// Чужой Host: отвечать нечем и незачем.
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

// matchVHost ищет домен по заголовку Host.
//
// Порт в Host допускается только 443: ссылка WEB его не несёт, клиент всегда
// идёт на 443, и любое другое значение означает не нашего клиента.
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

// handleRoot отдаёт страницу-мост, если запрос канонический и capability
// известен. Во всех остальных случаях - заглушка: ошибка вместо статики
// сообщила бы пробующему, что тут не просто сайт.
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

	body, csp := s.cfg.Bridge.Render(vhost.Host, encodeToken(token))

	s.registerPending(tokenHash(token), profile, clientIP(r, s.cfg.TrustedProxyCIDRs))

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

// pendingToken - профиль, которому выдан токен, но сессия ещё не создана.
type pendingToken struct {
	profile  Profile
	clientIP net.IP
	issued   time.Time
}

func (s *Server) registerPending(hash TokenHash, profile Profile, ip net.IP) {
	s.mu.Lock()
	s.pending[hash] = pendingToken{profile: profile, clientIP: ip, issued: time.Now()}
	s.mu.Unlock()
}

// takePending забирает выданный токен ровно один раз: повторное использование
// той же страницы-моста не должно поднимать вторую сессию.
func (s *Server) takePending(hash TokenHash) (pendingToken, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	issued, ok := s.pending[hash]
	if ok {
		delete(s.pending, hash)
	}

	return issued, ok
}

// handleSession создаёт сессию по первому телу с HELLO.
func (s *Server) handleSession(w http.ResponseWriter, r *http.Request, vhost VHost) {
	body, hash, ok := s.readCarrier(w, r, vhost)
	if !ok {
		return
	}

	if !ValidateHello(body, s.cfg.Session.Limits) {
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
	s.sessions[hash] = session
	s.mu.Unlock()

	// WELCOME - с ПУСТЫМ телом. Этот кадр уходит прямо в Telegram, и он ждёт
	// его именно таким: с байтом версии внутри клиент получает не то, что
	// ожидает, и замолкает навсегда (проверено на живом клиенте 20.09.2026 -
	// сессия создавалась, а дальше ни одного кадра). Асимметрия намеренная:
	// в HELLO от клиента версия есть, в ответе её нет.
	writeCarrier(w, Encode(FrameWelcome, 0, nil))
}

// handleUp принимает кадры клиента.
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
		// Клиент говорит не на нашем языке или вышел за границы. Сессию рвём:
		// продолжать поток, в синхронизации которого нет уверенности, хуже.
		s.drop(hash)
		vhost.serveDecoy(w, r)

		return
	}

	writeCarrier(w, nil)
}

// handleDown отдаёт накопленные кадры, придерживая запрос при пустой очереди.
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

// handleDiag принимает короткое текстовое сообщение от страницы.
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

// readCarrier проверяет форму запроса и читает тело с потолком.
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

// collectExpired убирает сессии, о которых клиент забыл: Telegram может просто
// закрыться, и BYE до нас не дойдёт.
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

			// Токены, по которым сессию так и не создали, тоже не копим.
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

// ── вспомогательное ─────────────────────────────────────────────────────────

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

// bearerTokenHash разбирает заголовок Authorization в строго каноническом виде.
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

// hasCarrierContentType требует точный тип без параметров.
func hasCarrierContentType(r *http.Request) bool {
	values := r.Header.Values("Content-Type")
	if len(values) != 1 {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(strings.TrimSpace(values[0])), []byte(carrierContentType)) == 1
}

// clientIP берёт адрес клиента: из X-Forwarded-For, если запрос пришёл от
// доверенного прокси, иначе - адрес соединения.
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
		// Цепочка прокси означает, что между нами и клиентом есть кто-то ещё,
		// и первому адресу доверять нельзя.
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
