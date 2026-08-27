package mtglib

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type secretStats struct {
	connections atomic.Int64
	bytesIn     atomic.Int64
	bytesOut    atomic.Int64
	lastSeen    atomic.Value // stores time.Time

	ipsMu sync.Mutex
	ips   map[string]int
}

// RejectReason classifies why an incoming connection never became a proxied
// session. Successful sessions are visible per user, but until these counters
// existed a client that could not complete the handshake was invisible in
// /stats: operators had to run tcpdump to notice, for example, a truncated
// FakeTLS ClientHello (Telegram Desktop behind a censoring ISP, 18.08.2026).
type RejectReason string

const (
	// RejectInitialBytes - could not even read the first 5 bytes.
	RejectInitialBytes RejectReason = "initial_bytes"
	// RejectSecuredHandshake - looked like dd, but the handshake failed.
	RejectSecuredHandshake RejectReason = "secured_handshake"
	// RejectClientHello - FakeTLS ClientHello unreadable/unmatched (truncated
	// hello or wrong secret both land here).
	RejectClientHello RejectReason = "client_hello"
	// RejectReplay - anti-replay cache hit.
	RejectReplay RejectReason = "replay"
	// RejectWelcome - could not send the welcome packet back.
	RejectWelcome RejectReason = "welcome"
)

// AllRejectReasons lists every reason in a stable order so the JSON response
// always carries the same keys (zeros included) - graphs stay comparable.
var AllRejectReasons = []RejectReason{
	RejectInitialBytes,
	RejectSecuredHandshake,
	RejectClientHello,
	RejectReplay,
	RejectWelcome,
}

// ProxyStats tracks per-secret connection stats with atomic counters.
// Thread-safe for concurrent access from proxy goroutines.
type ProxyStats struct {
	mu        sync.RWMutex
	users     map[string]*secretStats
	startedAt time.Time

	// Rejected handshakes by reason (see RejectReason). Not per-user: at the
	// point of rejection the secret - hence the user - is usually unknown.
	rejectedMu sync.Mutex
	rejected   map[RejectReason]*atomic.Int64

	// Throttle: per-user connection caps recomputed every throttleInterval.
	throttleMu       sync.RWMutex
	throttleCaps     map[string]int64
	throttleLimit    int64
	throttleInterval time.Duration
	throttleActive   atomic.Bool
}

// NewProxyStats creates a new ProxyStats instance.
func NewProxyStats() *ProxyStats {
	rejected := make(map[RejectReason]*atomic.Int64, len(AllRejectReasons))
	for _, reason := range AllRejectReasons {
		rejected[reason] = &atomic.Int64{}
	}

	return &ProxyStats{
		users:     make(map[string]*secretStats),
		startedAt: time.Now(),
		rejected:  rejected,
	}
}

func (s *ProxyStats) getOrCreate(name string) *secretStats {
	s.mu.RLock()
	st, ok := s.users[name]
	s.mu.RUnlock()

	if ok {
		return st
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if st, ok = s.users[name]; ok {
		return st
	}

	st = &secretStats{}
	st.lastSeen.Store(time.Time{})
	s.users[name] = st

	return st
}

// PreRegister adds a secret name to the stats map so it appears in output
// even if no connections have been made yet.
// OnReject records a connection that was turned away before becoming a session.
// Unknown reasons are counted too, so a future call site cannot silently vanish.
func (s *ProxyStats) OnReject(reason RejectReason) {
	if counter := s.rejectedCounter(reason); counter != nil {
		counter.Add(1)
	}
}

func (s *ProxyStats) rejectedCounter(reason RejectReason) *atomic.Int64 {
	s.rejectedMu.Lock()
	defer s.rejectedMu.Unlock()

	if s.rejected == nil {
		s.rejected = make(map[RejectReason]*atomic.Int64, len(AllRejectReasons))
	}

	counter, ok := s.rejected[reason]
	if !ok {
		counter = &atomic.Int64{}
		s.rejected[reason] = counter
	}

	return counter
}

// RejectedSnapshot returns the current per-reason counters.
func (s *ProxyStats) RejectedSnapshot() map[string]int64 {
	s.rejectedMu.Lock()
	defer s.rejectedMu.Unlock()

	out := make(map[string]int64, len(s.rejected))
	for reason, counter := range s.rejected {
		out[string(reason)] = counter.Load()
	}

	return out
}

func (s *ProxyStats) PreRegister(name string) {
	s.getOrCreate(name)
}

// OnConnect increments the active connection count for the given secret.
func (s *ProxyStats) OnConnect(name string) {
	s.getOrCreate(name).connections.Add(1)
}

// OnDisconnect decrements the active connection count for the given secret.
func (s *ProxyStats) OnDisconnect(name string) {
	s.getOrCreate(name).connections.Add(-1)
}

// OnConnectIP registers an active client IP for a secret.
func (s *ProxyStats) OnConnectIP(name, ip string) {
	if ip == "" {
		return
	}

	st := s.getOrCreate(name)
	st.ipsMu.Lock()
	defer st.ipsMu.Unlock()

	if st.ips == nil {
		st.ips = make(map[string]int)
	}
	st.ips[ip]++
}

// OnDisconnectIP unregisters an active client IP for a secret.
func (s *ProxyStats) OnDisconnectIP(name, ip string) {
	if ip == "" {
		return
	}

	st := s.getOrCreate(name)
	st.ipsMu.Lock()
	defer st.ipsMu.Unlock()

	if st.ips[ip] <= 1 {
		delete(st.ips, ip)
		return
	}
	st.ips[ip]--
}

// AddBytesIn adds to the bytes-in counter for the given secret.
func (s *ProxyStats) AddBytesIn(name string, n int64) {
	s.getOrCreate(name).bytesIn.Add(n)
}

// AddBytesOut adds to the bytes-out counter for the given secret.
func (s *ProxyStats) AddBytesOut(name string, n int64) {
	s.getOrCreate(name).bytesOut.Add(n)
}

// UpdateLastSeen sets the last-seen timestamp for the given secret to now.
func (s *ProxyStats) UpdateLastSeen(name string) {
	s.getOrCreate(name).lastSeen.Store(time.Now())
}

// SetThrottle configures connection throttling. Must be called before
// startThrottleLoop and before any connections arrive.
func (s *ProxyStats) SetThrottle(limit int64, interval time.Duration) {
	s.throttleLimit = limit
	s.throttleInterval = interval
	s.throttleCaps = make(map[string]int64)
}

// CanConnect returns true if the user is allowed to open a new connection
// under the current throttle caps. If throttling is not configured or the
// user has no cap, it always returns true.
func (s *ProxyStats) CanConnect(name string) bool {
	if s.throttleLimit == 0 {
		return true
	}

	s.throttleMu.RLock()
	cap, hasCap := s.throttleCaps[name]
	s.throttleMu.RUnlock()

	if !hasCap {
		return true
	}

	return s.getOrCreate(name).connections.Load() < cap
}

// startThrottleLoop runs a background goroutine that recomputes per-user
// caps every throttleInterval.
func (s *ProxyStats) startThrottleLoop(ctx context.Context, logger Logger) {
	go func() {
		ticker := time.NewTicker(s.throttleInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.recomputeCaps(logger)
			}
		}
	}()

	logger.BindStr("limit", fmt.Sprintf("%d", s.throttleLimit)).
		BindStr("interval", s.throttleInterval.String()).
		Info("throttle loop started")
}

func (s *ProxyStats) recomputeCaps(logger Logger) {
	s.mu.RLock()
	userConns := make(map[string]int64, len(s.users))
	for name, st := range s.users {
		userConns[name] = st.connections.Load()
	}
	s.mu.RUnlock()

	caps := computeFairCaps(userConns, s.throttleLimit)
	wasActive := s.throttleActive.Load()
	nowActive := len(caps) > 0

	s.throttleMu.Lock()
	s.throttleCaps = caps
	s.throttleActive.Store(nowActive)
	s.throttleMu.Unlock()

	if nowActive && !wasActive {
		logger.Warning("throttle activated")
	} else if !nowActive && wasActive {
		logger.Info("throttle deactivated")
	}
}

// computeFairCaps implements the fair-share algorithm. Users below the equal
// share keep their connections; remaining budget is split equally among the
// rest. Returns nil when no throttling is needed.
func computeFairCaps(userConns map[string]int64, limit int64) map[string]int64 {
	var total int64
	for _, c := range userConns {
		total += c
	}

	if total <= limit {
		return nil
	}

	remaining := make(map[string]int64, len(userConns))
	for k, v := range userConns {
		remaining[k] = v
	}

	budget := limit
	caps := make(map[string]int64)

	for len(remaining) > 0 {
		fairShare := budget / int64(len(remaining))
		changed := false

		for name, conns := range remaining {
			if conns <= fairShare {
				budget -= conns
				delete(remaining, name)
				changed = true
			}
		}

		if !changed {
			for name := range remaining {
				caps[name] = fairShare
			}

			break
		}
	}

	return caps
}

// StatsResponse is the JSON response for the stats endpoint.
type StatsResponse struct {
	StartedAt        time.Time                `json:"started_at"`
	UptimeSeconds    int64                    `json:"uptime_seconds"`
	TotalConnections int64                    `json:"total_connections"`
	// Rejected counts handshakes that never became sessions, by reason.
	Rejected map[string]int64         `json:"rejected"`
	Throttle *ThrottleJSON            `json:"throttle,omitempty"`
	Users    map[string]UserStatsJSON `json:"users"`
}

// ThrottleJSON is the throttle portion of the stats JSON response.
type ThrottleJSON struct {
	Active bool             `json:"active"`
	Limit  int64            `json:"limit"`
	Caps   map[string]int64 `json:"caps,omitempty"`
}

// UserStatsJSON is the per-user portion of the stats JSON response.
type UserStatsJSON struct {
	Connections int64      `json:"connections"`
	BytesIn     int64      `json:"bytes_in"`
	BytesOut    int64      `json:"bytes_out"`
	LastSeen    *time.Time `json:"last_seen"`
	ActiveIPs   []string   `json:"active_ips"`
}

func (s *ProxyStats) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var totalConns int64

	users := make(map[string]UserStatsJSON, len(s.users))

	for name, st := range s.users {
		conns := st.connections.Load()
		totalConns += conns

		lastSeen := st.lastSeen.Load().(time.Time) //nolint: forcetypeassert
		var lastSeenPtr *time.Time
		if !lastSeen.IsZero() {
			lastSeenPtr = &lastSeen
		}

		st.ipsMu.Lock()
		activeIPs := make([]string, 0, len(st.ips))
		for ip := range st.ips {
			activeIPs = append(activeIPs, ip)
		}
		st.ipsMu.Unlock()
		sort.Strings(activeIPs)

		users[name] = UserStatsJSON{
			Connections: conns,
			BytesIn:     st.bytesIn.Load(),
			BytesOut:    st.bytesOut.Load(),
			LastSeen:    lastSeenPtr,
			ActiveIPs:   activeIPs,
		}
	}

	var throttle *ThrottleJSON
	if s.throttleLimit > 0 {
		s.throttleMu.RLock()
		active := s.throttleActive.Load()

		var capsCopy map[string]int64
		if len(s.throttleCaps) > 0 {
			capsCopy = make(map[string]int64, len(s.throttleCaps))
			for k, v := range s.throttleCaps {
				capsCopy[k] = v
			}
		}

		s.throttleMu.RUnlock()

		throttle = &ThrottleJSON{
			Active: active,
			Limit:  s.throttleLimit,
			Caps:   capsCopy,
		}
	}

	resp := StatsResponse{
		StartedAt:        s.startedAt,
		UptimeSeconds:    int64(time.Since(s.startedAt).Seconds()),
		TotalConnections: totalConns,
		Throttle:         throttle,
		Users:            users,
	}

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// StartServer starts an HTTP server for the stats API in a background goroutine.
// The server is shut down when ctx is cancelled.
func (s *ProxyStats) StartServer(ctx context.Context, bindTo string, logger Logger) {
	mux := http.NewServeMux()
	mux.Handle("/stats", s)

	srv := &http.Server{
		Addr:    bindTo,
		Handler: mux,
	}

	ln, err := net.Listen("tcp", bindTo)
	if err != nil {
		logger.WarningError("cannot start stats API listener", err)
		return
	}

	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			logger.WarningError("stats API server error", err)
		}
	}()

	go func() {
		<-ctx.Done()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second) //nolint: mnd
		defer cancel()

		srv.Shutdown(shutdownCtx) //nolint: errcheck
	}()

	logger.BindStr("bind", bindTo).Info("Stats API server started")
}
