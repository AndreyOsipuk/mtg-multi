package web

import (
	"errors"
	"net"
	"os"
	"sync"
	"time"
)

// Session is a single WEB session: a user, their logical streams and the
// queue of frames waiting to be sent to the client.
//
// The client talks to us with plain HTTP requests: it posts its frames to /up
// and fetches ours from /down. The session keeps state between these requests,
// which is what sets it apart from a regular socket, where the kernel keeps the
// state.
type Session struct {
	token    Token
	profile  Profile
	clientIP net.IP
	limits   Limits

	// handle is called for every new stream. It is Proxy.ServeConn, i.e. the
	// whole regular mtg path; the session knows nothing about MTProto.
	handle func(*Stream)

	mu      sync.Mutex
	streams map[uint32]*Stream
	// credit is how many bytes we may still send to the client on each stream.
	credit map[uint32]uint32
	// outbound holds frames waiting for the next /down.
	outbound [][]byte
	// outboundBytes is the queue size. It is capped, otherwise a client stuck
	// on /down would bloat the server memory.
	outboundBytes int
	closed        bool

	// notify wakes both a waiting /down and writes that are short of credit.
	notify chan struct{}

	lastSeen time.Time

	maxStreams        int
	maxOutboundBytes  int
	streamBufferBytes int
}

// Token is the session ID the client carries in the Authorization header.
type Token [32]byte

// Session-level errors.
var (
	// ErrSessionClosed means the session has already ended.
	ErrSessionClosed = errors.New("web: session is closed")
	// ErrTooManyStreams means the session has more streams than allowed.
	ErrTooManyStreams = errors.New("web: too many streams in session")
	// ErrOutboundFull means the outbound queue is full.
	ErrOutboundFull = errors.New("web: outbound queue is full")
	// ErrUnknownStream means a frame is addressed to a nonexistent stream.
	ErrUnknownStream = errors.New("web: frame for unknown stream")
)

// SessionConfig holds the limits of a single session.
type SessionConfig struct {
	// MaxStreams caps concurrent logical streams.
	MaxStreams int
	// MaxOutboundBytes caps the outbound queue.
	MaxOutboundBytes int
	// StreamBufferBytes is the inbound data buffer per stream.
	StreamBufferBytes int
	Limits            Limits
}

// DefaultSessionConfig returns the default values.
func DefaultSessionConfig() SessionConfig {
	return SessionConfig{
		MaxStreams:        64,
		MaxOutboundBytes:  8 * 1024 * 1024,
		StreamBufferBytes: 1024 * 1024,
		Limits:            DefaultLimits(),
	}
}

// NewSession creates a session. handle is called in a separate goroutine for
// every stream the client opens.
func NewSession(token Token, profile Profile, clientIP net.IP, cfg SessionConfig, handle func(*Stream)) *Session {
	return &Session{
		token:             token,
		profile:           profile,
		clientIP:          clientIP,
		limits:            cfg.Limits,
		handle:            handle,
		streams:           make(map[uint32]*Stream),
		credit:            make(map[uint32]uint32),
		notify:            make(chan struct{}, 1),
		lastSeen:          time.Now(),
		maxStreams:        cfg.MaxStreams,
		maxOutboundBytes:  cfg.MaxOutboundBytes,
		streamBufferBytes: cfg.StreamBufferBytes,
	}
}

// Token returns the session ID.
func (s *Session) Token() Token { return s.token }

// User returns the user name (also the mtg stats key).
func (s *Session) User() string { return s.profile.User }

// LastSeen reports the time of the last activity. It is used to clean up
// abandoned sessions: the client may just quit Telegram without notice.
func (s *Session) LastSeen() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.lastSeen
}

func (s *Session) touch() {
	s.lastSeen = time.Now()
}

func (s *Session) wake() {
	select {
	case s.notify <- struct{}{}:
	default:
	}
}

// Accept parses a /up request body and applies the client frames.
//
// Any error means the client does not speak our protocol. In that case the
// whole session is closed: continuing to parse a stream whose sync we are not
// sure about is more dangerous than dropping it.
func (s *Session) Accept(body []byte) error {
	frames, err := ParseAll(body, s.limits)
	if err != nil {
		return err
	}

	for _, frame := range frames {
		if err := ValidateClientShape(frame); err != nil {
			return err
		}
	}

	s.mu.Lock()

	if s.closed {
		s.mu.Unlock()

		return ErrSessionClosed
	}

	s.touch()
	s.mu.Unlock()

	for _, frame := range frames {
		if err := s.applyFrame(frame); err != nil {
			return err
		}
	}

	return nil
}

func (s *Session) applyFrame(frame Frame) error {
	switch frame.Type {
	case FrameOpen:
		return s.openStream(frame.StreamID)
	case FrameData:
		return s.deliverData(frame.StreamID, frame.Payload)
	case FrameClose:
		s.closeStream(frame.StreamID)

		return nil
	case FrameWindow:
		amount, err := WindowAmount(frame.Payload)
		if err != nil {
			return err
		}

		s.addCredit(frame.StreamID, amount)

		return nil
	case FramePong:
		return nil // liveness signal, state already updated in Accept
	case FramePing, FrameHello, FrameWelcome, FrameBye:
		// These frames never arrive on /up: HELLO is handled at session
		// creation, and the rest are server-only.
		return ErrInvalidShape
	default:
		return ErrInvalidShape
	}
}

func (s *Session) openStream(id uint32) error {
	s.mu.Lock()

	if s.closed {
		s.mu.Unlock()

		return ErrSessionClosed
	}

	if _, exists := s.streams[id]; exists {
		s.mu.Unlock()

		// A repeated OPEN on a live stream means the state is out of sync, and
		// the numbering can no longer be trusted.
		return ErrInvalidShape
	}

	if len(s.streams) >= s.maxStreams {
		s.mu.Unlock()

		return ErrTooManyStreams
	}

	stream := newStream(id, s, s.clientIP, s.streamBufferBytes)
	s.streams[id] = stream
	s.credit[id] = InitialStreamWindow
	s.mu.Unlock()

	go s.handle(stream)

	return nil
}

func (s *Session) deliverData(id uint32, payload []byte) error {
	s.mu.Lock()
	stream := s.streams[id]
	s.mu.Unlock()

	if stream == nil {
		return ErrUnknownStream
	}

	return stream.deliver(payload)
}

func (s *Session) closeStream(id uint32) {
	s.mu.Lock()
	stream := s.streams[id]
	s.mu.Unlock()

	if stream != nil {
		stream.finish(nil)
	}
}

func (s *Session) addCredit(id uint32, amount uint32) {
	s.mu.Lock()

	if _, ok := s.credit[id]; ok {
		// Saturate rather than overflow: the client controls this number.
		if s.credit[id] > ^uint32(0)-amount {
			s.credit[id] = ^uint32(0)
		} else {
			s.credit[id] += amount
		}
	}

	s.mu.Unlock()
	s.wake()
}

// ── streamSink ──────────────────────────────────────────────────────────────

// sendData queues data, waiting for window credit.
func (s *Session) sendData(streamID uint32, payload []byte, deadline time.Time) error {
	remaining := payload

	for len(remaining) > 0 {
		allowed, err := s.reserveCredit(streamID, len(remaining), deadline)
		if err != nil {
			return err
		}

		chunk := remaining[:allowed]
		remaining = remaining[allowed:]

		if err := s.enqueue(Encode(FrameData, streamID, chunk)); err != nil {
			return err
		}
	}

	return nil
}

// reserveCredit takes the available credit, waiting for it until the deadline.
func (s *Session) reserveCredit(streamID uint32, want int, deadline time.Time) (int, error) {
	for {
		s.mu.Lock()

		if s.closed {
			s.mu.Unlock()

			return 0, ErrSessionClosed
		}

		available, ok := s.credit[streamID]
		if !ok {
			s.mu.Unlock()

			return 0, ErrUnknownStream
		}

		if available > 0 {
			allowed := min(want, int(available))
			s.credit[streamID] = available - uint32(allowed)
			s.mu.Unlock()

			return allowed, nil
		}

		s.mu.Unlock()

		if err := s.waitNotify(deadline); err != nil {
			return 0, err
		}
	}
}

func (s *Session) waitNotify(deadline time.Time) error {
	if deadline.IsZero() {
		<-s.notify

		return nil
	}

	remaining := time.Until(deadline)
	if remaining <= 0 {
		return os.ErrDeadlineExceeded
	}

	timer := time.NewTimer(remaining)
	defer timer.Stop()

	select {
	case <-s.notify:
		return nil
	case <-timer.C:
		return os.ErrDeadlineExceeded
	}
}

func (s *Session) enqueue(frame []byte) error {
	s.mu.Lock()

	if s.closed {
		s.mu.Unlock()

		return ErrSessionClosed
	}

	if s.outboundBytes+len(frame) > s.maxOutboundBytes {
		s.mu.Unlock()

		// The client is not fetching responses. Buffering more would hand memory
		// to someone who stopped reading; dropping the session is more honest.
		return ErrOutboundFull
	}

	s.outbound = append(s.outbound, frame)
	s.outboundBytes += len(frame)
	s.mu.Unlock()
	s.wake()

	return nil
}

func (s *Session) sendClose(streamID uint32) {
	_ = s.enqueue(Encode(FrameClose, streamID, nil))
}

func (s *Session) returnWindow(streamID uint32, amount uint32) {
	_ = s.enqueue(Encode(FrameWindow, streamID, WindowPayload(amount)))
}

func (s *Session) dropStream(streamID uint32) {
	s.mu.Lock()
	delete(s.streams, streamID)
	delete(s.credit, streamID)
	s.mu.Unlock()
}

// ── delivery to the client ──────────────────────────────────────────────────

// Drain takes the queued frames. If the queue is empty, it waits until wait
// elapses. This is the long poll: without it the client would hammer the
// server for nothing.
func (s *Session) Drain(wait time.Duration) ([]byte, error) {
	deadline := time.Now().Add(wait)

	for {
		s.mu.Lock()

		if s.closed {
			s.mu.Unlock()

			return nil, ErrSessionClosed
		}

		s.touch()

		if len(s.outbound) > 0 {
			body := make([]byte, 0, s.outboundBytes)
			for _, frame := range s.outbound {
				body = append(body, frame...)
			}

			s.outbound = s.outbound[:0]
			s.outboundBytes = 0
			s.mu.Unlock()

			return body, nil
		}

		s.mu.Unlock()

		if err := s.waitNotify(deadline); err != nil {
			// A long poll deadline is normal, not an error: return empty.
			return nil, nil
		}
	}
}

// Close ends the session and all its streams.
func (s *Session) Close() {
	s.mu.Lock()

	if s.closed {
		s.mu.Unlock()

		return
	}

	s.closed = true
	streams := make([]*Stream, 0, len(s.streams))

	for _, stream := range s.streams {
		streams = append(streams, stream)
	}

	s.outbound = nil
	s.outboundBytes = 0
	s.mu.Unlock()

	for _, stream := range streams {
		stream.finish(ErrSessionClosed)
		_ = stream.CloseRead()
	}

	s.wake()
}

// StreamCount reports the number of live streams.
func (s *Session) StreamCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.streams)
}
