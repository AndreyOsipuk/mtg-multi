package web

import (
	"errors"
	"net"
	"os"
	"sync"
	"time"
)

// Session - одна WEB-сессия: пользователь, его логические потоки и очередь
// кадров, которые ждут отправки клиенту.
//
// Клиент ходит к нам обычными HTTP-запросами: в /up приносит свои кадры, на
// /down забирает наши. Сессия держит состояние между этими запросами - тем она
// и отличается от обычного сокета, где состояние держит ядро.
type Session struct {
	token    Token
	profile  Profile
	clientIP net.IP
	limits   Limits

	// handle вызывается на каждый новый поток. Это Proxy.ServeConn, то есть
	// весь обычный путь mtg; сессия про MTProto ничего не знает.
	handle func(*Stream)

	mu      sync.Mutex
	streams map[uint32]*Stream
	// credit - сколько байт мы ещё вправе отправить клиенту по каждому потоку.
	credit map[uint32]uint32
	// outbound - кадры, ожидающие ближайшего /down.
	outbound [][]byte
	// outboundBytes - объём очереди: держим потолок, иначе зависший на /down
	// клиент раздул бы память сервера.
	outboundBytes int
	closed        bool

	// notify будит и ожидающий /down, и записи, которым не хватает кредита.
	notify chan struct{}

	lastSeen time.Time

	maxStreams        int
	maxOutboundBytes  int
	streamBufferBytes int
}

// Token - идентификатор сессии, который клиент носит в заголовке Authorization.
type Token [32]byte

// Ошибки уровня сессии.
var (
	// ErrSessionClosed - сессия уже завершена.
	ErrSessionClosed = errors.New("web: сессия закрыта")
	// ErrTooManyStreams - у сессии больше потоков, чем разрешено.
	ErrTooManyStreams = errors.New("web: слишком много потоков в сессии")
	// ErrOutboundFull - очередь ответов переполнена.
	ErrOutboundFull = errors.New("web: очередь ответов переполнена")
	// ErrUnknownStream - кадр адресован несуществующему потоку.
	ErrUnknownStream = errors.New("web: кадр для неизвестного потока")
)

// SessionConfig - границы одной сессии.
type SessionConfig struct {
	// MaxStreams - потолок одновременных логических потоков.
	MaxStreams int
	// MaxOutboundBytes - потолок очереди ответов.
	MaxOutboundBytes int
	// StreamBufferBytes - буфер входящих данных на один поток.
	StreamBufferBytes int
	Limits            Limits
}

// DefaultSessionConfig - значения по умолчанию.
func DefaultSessionConfig() SessionConfig {
	return SessionConfig{
		MaxStreams:        64,
		MaxOutboundBytes:  8 * 1024 * 1024,
		StreamBufferBytes: 1024 * 1024,
		Limits:            DefaultLimits(),
	}
}

// NewSession создаёт сессию. handle вызывается в отдельной горутине на каждый
// открытый клиентом поток.
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

// Token возвращает идентификатор сессии.
func (s *Session) Token() Token { return s.token }

// User возвращает имя пользователя (оно же ключ статистики mtg).
func (s *Session) User() string { return s.profile.User }

// LastSeen сообщает время последней активности - по нему чистим брошенные
// сессии: клиент может просто закрыть Telegram, никого не предупредив.
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

// Accept разбирает тело запроса /up и применяет кадры клиента.
//
// Любая ошибка означает, что клиент говорит не на нашем языке. Сессию в этом
// случае закрываем целиком: продолжать разбирать поток, в синхронизации
// которого мы не уверены, опаснее, чем оборвать.
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
		return nil // признак жизни, состояние уже обновлено в Accept
	case FramePing, FrameHello, FrameWelcome, FrameBye:
		// Эти кадры в /up не приходят: HELLO обрабатывается при создании
		// сессии, остальные - только от сервера.
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

		// Повтор OPEN на живом потоке - рассинхрон состояния, дальше доверять
		// нумерации нельзя.
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
		// Насыщаем, а не переполняем: клиент управляет этим числом.
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

// sendData ставит данные в очередь, дожидаясь кредита окна.
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

// reserveCredit забирает доступный кредит, ожидая его появления до дедлайна.
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

		// Клиент не забирает ответы. Копить дальше - отдать память тому, кто
		// перестал читать; честнее оборвать сессию.
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

// ── отдача клиенту ──────────────────────────────────────────────────────────

// Drain забирает накопленные кадры. Если очередь пуста, ждёт до истечения
// wait - это и есть длинный опрос: без него клиент долбил бы сервер вхолостую.
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
			// Дедлайн длинного опроса - это норма, а не ошибка: отдаём пусто.
			return nil, nil
		}
	}
}

// Close завершает сессию и все её потоки.
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

// StreamCount сообщает число живых потоков.
func (s *Session) StreamCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.streams)
}
