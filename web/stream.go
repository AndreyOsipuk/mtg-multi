package web

import (
	"io"
	"net"
	"sync"
	"time"

	"github.com/dolonet/mtg-multi/essentials"
)

// Проверка на этапе компиляции: поток обязан подходить под essentials.Conn,
// иначе его нельзя отдать в Proxy.ServeConn.
var _ essentials.Conn = (*Stream)(nil)

// streamSink - то, куда поток отдаёт кадры для клиента. Отдельный интерфейс,
// чтобы поток тестировался без HTTP и без сессии целиком.
type streamSink interface {
	// sendData отдаёт клиенту кусок данных потока, соблюдая кредит окна.
	sendData(streamID uint32, payload []byte, deadline time.Time) error
	// sendClose сообщает клиенту, что поток закрыт.
	sendClose(streamID uint32)
	// returnWindow возвращает клиенту израсходованный кредит.
	returnWindow(streamID uint32, amount uint32)
	// dropStream убирает поток из таблицы сессии.
	dropStream(streamID uint32)
}

// Stream - одно логическое MTProto-соединение внутри WEB-сессии.
//
// Реализует essentials.Conn, поэтому уходит в Proxy.ServeConn как обычный
// сокет: весь существующий путь mtg (рукопожатие, статистика, DC-пул) работает
// без единой правки. В этом и смысл - WEB добавляет транспорт, а не второй
// параллельный прокси.
type Stream struct {
	id      uint32
	sink    streamSink
	inbound *pipe

	local  net.Addr
	remote net.Addr

	// consumed - сколько байт прочитано с момента последнего возврата кредита.
	// Возвращаем не на каждый байт, а порциями: кадр WINDOW на каждые
	// прочитанные 10 байт утроил бы служебный трафик.
	consumedMu sync.Mutex
	consumed   uint32

	closeOnce sync.Once
}

// windowReturnThreshold - порог возврата кредита: четверть окна.
const windowReturnThreshold = InitialStreamWindow / 4

// Адреса ОБЯЗАНЫ быть *net.TCPAddr, а не своим типом: mtg приводит адрес
// жёстко (stream_context.go: RemoteAddr().(*net.TCPAddr).IP), и любой другой
// тип роняет процесс на первом же потоке. Поймано живой пробой на ноде
// 19.09.2026 - юнит-тесты этого не видели, потому что дёргали только String().
func newStream(id uint32, sink streamSink, clientIP net.IP, bufferCapacity int) *Stream {
	remote := &net.TCPAddr{IP: clientIP}
	if clientIP == nil {
		remote.IP = net.IPv4zero
	}

	return &Stream{
		id:      id,
		sink:    sink,
		inbound: newPipe(bufferCapacity),
		// Порт 443: снаружи клиент пришёл именно на него, через настоящий HTTPS.
		local:  &net.TCPAddr{IP: net.IPv4zero, Port: 443},
		remote: remote,
	}
}

// ID возвращает номер логического потока.
func (s *Stream) ID() uint32 { return s.id }

// deliver кладёт пришедшие от клиента данные в поток.
func (s *Stream) deliver(payload []byte) error {
	// Копия обязательна: payload указывает внутрь тела HTTP-запроса, которое
	// обработчик освободит сразу после разбора.
	data := make([]byte, len(payload))
	copy(data, payload)

	return s.inbound.write(data)
}

// finish закрывает поток со стороны клиента: читатель добёрет остаток.
func (s *Stream) finish(err error) {
	s.inbound.closeWrite(err)
}

func (s *Stream) Read(dst []byte) (int, error) {
	n, err := s.inbound.Read(dst)
	if n > 0 {
		s.creditConsumed(uint32(n))
	}

	return n, err
}

// creditConsumed копит прочитанное и возвращает кредит порциями.
func (s *Stream) creditConsumed(n uint32) {
	s.consumedMu.Lock()

	s.consumed += n

	var release uint32

	if s.consumed >= windowReturnThreshold {
		release = s.consumed
		s.consumed = 0
	}

	s.consumedMu.Unlock()

	if release > 0 {
		s.sink.returnWindow(s.id, release)
	}
}

func (s *Stream) Write(src []byte) (int, error) {
	deadline := s.inbound.getWriteDeadline()
	written := 0

	// Режем на куски: один кадр не должен быть больше согласованного потолка,
	// иначе клиент отвергнет тело целиком.
	for written < len(src) {
		end := min(written+DataChunkBytes, len(src))

		if err := s.sink.sendData(s.id, src[written:end], deadline); err != nil {
			return written, err
		}

		written = end
	}

	return written, nil
}

// Close закрывает поток в обе стороны и убирает его из сессии.
func (s *Stream) Close() error {
	s.closeOnce.Do(func() {
		s.inbound.closeRead()
		s.inbound.closeWrite(io.EOF)
		s.sink.sendClose(s.id)
		s.sink.dropStream(s.id)
	})

	return nil
}

// CloseRead закрывает чтение, не трогая запись.
func (s *Stream) CloseRead() error {
	s.inbound.closeRead()

	return nil
}

// CloseWrite сообщает клиенту, что данных больше не будет.
func (s *Stream) CloseWrite() error {
	s.sink.sendClose(s.id)

	return nil
}

func (s *Stream) LocalAddr() net.Addr  { return s.local }
func (s *Stream) RemoteAddr() net.Addr { return s.remote }

func (s *Stream) SetDeadline(t time.Time) error {
	s.inbound.setReadDeadline(t)
	s.inbound.setWriteDeadline(t)

	return nil
}

func (s *Stream) SetReadDeadline(t time.Time) error {
	s.inbound.setReadDeadline(t)

	return nil
}

func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.inbound.setWriteDeadline(t)

	return nil
}
