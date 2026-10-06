package mtglib

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net"
	"time"

	"github.com/dolonet/mtg-multi/essentials"
)

type streamContext struct {
	ctx          context.Context
	ctxCancel    context.CancelFunc
	clientConn   essentials.Conn
	telegramConn essentials.Conn
	// rawConn - исходное соединение клиента. В отличие от clientConn, его никто
	// не переписывает, поэтому только его можно закрывать из чужой горутины
	// (перезагрузка секретов, остановка): clientConn/telegramConn ServeConn
	// подменяет обёртками, и чтение интерфейса во время записи - гонка.
	rawConn essentials.Conn
	// userStats - запись статистики, в которой эта сессия учтена. Уменьшаем
	// именно её: после удаления и повторного добавления пользователя по имени
	// нашлась бы уже новая запись, и счётчик ушёл бы в минус.
	userStats        *secretStats
	streamID         string
	dc               int
	matchedSecretKey []byte
	secretName       string
	adTag            *[AdTagLength]byte
	// secured=true — клиент подключился через secured-режим (dd-секрет,
	// obfuscated2 без FakeTLS-обёртки). В этом случае obfuscated2-рукопожатие уже
	// сделано внутри doSecuredHandshake, и ServeConn пропускает FakeTLS-специфику
	// (doppelganger + отдельный doObfuscatedHandshake).
	secured bool
	logger  Logger
}

func (s *streamContext) Deadline() (time.Time, bool) {
	return s.ctx.Deadline()
}

func (s *streamContext) Done() <-chan struct{} {
	return s.ctx.Done()
}

func (s *streamContext) Err() error {
	return s.ctx.Err() //nolint: wrapcheck
}

func (s *streamContext) Value(key any) any {
	return s.ctx.Value(key)
}

func (s *streamContext) Close() {
	s.ctxCancel()

	if s.clientConn != nil {
		s.clientConn.Close() //nolint: errcheck
	}

	if s.telegramConn != nil {
		s.telegramConn.Close() //nolint: errcheck
	}
}

// closeFromOutside прерывает сессию из чужой горутины: отменяет контекст и
// закрывает исходное соединение. Остальное закроет ServeConn в своём defer.
func (s *streamContext) closeFromOutside() {
	s.ctxCancel()

	if s.rawConn != nil {
		s.rawConn.Close() //nolint: errcheck
	}
}

func (s *streamContext) ClientIP() net.IP {
	return s.clientConn.RemoteAddr().(*net.TCPAddr).IP //nolint: forcetypeassert
}

func newStreamContext(ctx context.Context, logger Logger, clientConn essentials.Conn) *streamContext {
	connIDBytes := make([]byte, ConnectionIDBytesLength)

	if _, err := rand.Read(connIDBytes); err != nil {
		panic(err)
	}

	ctx, cancel := context.WithCancel(ctx)
	streamCtx := &streamContext{
		ctx:        ctx,
		ctxCancel:  cancel,
		clientConn: clientConn,
		rawConn:    clientConn,
		streamID:   base64.RawURLEncoding.EncodeToString(connIDBytes),
	}
	streamCtx.logger = logger.
		BindStr("stream-id", streamCtx.streamID).
		BindStr("client-ip", streamCtx.ClientIP().String())

	return streamCtx
}
