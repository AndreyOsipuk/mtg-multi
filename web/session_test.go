package web_test

import (
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/dolonet/mtg-multi/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestSession(t *testing.T, handle func(*web.Stream)) *web.Session {
	t.Helper()

	if handle == nil {
		handle = func(*web.Stream) {}
	}

	session := web.NewSession(
		web.Token{1, 2, 3},
		web.Profile{User: "petya_1", SecretMode: web.SecretModeDD},
		net.ParseIP("203.0.113.7"),
		web.DefaultSessionConfig(),
		handle,
	)
	t.Cleanup(session.Close)

	return session
}

// Сквозной сценарий: клиент открывает поток и шлёт байты, обработчик читает их
// как из обычного сокета и отвечает, ответ возвращается клиенту кадрами.
// Именно ради этого весь модуль и существует.
func TestSessionRoundTrip(t *testing.T) {
	handled := make(chan struct{})

	session := newTestSession(t, func(stream *web.Stream) {
		defer close(handled)

		buf := make([]byte, 16)

		n, err := stream.Read(buf)
		assert.NoError(t, err)
		assert.Equal(t, "ping", string(buf[:n]))

		_, err = stream.Write([]byte("pong"))
		assert.NoError(t, err)
	})

	body := append(
		web.Encode(web.FrameOpen, 1, nil),
		web.Encode(web.FrameData, 1, []byte("ping"))...,
	)
	require.NoError(t, session.Accept(body))

	select {
	case <-handled:
	case <-time.After(2 * time.Second):
		t.Fatal("обработчик потока не отработал")
	}

	out, err := session.Drain(time.Second)
	require.NoError(t, err)

	frames, err := web.ParseAll(out, web.DefaultLimits())
	require.NoError(t, err)
	require.NotEmpty(t, frames)

	assert.Equal(t, web.FrameData, frames[0].Type)
	assert.Equal(t, uint32(1), frames[0].StreamID)
	assert.Equal(t, []byte("pong"), frames[0].Payload)
}

// Клиентский IP должен доезжать до потока: на нём держится статистика mtg и
// ограничения по адресам. Без этого все WEB-клиенты выглядели бы как один.
func TestStreamCarriesClientIP(t *testing.T) {
	got := make(chan string, 1)

	session := newTestSession(t, func(stream *web.Stream) {
		host, _, _ := net.SplitHostPort(stream.RemoteAddr().String())
		got <- host
	})

	require.NoError(t, session.Accept(web.Encode(web.FrameOpen, 1, nil)))

	select {
	case host := <-got:
		assert.Equal(t, "203.0.113.7", host)
	case <-time.After(2 * time.Second):
		t.Fatal("поток не открылся")
	}
}

// mtg ставит дедлайн на рукопожатие и ждёт, что Read с него сорвётся. Если
// дедлайны не работают, молчащий клиент держит горутину и слот навсегда.
func TestStreamReadDeadline(t *testing.T) {
	done := make(chan error, 1)

	session := newTestSession(t, func(stream *web.Stream) {
		require.NoError(t, stream.SetDeadline(time.Now().Add(150*time.Millisecond)))

		_, err := stream.Read(make([]byte, 8))
		done <- err
	})

	require.NoError(t, session.Accept(web.Encode(web.FrameOpen, 1, nil)))

	select {
	case err := <-done:
		assert.ErrorIs(t, err, os.ErrDeadlineExceeded)
	case <-time.After(2 * time.Second):
		t.Fatal("Read не сорвался по дедлайну")
	}
}

// CLOSE от клиента = конец данных: читатель обязан получить EOF, а не зависнуть.
func TestSessionCloseStreamGivesEOF(t *testing.T) {
	done := make(chan error, 1)

	session := newTestSession(t, func(stream *web.Stream) {
		_, err := io.ReadAll(stream)
		done <- err
	})

	body := append(
		web.Encode(web.FrameOpen, 1, nil),
		web.Encode(web.FrameData, 1, []byte("x"))...,
	)
	body = append(body, web.Encode(web.FrameClose, 1, nil)...)
	require.NoError(t, session.Accept(body))

	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("поток не завершился после CLOSE")
	}
}

func TestSessionRejectsBadFrames(t *testing.T) {
	t.Run("данные для неизвестного потока", func(t *testing.T) {
		session := newTestSession(t, nil)
		err := session.Accept(web.Encode(web.FrameData, 9, []byte("x")))
		assert.ErrorIs(t, err, web.ErrUnknownStream)
	})

	t.Run("повторный OPEN того же потока", func(t *testing.T) {
		session := newTestSession(t, nil)
		require.NoError(t, session.Accept(web.Encode(web.FrameOpen, 1, nil)))

		err := session.Accept(web.Encode(web.FrameOpen, 1, nil))
		assert.ErrorIs(t, err, web.ErrInvalidShape)
	})

	t.Run("HELLO внутри живой сессии", func(t *testing.T) {
		session := newTestSession(t, nil)
		err := session.Accept(web.Encode(web.FrameHello, 0, []byte{1}))
		assert.ErrorIs(t, err, web.ErrInvalidShape)
	})

	// Число потоков задаёт клиент, поэтому потолок обязателен: иначе одна
	// сессия выедает память и слоты статистики.
	t.Run("потоков больше потолка", func(t *testing.T) {
		cfg := web.DefaultSessionConfig()
		cfg.MaxStreams = 2

		session := web.NewSession(web.Token{}, web.Profile{User: "u"}, nil, cfg, func(*web.Stream) {})
		t.Cleanup(session.Close)

		require.NoError(t, session.Accept(web.Encode(web.FrameOpen, 1, nil)))
		require.NoError(t, session.Accept(web.Encode(web.FrameOpen, 2, nil)))

		err := session.Accept(web.Encode(web.FrameOpen, 3, nil))
		assert.ErrorIs(t, err, web.ErrTooManyStreams)
	})
}

// Длинный опрос: если отдавать нечего, Drain ждёт и возвращает пусто, а не
// заставляет клиента долбить сервер впустую.
func TestSessionDrainWaitsAndReturnsEmpty(t *testing.T) {
	session := newTestSession(t, nil)

	start := time.Now()
	body, err := session.Drain(200 * time.Millisecond)

	require.NoError(t, err)
	assert.Empty(t, body)
	assert.GreaterOrEqual(t, time.Since(start), 150*time.Millisecond)
}

// Кредит окна: сервер не вправе отправлять больше, чем разрешил клиент.
func TestSessionRespectsWindowCredit(t *testing.T) {
	cfg := web.DefaultSessionConfig()
	cfg.MaxOutboundBytes = 64 * 1024 * 1024

	blocked := make(chan struct{})
	finished := make(chan int, 1)

	session := web.NewSession(web.Token{}, web.Profile{User: "u"}, nil, cfg, func(stream *web.Stream) {
		close(blocked)
		// Просим отправить больше стартового окна - последний кусок обязан
		// дождаться, пока клиент вернёт кредит кадром WINDOW.
		n, _ := stream.Write(make([]byte, web.InitialStreamWindow+1024))
		finished <- n
	})
	t.Cleanup(session.Close)

	require.NoError(t, session.Accept(web.Encode(web.FrameOpen, 1, nil)))
	<-blocked

	select {
	case <-finished:
		t.Fatal("запись прошла целиком, хотя кредита окна не хватало")
	case <-time.After(300 * time.Millisecond):
	}

	require.NoError(t, session.Accept(web.Encode(web.FrameWindow, 1, web.WindowPayload(4096))))

	select {
	case n := <-finished:
		assert.Equal(t, web.InitialStreamWindow+1024, n)
	case <-time.After(2 * time.Second):
		t.Fatal("запись не продолжилась после возврата кредита")
	}
}

// Клиент перестал забирать ответы - копить бесконечно нельзя.
func TestSessionOutboundOverflow(t *testing.T) {
	cfg := web.DefaultSessionConfig()
	cfg.MaxOutboundBytes = 1024

	failed := make(chan error, 1)

	session := web.NewSession(web.Token{}, web.Profile{User: "u"}, nil, cfg, func(stream *web.Stream) {
		_, err := stream.Write(make([]byte, 4096))
		failed <- err
	})
	t.Cleanup(session.Close)

	require.NoError(t, session.Accept(web.Encode(web.FrameOpen, 1, nil)))

	select {
	case err := <-failed:
		assert.ErrorIs(t, err, web.ErrOutboundFull)
	case <-time.After(2 * time.Second):
		t.Fatal("переполнение очереди не обнаружено")
	}
}

// Закрытие сессии обязано разбудить все потоки: иначе горутины обработчиков
// останутся висеть после ухода клиента.
func TestSessionCloseReleasesStreams(t *testing.T) {
	done := make(chan error, 1)

	session := newTestSession(t, func(stream *web.Stream) {
		_, err := stream.Read(make([]byte, 8))
		done <- err
	})

	require.NoError(t, session.Accept(web.Encode(web.FrameOpen, 1, nil)))
	time.Sleep(50 * time.Millisecond)
	session.Close()

	select {
	case err := <-done:
		assert.Error(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("поток не разбудили при закрытии сессии")
	}

	assert.ErrorIs(t, session.Accept(web.Encode(web.FrameOpen, 2, nil)), web.ErrSessionClosed)
}
