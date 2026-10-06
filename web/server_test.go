package web_test

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dolonet/mtg-multi/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testHost   = "web3.proxy-os.online"
	testSecret = "0123456789abcdef"
	decoyBody  = "<html>обычный сайт</html>"
)

type stubBridge struct{}

func (stubBridge) Render(host, token string) (string, string) {
	return "<html>мост " + host + " " + token + "</html>", "default-src 'none'"
}

type stubDecoy struct{}

func (stubDecoy) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, decoyBody)
}

func newTestServer(t *testing.T, handle func(*web.Stream), opts ...func(*web.ServerConfig)) (*web.Server, web.Profile) {
	t.Helper()

	capability, err := web.DeriveCapability(web.ClientSecret([]byte(testSecret), web.SecretModeDD), testHost)
	require.NoError(t, err)

	profile := web.Profile{User: "petya_1", Capability: capability, SecretMode: web.SecretModeDD}

	table, err := web.NewProfileTable([]web.Profile{profile})
	require.NoError(t, err)

	_, loopback, err := net.ParseCIDR("127.0.0.1/32")
	require.NoError(t, err)

	cfg := web.DefaultServerConfig()
	cfg.VHosts = []web.VHost{{Host: testHost, Profiles: table, Decoy: stubDecoy{}}}
	cfg.TrustedProxyCIDRs = []*net.IPNet{loopback}
	cfg.Bridge = stubBridge{}
	cfg.LongPollTimeout = 300 * time.Millisecond

	if handle == nil {
		handle = func(*web.Stream) {}
	}

	cfg.Handle = handle

	for _, opt := range opts {
		opt(&cfg)
	}

	srv := web.NewServer(cfg)
	t.Cleanup(srv.Close)

	return srv, profile
}

func do(srv *web.Server, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, r)

	return rec
}

func bridgeRequest(profile web.Profile) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/?bridge="+web.EncodeCapability(profile.Capability), nil)
	r.Host = testHost
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set("X-Forwarded-For", "203.0.113.7")

	return r
}

func carrierRequest(path, token string, body []byte) *http.Request {
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	r.Host = testHost
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set("Content-Type", "application/octet-stream")
	r.Header.Set("Authorization", "Bearer "+token)

	return r
}

// Токен выдаётся страницей-мостом; тест повторяет путь настоящего клиента.
func openSession(t *testing.T, srv *web.Server, profile web.Profile) string {
	t.Helper()

	rec := do(srv, bridgeRequest(profile))
	require.Equal(t, http.StatusOK, rec.Code)

	fields := strings.Fields(strings.TrimSuffix(rec.Body.String(), "</html>"))
	token := fields[len(fields)-1]

	hello := web.Encode(web.FrameHello, 0, []byte{1})
	rec = do(srv, carrierRequest("/api/v1/session", token, hello))
	require.Equal(t, http.StatusOK, rec.Code)

	frames, err := web.ParseAll(rec.Body.Bytes(), web.DefaultLimits())
	require.NoError(t, err)
	require.Len(t, frames, 1)
	require.Equal(t, web.FrameWelcome, frames[0].Type)
	// Тело WELCOME обязано быть пустым: кадр уходит в Telegram, и с лишним
	// байтом версии клиент замолкает после создания сессии (20.09.2026).
	require.Empty(t, frames[0].Payload)

	return token
}

// Главное свойство маскировки: всё, что не является запросом нашего клиента,
// получает обычную статику. Отличимый ответ выдал бы прокси пробующему DPI.
func TestServerServesDecoyForEverythingElse(t *testing.T) {
	srv, profile := newTestServer(t, nil)

	cases := map[string]*http.Request{
		"корень без параметров":  httptest.NewRequest(http.MethodGet, "/", nil),
		"чужой путь":             httptest.NewRequest(http.MethodGet, "/wp-login.php", nil),
		"мусор в bridge":         httptest.NewRequest(http.MethodGet, "/?bridge=нетакое", nil),
		"неизвестный capability": httptest.NewRequest(http.MethodGet, "/?bridge="+strings.Repeat("A", 43), nil),
		"POST в корень":          httptest.NewRequest(http.MethodPost, "/", nil),
		"транспорт без токена":   httptest.NewRequest(http.MethodPost, "/api/v1/up", nil),
	}

	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			r.Host = testHost
			r.RemoteAddr = "127.0.0.1:12345"

			rec := do(srv, r)

			assert.Equal(t, http.StatusOK, rec.Code)
			assert.Equal(t, decoyBody, rec.Body.String())
		})
	}

	// А вот канонический запрос своего клиента получает мост.
	rec := do(srv, bridgeRequest(profile))
	assert.Contains(t, rec.Body.String(), "мост")
}

func TestServerRejectsForeignHost(t *testing.T) {
	srv, profile := newTestServer(t, nil)

	r := bridgeRequest(profile)
	r.Host = "чужой.example.com"

	assert.Equal(t, http.StatusNotFound, do(srv, r).Code)
}

// Ссылка WEB не несёт порт - клиент всегда идёт на 443. Host с другим портом
// означает не нашего клиента.
func TestServerRejectsNonStandardPort(t *testing.T) {
	srv, profile := newTestServer(t, nil)

	r := bridgeRequest(profile)
	r.Host = testHost + ":8443"

	assert.Equal(t, http.StatusNotFound, do(srv, r).Code)
}

// Сквозной сценарий целиком: мост → сессия → открытие потока → данные туда и
// обратно. Это и есть WEB с точки зрения пользователя.
func TestServerEndToEnd(t *testing.T) {
	handled := make(chan struct{})

	srv, profile := newTestServer(t, func(stream *web.Stream) {
		defer close(handled)

		buf := make([]byte, 16)
		n, err := stream.Read(buf)
		assert.NoError(t, err)
		assert.Equal(t, "ping", string(buf[:n]))

		_, err = stream.Write([]byte("pong"))
		assert.NoError(t, err)
	})

	token := openSession(t, srv, profile)

	body := append(
		web.Encode(web.FrameOpen, 1, nil),
		web.Encode(web.FrameData, 1, []byte("ping"))...,
	)
	require.Equal(t, http.StatusOK, do(srv, carrierRequest("/api/v1/up", token, body)).Code)

	select {
	case <-handled:
	case <-time.After(2 * time.Second):
		t.Fatal("поток не обработан")
	}

	rec := do(srv, carrierRequest("/api/v1/down", token, nil))
	require.Equal(t, http.StatusOK, rec.Code)

	frames, err := web.ParseAll(rec.Body.Bytes(), web.DefaultLimits())
	require.NoError(t, err)
	require.NotEmpty(t, frames)
	assert.Equal(t, []byte("pong"), frames[0].Payload)
}

// Клиентский IP берётся из X-Forwarded-For только от доверенного прокси - это
// nginx на localhost. Иначе любой мог бы назначить себе чужой адрес и обойти
// ограничения по адресам.
func TestServerTakesClientIPFromTrustedProxy(t *testing.T) {
	got := make(chan string, 1)

	srv, profile := newTestServer(t, func(stream *web.Stream) {
		host, _, _ := net.SplitHostPort(stream.RemoteAddr().String())
		got <- host
	})

	token := openSession(t, srv, profile)
	require.Equal(t, http.StatusOK,
		do(srv, carrierRequest("/api/v1/up", token, web.Encode(web.FrameOpen, 1, nil))).Code)

	select {
	case host := <-got:
		assert.Equal(t, "203.0.113.7", host)
	case <-time.After(2 * time.Second):
		t.Fatal("поток не открылся")
	}
}

func TestServerIgnoresForwardedFromUntrustedPeer(t *testing.T) {
	got := make(chan string, 1)

	srv, profile := newTestServer(t, func(stream *web.Stream) {
		host, _, _ := net.SplitHostPort(stream.RemoteAddr().String())
		got <- host
	})

	// Запрос якобы от клиента, но соединение пришло не от nginx с localhost.
	r := bridgeRequest(profile)
	r.RemoteAddr = "198.51.100.5:40000"
	r.Header.Set("X-Forwarded-For", "203.0.113.7")

	rec := do(srv, r)
	require.Equal(t, http.StatusOK, rec.Code)

	fields := strings.Fields(strings.TrimSuffix(rec.Body.String(), "</html>"))
	token := fields[len(fields)-1]

	require.Equal(t, http.StatusOK,
		do(srv, carrierRequest("/api/v1/session", token, web.Encode(web.FrameHello, 0, []byte{1}))).Code)
	require.Equal(t, http.StatusOK,
		do(srv, carrierRequest("/api/v1/up", token, web.Encode(web.FrameOpen, 1, nil))).Code)

	select {
	case host := <-got:
		assert.Equal(t, "198.51.100.5", host)
	case <-time.After(2 * time.Second):
		t.Fatal("поток не открылся")
	}
}

// Токен одноразовый: по одной странице-мосту поднимается ровно одна сессия.
func TestServerTokenIsSingleUse(t *testing.T) {
	srv, profile := newTestServer(t, nil)

	token := openSession(t, srv, profile)

	rec := do(srv, carrierRequest("/api/v1/session", token, web.Encode(web.FrameHello, 0, []byte{1})))
	assert.Equal(t, decoyBody, rec.Body.String())
}

func TestServerRejectsBadCarrierRequests(t *testing.T) {
	srv, profile := newTestServer(t, nil)
	token := openSession(t, srv, profile)

	t.Run("чужой тип содержимого", func(t *testing.T) {
		r := carrierRequest("/api/v1/up", token, web.Encode(web.FrameOpen, 1, nil))
		r.Header.Set("Content-Type", "application/json")

		assert.Equal(t, decoyBody, do(srv, r).Body.String())
	})

	t.Run("кривой токен", func(t *testing.T) {
		r := carrierRequest("/api/v1/up", strings.Repeat("!", 43), web.Encode(web.FrameOpen, 1, nil))

		assert.Equal(t, decoyBody, do(srv, r).Body.String())
	})

	t.Run("GET вместо POST", func(t *testing.T) {
		r := carrierRequest("/api/v1/up", token, nil)
		r.Method = http.MethodGet

		assert.Equal(t, decoyBody, do(srv, r).Body.String())
	})
}

// Сломанный кадр рвёт сессию: дальше доверять состоянию потока нельзя.
func TestServerDropsSessionOnProtocolError(t *testing.T) {
	srv, profile := newTestServer(t, nil)
	token := openSession(t, srv, profile)

	assert.Equal(t, 1, srv.SessionCount())

	// DATA на нулевом потоке - нарушение грамматики.
	rec := do(srv, carrierRequest("/api/v1/up", token, web.Encode(web.FrameData, 0, []byte("x"))))
	assert.Equal(t, decoyBody, rec.Body.String())
	assert.Equal(t, 0, srv.SessionCount())
}

// Длинный опрос: при пустой очереди запрос придерживается и возвращает пусто.
func TestServerLongPollReturnsEmpty(t *testing.T) {
	srv, profile := newTestServer(t, nil)
	token := openSession(t, srv, profile)

	start := time.Now()
	rec := do(srv, carrierRequest("/api/v1/down", token, nil))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, rec.Body.Bytes())
	assert.GreaterOrEqual(t, time.Since(start), 200*time.Millisecond)
}

// Таблица выданных мостом токенов ограничена: иначе её раздувал бы любой, кто
// дёргает страницу-мост. При заполнении - обычная заглушка, как у сайта.
func TestServerPendingTokensAreCapped(t *testing.T) {
	srv, profile := newTestServer(t, nil, func(cfg *web.ServerConfig) { cfg.MaxPending = 2 })

	for range 2 {
		rec := do(srv, bridgeRequest(profile))
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "мост")
	}

	rec := do(srv, bridgeRequest(profile))
	assert.Equal(t, decoyBody, rec.Body.String())
}

// Живых сессий не больше MaxSessions; лишняя получает заглушку.
func TestServerSessionsAreCapped(t *testing.T) {
	srv, profile := newTestServer(t, nil, func(cfg *web.ServerConfig) { cfg.MaxSessions = 1 })

	openSession(t, srv, profile)
	require.Equal(t, 1, srv.SessionCount())

	rec := do(srv, bridgeRequest(profile))
	require.Equal(t, http.StatusOK, rec.Code)

	fields := strings.Fields(strings.TrimSuffix(rec.Body.String(), "</html>"))
	token := fields[len(fields)-1]

	rec = do(srv, carrierRequest("/api/v1/session", token, web.Encode(web.FrameHello, 0, []byte{1})))
	assert.Equal(t, decoyBody, rec.Body.String())
	assert.Equal(t, 1, srv.SessionCount())
}
