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

	"github.com/mhsanaei/mtg-multi/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testHost   = "proxy.example.com"
	testSecret = "0123456789abcdef"
	decoyBody  = "<html>regular site</html>"
)

type stubBridge struct{}

func (stubBridge) Render(host, token string) (string, string) {
	return "<html>bridge " + host + " " + token + "</html>", "default-src 'none'"
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

// The token is issued by the bridge page; the test follows the path of a real
// client.
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
	// The WELCOME body must be empty: the frame goes to Telegram, and with an
	// extra version byte the client goes silent after the session is created.
	require.Empty(t, frames[0].Payload)

	return token
}

// The key camouflage property: anything that is not a request from our client
// gets ordinary static content. A distinguishable response would give the
// proxy away to a probing DPI.
func TestServerServesDecoyForEverythingElse(t *testing.T) {
	srv, profile := newTestServer(t, nil)

	cases := map[string]*http.Request{
		"root without parameters": httptest.NewRequest(http.MethodGet, "/", nil),
		"foreign path":            httptest.NewRequest(http.MethodGet, "/wp-login.php", nil),
		"garbage in bridge":       httptest.NewRequest(http.MethodGet, "/?bridge=garbage", nil),
		"unknown capability":      httptest.NewRequest(http.MethodGet, "/?bridge="+strings.Repeat("A", 43), nil),
		"POST to root":            httptest.NewRequest(http.MethodPost, "/", nil),
		"transport without token": httptest.NewRequest(http.MethodPost, "/api/v1/up", nil),
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

	// A canonical request from our own client, however, gets the bridge.
	rec := do(srv, bridgeRequest(profile))
	assert.Contains(t, rec.Body.String(), "bridge")
}

func TestServerRejectsForeignHost(t *testing.T) {
	srv, profile := newTestServer(t, nil)

	r := bridgeRequest(profile)
	r.Host = "other.example.com"

	assert.Equal(t, http.StatusNotFound, do(srv, r).Code)
}

// The WEB link carries no port: the client always connects to 443. A Host with
// any other port means it is not our client.
func TestServerRejectsNonStandardPort(t *testing.T) {
	srv, profile := newTestServer(t, nil)

	r := bridgeRequest(profile)
	r.Host = testHost + ":8443"

	assert.Equal(t, http.StatusNotFound, do(srv, r).Code)
}

// The full end-to-end scenario: bridge -> session -> stream open -> data both
// ways. This is what WEB looks like from the user's point of view.
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
		t.Fatal("stream was not handled")
	}

	rec := do(srv, carrierRequest("/api/v1/down", token, nil))
	require.Equal(t, http.StatusOK, rec.Code)

	frames, err := web.ParseAll(rec.Body.Bytes(), web.DefaultLimits())
	require.NoError(t, err)
	require.NotEmpty(t, frames)
	assert.Equal(t, []byte("pong"), frames[0].Payload)
}

// The server takes the largest /up body the bridge page sends (whole frames
// up to 512 KB, at most 256 frames) and a body of exactly MaxBodyBytes, and
// refuses a longer one.
func TestServerAcceptsUpBodyUpToMaxBodyBytes(t *testing.T) {
	discard := func(stream *web.Stream) {
		io.Copy(io.Discard, stream) //nolint: errcheck
	}

	upOK := func(t *testing.T, srv *web.Server, token string, body []byte) {
		t.Helper()

		rec := do(srv, carrierRequest("/api/v1/up", token, body))
		require.Equal(t, "application/octet-stream", rec.Header().Get("Content-Type"))
		require.Equal(t, 1, srv.SessionCount())
	}

	full := web.Encode(web.FrameData, 1, make([]byte, web.DataChunkBytes))

	t.Run("largest page batches with the defaults", func(t *testing.T) {
		srv, profile := newTestServer(t, discard)
		token := openSession(t, srv, profile)

		upOK(t, srv, token, web.Encode(web.FrameOpen, 1, nil))
		upOK(t, srv, token, bytes.Repeat(full, 512*1024/len(full)))

		many := web.Encode(web.FrameOpen, 3, nil)
		for range web.DefaultLimits().MaxFramesPerBody - 1 {
			many = append(many, web.Encode(web.FrameData, 3, []byte{1})...)
		}

		upOK(t, srv, token, many)
	})

	t.Run("exactly the limit and one frame over it", func(t *testing.T) {
		small := web.Encode(web.FrameData, 1, []byte("data"))

		srv, profile := newTestServer(t, discard, func(cfg *web.ServerConfig) {
			cfg.MaxBodyBytes = int64(3 * len(small))
		})
		token := openSession(t, srv, profile)

		upOK(t, srv, token, web.Encode(web.FrameOpen, 1, nil))
		upOK(t, srv, token, bytes.Repeat(small, 3))

		rec := do(srv, carrierRequest("/api/v1/up", token, bytes.Repeat(small, 4)))
		assert.Equal(t, decoyBody, rec.Body.String())
	})
}

// The client IP is taken from X-Forwarded-For only when it comes from a
// trusted proxy, i.e. nginx on localhost. Otherwise anyone could assign
// themselves a foreign address and bypass per-address limits.
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
		t.Fatal("stream did not open")
	}
}

func TestServerIgnoresForwardedFromUntrustedPeer(t *testing.T) {
	got := make(chan string, 1)

	srv, profile := newTestServer(t, func(stream *web.Stream) {
		host, _, _ := net.SplitHostPort(stream.RemoteAddr().String())
		got <- host
	})

	// The request claims to be from a client, but the connection did not come
	// from nginx on localhost.
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
		t.Fatal("stream did not open")
	}
}

// The token is single-use: one bridge page brings up exactly one session.
func TestServerTokenIsSingleUse(t *testing.T) {
	srv, profile := newTestServer(t, nil)

	token := openSession(t, srv, profile)

	rec := do(srv, carrierRequest("/api/v1/session", token, web.Encode(web.FrameHello, 0, []byte{1})))
	assert.Equal(t, decoyBody, rec.Body.String())
}

func TestServerRejectsBadCarrierRequests(t *testing.T) {
	srv, profile := newTestServer(t, nil)
	token := openSession(t, srv, profile)

	t.Run("foreign content type", func(t *testing.T) {
		r := carrierRequest("/api/v1/up", token, web.Encode(web.FrameOpen, 1, nil))
		r.Header.Set("Content-Type", "application/json")

		assert.Equal(t, decoyBody, do(srv, r).Body.String())
	})

	t.Run("malformed token", func(t *testing.T) {
		r := carrierRequest("/api/v1/up", strings.Repeat("!", 43), web.Encode(web.FrameOpen, 1, nil))

		assert.Equal(t, decoyBody, do(srv, r).Body.String())
	})

	t.Run("GET instead of POST", func(t *testing.T) {
		r := carrierRequest("/api/v1/up", token, nil)
		r.Method = http.MethodGet

		assert.Equal(t, decoyBody, do(srv, r).Body.String())
	})
}

// A broken frame tears the session down: the stream state can no longer be
// trusted.
func TestServerDropsSessionOnProtocolError(t *testing.T) {
	srv, profile := newTestServer(t, nil)
	token := openSession(t, srv, profile)

	assert.Equal(t, 1, srv.SessionCount())

	// DATA on stream 0 violates the grammar.
	rec := do(srv, carrierRequest("/api/v1/up", token, web.Encode(web.FrameData, 0, []byte("x"))))
	assert.Equal(t, decoyBody, rec.Body.String())
	assert.Equal(t, 0, srv.SessionCount())
}

// Long polling: with an empty queue the request is held and returns empty.
func TestServerLongPollReturnsEmpty(t *testing.T) {
	srv, profile := newTestServer(t, nil)
	token := openSession(t, srv, profile)

	start := time.Now()
	rec := do(srv, carrierRequest("/api/v1/down", token, nil))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, rec.Body.Bytes())
	assert.GreaterOrEqual(t, time.Since(start), 200*time.Millisecond)
}

// The table of tokens issued by the bridge is capped: otherwise anyone hitting
// the bridge page could inflate it. When full, the regular decoy is served,
// like on an ordinary site.
func TestServerPendingTokensAreCapped(t *testing.T) {
	srv, profile := newTestServer(t, nil, func(cfg *web.ServerConfig) { cfg.MaxPending = 2 })

	for range 2 {
		rec := do(srv, bridgeRequest(profile))
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "bridge")
	}

	rec := do(srv, bridgeRequest(profile))
	assert.Equal(t, decoyBody, rec.Body.String())
}

// There are at most MaxSessions live sessions; an extra one gets the decoy.
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
