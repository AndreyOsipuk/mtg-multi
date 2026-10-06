package mtglib

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dolonet/mtg-multi/essentials"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newUpdateTestProxy(secrets map[string]Secret) *Proxy {
	p := &Proxy{
		stats:    NewProxyStats(),
		sessions: newSessionRegistry(),
	}
	set := newSecretSet(secrets)

	for _, name := range set.names {
		p.stats.PreRegister(name)
	}

	p.secrets.Store(set)

	return p
}

// authenticatedSession imitates a stream that has passed the handshake with
// the given secret and registers it like ServeConn does.
func authenticatedSession(t *testing.T, p *Proxy, name string, secret Secret) *streamContext {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	stream := &streamContext{
		ctx:              ctx,
		ctxCancel:        cancel,
		secretName:       name,
		matchedSecretKey: secret.Key[:],
	}

	require.True(t, p.trackSession(stream))

	return stream
}

func isClosed(stream *streamContext) bool {
	select {
	case <-stream.Done():
		return true
	default:
		return false
	}
}

func TestNewSecretSet(t *testing.T) {
	t.Parallel()

	a := GenerateSecret("a.example.com")
	b := GenerateSecret("b.example.com")
	c := GenerateSecret("a.example.com")

	set := newSecretSet(map[string]Secret{"carol": c, "alice": a, "bob": b})

	assert.Equal(t, []string{"alice", "bob", "carol"}, set.names)
	assert.Equal(t, []Secret{a, b, c}, set.secrets)
	assert.Equal(t, [][]byte{a.Key[:], b.Key[:], c.Key[:]}, set.keys)
	assert.Equal(t, []string{"a.example.com", "b.example.com"}, set.hostnames)
	assert.True(t, set.sameSecret("bob", b.Key[:]))
	assert.False(t, set.sameSecret("bob", a.Key[:]))
	assert.False(t, set.sameSecret("dave", a.Key[:]))
}

func TestUpdateSecretsRejectsInvalidSet(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("example.com")
	p := newUpdateTestProxy(map[string]Secret{"alice": alice})
	stream := authenticatedSession(t, p, "alice", alice)

	_, err := p.UpdateSecrets(map[string]Secret{})
	require.ErrorIs(t, err, ErrSecretEmpty)

	_, err = p.UpdateSecrets(map[string]Secret{"bob": {}})
	require.Error(t, err)

	// A failed update leaves everything as it was.
	assert.Equal(t, []string{"alice"}, p.secrets.Load().names)
	assert.False(t, isClosed(stream))
}

func TestUpdateSecretsKeepsUnchangedSessions(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("example.com")
	bob := GenerateSecret("example.com")
	p := newUpdateTestProxy(map[string]Secret{"alice": alice, "bob": bob})

	aliceSession := authenticatedSession(t, p, "alice", alice)
	bobSession := authenticatedSession(t, p, "bob", bob)

	carol := GenerateSecret("other.example.com")
	update, err := p.UpdateSecrets(map[string]Secret{"alice": alice, "bob": bob, "carol": carol})
	require.NoError(t, err)

	assert.Equal(t, SecretsUpdate{Added: 1}, update)
	assert.False(t, isClosed(aliceSession))
	assert.False(t, isClosed(bobSession))

	set := p.secrets.Load()
	assert.Equal(t, []string{"alice", "bob", "carol"}, set.names)
	assert.Equal(t, []string{"example.com", "other.example.com"}, set.hostnames)
	assert.NotNil(t, p.stats.lookup("carol"))
}

func TestUpdateSecretsClosesRemovedAndChanged(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("example.com")
	bob := GenerateSecret("example.com")
	carol := GenerateSecret("example.com")
	p := newUpdateTestProxy(map[string]Secret{"alice": alice, "bob": bob, "carol": carol})

	alice1 := authenticatedSession(t, p, "alice", alice)
	alice2 := authenticatedSession(t, p, "alice", alice)
	bobSession := authenticatedSession(t, p, "bob", bob)
	carolSession := authenticatedSession(t, p, "carol", carol)

	// alice is removed, bob gets a new key, carol is kept.
	bobRotated := GenerateSecret("example.com")
	update, err := p.UpdateSecrets(map[string]Secret{"bob": bobRotated, "carol": carol})
	require.NoError(t, err)

	assert.Equal(t, SecretsUpdate{Removed: 1, Changed: 1, ClosedSessions: 3}, update)
	assert.True(t, isClosed(alice1))
	assert.True(t, isClosed(alice2))
	assert.True(t, isClosed(bobSession))
	assert.False(t, isClosed(carolSession))

	// The removed user disappears from the stats, and late updates from its
	// closing sessions do not bring it back.
	assert.Nil(t, p.stats.lookup("alice"))
	p.stats.OnDisconnect("alice")
	p.stats.AddBytesIn("alice", 10)
	p.stats.AddBytesOut("alice", 10)
	p.stats.UpdateLastSeen("alice")
	assert.Nil(t, p.stats.lookup("alice"))

	// The kept user still has its stats.
	assert.EqualValues(t, 1, p.stats.lookup("carol").connections.Load())

	// Closed sessions unregister themselves as ServeConn does on return.
	p.sessions.remove(alice1)
	p.sessions.remove(alice2)
	p.sessions.remove(bobSession)
	assert.Len(t, p.sessions.sessions, 1)
}

func TestUpdateSecretsHostChangeClosesSessions(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("old.example.com")
	p := newUpdateTestProxy(map[string]Secret{"alice": alice})
	stream := authenticatedSession(t, p, "alice", alice)

	moved := alice
	moved.Host = "new.example.com"

	update, err := p.UpdateSecrets(map[string]Secret{"alice": moved})
	require.NoError(t, err)

	assert.Equal(t, SecretsUpdate{Changed: 1, ClosedSessions: 1}, update)
	assert.True(t, isClosed(stream))
	assert.Equal(t, []string{"new.example.com"}, p.secrets.Load().hostnames)
}

// A handshake that matched a secret before an update must not register a
// session after the update has removed or rotated that secret: the session
// would escape the sweep.
func TestTrackSessionAfterSecretRemoved(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("example.com")
	bob := GenerateSecret("example.com")
	p := newUpdateTestProxy(map[string]Secret{"alice": alice, "bob": bob})

	_, err := p.UpdateSecrets(map[string]Secret{"bob": GenerateSecret("example.com")})
	require.NoError(t, err)

	for name, secret := range map[string]Secret{"alice": alice, "bob": bob} {
		ctx, cancel := context.WithCancel(context.Background())
		stream := &streamContext{
			ctx:              ctx,
			ctxCancel:        cancel,
			secretName:       name,
			matchedSecretKey: secret.Key[:],
		}

		assert.False(t, p.trackSession(stream), name)
		cancel()
	}

	assert.Empty(t, p.sessions.sessions)
	// A rejected session is not counted, and the removed user is not
	// brought back into the stats.
	assert.Nil(t, p.stats.lookup("alice"))
	assert.Zero(t, p.stats.lookup("bob").connections.Load())
}

func TestUpdateSecretsConcurrentWithSessions(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("example.com")
	p := newUpdateTestProxy(map[string]Secret{"alice": alice})

	done := make(chan struct{})

	go func() {
		defer close(done)

		for range 1000 {
			ctx, cancel := context.WithCancel(context.Background())
			stream := &streamContext{
				ctx:              ctx,
				ctxCancel:        cancel,
				secretName:       "alice",
				matchedSecretKey: alice.Key[:],
			}

			if p.trackSession(stream) {
				p.sessions.remove(stream)
			}

			cancel()
		}
	}()

	for i := range 200 {
		secrets := map[string]Secret{"alice": alice}
		if i%2 == 0 {
			secrets["bob"] = GenerateSecret("example.com")
		}

		_, err := p.UpdateSecrets(secrets)
		require.NoError(t, err)
	}

	<-done

	assert.Empty(t, p.sessions.sessions)
}

// tcpPair - настоящая пара TCP-соединений: newStreamContext требует TCP-адрес.
func tcpPair(t *testing.T) (server, client *net.TCPConn) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	accepted := make(chan net.Conn, 1)

	go func() {
		conn, _ := ln.Accept()
		accepted <- conn
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)

	s := <-accepted
	require.NotNil(t, s)
	t.Cleanup(func() { s.Close(); c.Close() })

	return s.(*net.TCPConn), c.(*net.TCPConn) //nolint: forcetypeassert
}

type wrappedConn struct {
	essentials.Conn
}

// Ревью: UpdateSecrets закрывал сессию через ctx.Close(), который читает
// clientConn/telegramConn, а ServeConn в это время подменяет их обёртками -
// гонка на интерфейсе, падение процесса. Теперь закрывается только исходное
// соединение. Тест ловится go test -race на старом коде.
func TestUpdateSecretsClosesWhileServeConnRewrapsConn(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("example.com")
	p := newUpdateTestProxy(map[string]Secret{"alice": alice})

	server, client := tcpPair(t)
	stream := newStreamContext(context.Background(), NoopLogger{}, server)
	stream.secretName = "alice"
	stream.matchedSecretKey = alice.Key[:]
	require.True(t, p.trackSession(stream))

	stop := make(chan struct{})
	done := make(chan struct{})

	go func() {
		defer close(done)

		for {
			select {
			case <-stop:
				return
			default:
				// Так ServeConn оборачивает соединение после регистрации.
				stream.clientConn = wrappedConn{Conn: stream.clientConn}
				stream.telegramConn = wrappedConn{Conn: server}
			}
		}
	}()

	update, err := p.UpdateSecrets(map[string]Secret{"bob": GenerateSecret("example.com")})
	require.NoError(t, err)
	close(stop)
	<-done

	assert.Equal(t, 1, update.ClosedSessions)
	assert.True(t, isClosed(stream))

	// Исходное соединение закрыто: клиент видит конец потока.
	require.NoError(t, client.SetReadDeadline(time.Now().Add(2*time.Second)))
	_, err = client.Read(make([]byte, 1))
	assert.ErrorIs(t, err, io.EOF)
}

// Ревью: удалили пользователя, следующей перезагрузкой вернули, и только потом
// закрылись его старые сессии - счётчик новой записи уходил в минус.
func TestReaddedUserCountersStayConsistent(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("example.com")
	bob := GenerateSecret("example.com")
	p := newUpdateTestProxy(map[string]Secret{"alice": alice, "bob": bob})

	old := authenticatedSession(t, p, "alice", alice)

	_, err := p.UpdateSecrets(map[string]Secret{"bob": bob})
	require.NoError(t, err)
	_, err = p.UpdateSecrets(map[string]Secret{"alice": alice, "bob": bob})
	require.NoError(t, err)

	// Так старая сессия завершается в ServeConn.
	old.userStats.connections.Add(-1)
	p.sessions.remove(old)

	assert.Zero(t, p.stats.lookup("alice").connections.Load())
}

// Ревью: при включённом троттлинге CanConnect через getOrCreate воскрешал
// удалённого пользователя в /stats, и горячая перезагрузка дальше не сходилась.
func TestCanConnectDoesNotRecreateForgottenUser(t *testing.T) {
	t.Parallel()

	stats := NewProxyStats()
	stats.SetThrottle(10, time.Second)
	stats.PreRegister("alice")
	stats.throttleCaps["alice"] = 1
	stats.Forget("alice")

	assert.True(t, stats.CanConnect("alice"))
	assert.Nil(t, stats.lookup("alice"))
}

func TestSecretsDigest(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("example.com")
	bob := GenerateSecret("example.com")
	p := newUpdateTestProxy(map[string]Secret{"bob": bob, "alice": alice})
	p.stats.SetSecretsDigest(p.secrets.Load().digest())

	want := sha256.Sum256([]byte("alice=" + alice.Hex() + "\nbob=" + bob.Hex()))
	assert.Equal(t, hex.EncodeToString(want[:]), p.secrets.Load().digest())

	readDigest := func() string {
		rec := httptest.NewRecorder()
		p.stats.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/stats", nil))

		var resp StatsResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))

		return resp.SecretsSHA256
	}

	before := readDigest()
	assert.Equal(t, hex.EncodeToString(want[:]), before)

	// Те же имена, другой ключ - отпечаток обязан смениться.
	_, err := p.UpdateSecrets(map[string]Secret{"alice": GenerateSecret("example.com"), "bob": bob})
	require.NoError(t, err)
	assert.NotEqual(t, before, readDigest())
}
