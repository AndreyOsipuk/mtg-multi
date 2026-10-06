package mtglib

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/dolonet/mtg-multi/essentials"
	"github.com/dolonet/mtg-multi/mtglib/obfuscation"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Хук (WEB-вход) вызывается при любом применении - и SIGHUP/ApplySecrets, и
// PUT /secrets - после проверок и до подмены набора прокси.
func TestSecretsHook(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("alice.example.com")
	bob := GenerateSecret("bob.example.com")

	t.Run("set syncs the hook right away", func(t *testing.T) {
		t.Parallel()

		p := newAPITestProxy(map[string]Secret{"alice": alice})

		var got map[string]Secret
		require.NoError(t, p.SetSecretsHook(func(s map[string]Secret) error {
			got = s

			return nil
		}))
		assert.Equal(t, map[string]Secret{"alice": alice}, got)
	})

	t.Run("hook sees every entry point", func(t *testing.T) {
		t.Parallel()

		p := newAPITestProxy(map[string]Secret{"alice": alice})

		calls := []map[string]Secret{}
		require.NoError(t, p.SetSecretsHook(func(s map[string]Secret) error {
			calls = append(calls, s)

			return nil
		}))

		_, err := p.ApplySecrets(SecretConfig{Secrets: map[string]Secret{"alice": alice, "bob": bob}})
		require.NoError(t, err)

		rec := doAPI(t, p, "", http.MethodPut, "/secrets", `{"secrets":{"bob":{"secret":"`+bob.Hex()+`"}}}`)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

		p.reloader = func() (SecretConfig, error) {
			return SecretConfig{Secrets: map[string]Secret{"alice": alice}}, nil
		}
		require.NoError(t, p.ReloadSecrets())

		require.Len(t, calls, 4)
		assert.Equal(t, map[string]Secret{"alice": alice, "bob": bob}, calls[1])
		assert.Equal(t, map[string]Secret{"bob": bob}, calls[2])
		assert.Equal(t, map[string]Secret{"alice": alice}, calls[3])
	})

	t.Run("hook error keeps the current set", func(t *testing.T) {
		t.Parallel()

		p := newAPITestProxy(map[string]Secret{"alice": alice})
		_, err := p.ApplySecrets(SecretConfig{Secrets: map[string]Secret{"alice": alice}})
		require.NoError(t, err)

		digest := p.stats.secretsDigest.Load()
		stream := registerFakeStream(p, "alice")

		require.NoError(t, p.SetSecretsHook(func(s map[string]Secret) error {
			if _, ok := s["bob"]; ok {
				return errors.New("duplicate capability")
			}

			return nil
		}))

		rec := doAPI(t, p, "", http.MethodPut, "/secrets", `{"secrets":{"bob":{"secret":"`+bob.Hex()+`"}}}`)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Equal(t, []string{"alice"}, p.secrets.Load().names)
		assert.Equal(t, digest, p.stats.secretsDigest.Load())
		assert.NoError(t, stream.Err(), "a failed update must not close sessions")
	})

	t.Run("invalid secret is rejected before the hook", func(t *testing.T) {
		t.Parallel()

		p := newAPITestProxy(map[string]Secret{"alice": alice})

		called := 0
		require.NoError(t, p.SetSecretsHook(func(map[string]Secret) error {
			called++

			return nil
		}))

		_, err := p.ApplySecrets(SecretConfig{Secrets: map[string]Secret{"bob": {}}})
		require.ErrorIs(t, err, ErrSecretInvalid)

		_, err = p.ApplySecrets(SecretConfig{})
		require.ErrorIs(t, err, ErrSecretEmpty)
		require.ErrorIs(t, err, ErrSecretInvalid)

		assert.Equal(t, 1, called, "only the initial sync")
	})
}

// Рукопожатие, прошедшее проверку лимитов на старом наборе, не регистрируется,
// если пользователя тем временем выключили или у него истёк срок.
func TestTrackSessionRespectsLimits(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("alice.example.com")

	for name, lim := range map[string]SecretLimits{
		"disabled": {Disabled: true},
		"expired":  {ExpiresAt: time.Now().Add(-time.Minute)},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			p := newUpdateTestProxy(map[string]Secret{"alice": alice})

			_, err := p.ApplySecrets(SecretConfig{
				Secrets: map[string]Secret{"alice": alice},
				Limits:  map[string]SecretLimits{"alice": lim},
			})
			require.NoError(t, err)

			stream := &streamContext{secretName: "alice", matchedSecretKey: alice.Key[:]}
			assert.False(t, p.trackSession(stream))
			assert.Zero(t, p.stats.lookup("alice").connections.Load())
		})
	}

	t.Run("quota does not reject a tracked session", func(t *testing.T) {
		t.Parallel()

		p := newUpdateTestProxy(map[string]Secret{"alice": alice})
		_, err := p.ApplySecrets(SecretConfig{
			Secrets: map[string]Secret{"alice": alice},
			Limits:  map[string]SecretLimits{"alice": {QuotaBytes: 1}},
		})
		require.NoError(t, err)

		p.stats.lookup("alice").quotaUsed.Store(10)
		authenticatedSession(t, p, "alice", alice)
	})
}

// Выключение пользователя через применение закрывает его живые сессии (через
// closeFromOutside) и считается в ClosedSessions; остальные живут.
func TestApplyClosesDisabledSessions(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("alice.example.com")
	bob := GenerateSecret("bob.example.com")

	p := newUpdateTestProxy(map[string]Secret{"alice": alice, "bob": bob})
	aliceSession := authenticatedSession(t, p, "alice", alice)
	bobSession := authenticatedSession(t, p, "bob", bob)

	update, err := p.ApplySecrets(SecretConfig{
		Secrets: map[string]Secret{"alice": alice, "bob": bob},
		Limits:  map[string]SecretLimits{"alice": {Disabled: true}},
	})
	require.NoError(t, err)

	assert.Equal(t, 1, update.ClosedSessions)
	assert.True(t, isClosed(aliceSession))
	assert.False(t, isClosed(bobSession))
}

// UpdateSecrets (только секреты) сохраняет теги и лимиты оставшихся имён.
func TestUpdateSecretsKeepsTagsAndLimits(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("alice.example.com")
	bob := GenerateSecret("bob.example.com")
	tag := [AdTagLength]byte{1}

	p := newUpdateTestProxy(map[string]Secret{"alice": alice})
	_, err := p.ApplySecrets(SecretConfig{
		Secrets:      map[string]Secret{"alice": alice, "bob": bob},
		SecretAdTags: map[string][AdTagLength]byte{"alice": tag, "bob": tag},
		Limits:       map[string]SecretLimits{"alice": {QuotaBytes: 5}, "bob": {QuotaBytes: 7}},
	})
	require.NoError(t, err)

	_, err = p.UpdateSecrets(map[string]Secret{"alice": alice})
	require.NoError(t, err)

	cfg := p.secrets.Load().toConfig()
	assert.Equal(t, map[string][AdTagLength]byte{"alice": tag}, cfg.SecretAdTags)
	assert.Equal(t, map[string]SecretLimits{"alice": {QuotaBytes: 5}}, cfg.Limits)
}

type noReplayCache struct{}

func (noReplayCache) SeenBefore([]byte) bool { return false }

// securedServerStream - серверная сторона соединения, клиент которого отправил
// secured (dd) рукопожатие с ключом key.
func securedServerStream(t *testing.T, key []byte) (*streamContext, *connRewind) {
	t.Helper()

	client, server := net.Pipe()
	t.Cleanup(func() {
		client.Close() //nolint: errcheck
		server.Close() //nolint: errcheck
	})

	go func() {
		obfs := obfuscation.Obfuscator{Secret: key}
		obfs.SendHandshake(essentials.WrapNetConn(client), 2) //nolint: errcheck
	}()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	conn := essentials.WrapNetConn(server)
	stream := &streamContext{
		ctx:        ctx,
		ctxCancel:  cancel,
		clientConn: conn,
		rawConn:    conn,
		logger:     testLogger(),
	}

	return stream, newConnRewind(conn)
}

// Лимиты пользователя действуют и на secured (dd), а не только на FakeTLS:
// отказ - до Commit, чтобы байты рукопожатия ушли на маскировку.
func TestSecuredHandshakeRespectsLimits(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("alice.example.com")
	bob := GenerateSecret("bob.example.com")

	p := newLimitTestProxy(map[string]Secret{"alice": alice, "bob": bob}, map[string]SecretLimits{
		"bob": {Disabled: true},
	})
	p.antiReplayCache = noReplayCache{}

	stream, rewind := securedServerStream(t, alice.Key[:])
	ok, err := p.doSecuredHandshake(stream, rewind, p.secrets.Load())
	require.NoError(t, err)
	require.True(t, ok)
	assert.True(t, stream.secured)
	assert.Equal(t, "alice", stream.secretName)
	assert.Equal(t, 2, stream.dc)

	stream, rewind = securedServerStream(t, bob.Key[:])
	ok, err = p.doSecuredHandshake(stream, rewind, p.secrets.Load())
	require.Error(t, err)
	assert.False(t, ok)
	assert.False(t, stream.secured)
	assert.Empty(t, stream.secretName)
}
