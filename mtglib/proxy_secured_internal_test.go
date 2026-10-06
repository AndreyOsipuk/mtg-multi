package mtglib

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mhsanaei/mtg-multi/essentials"
	"github.com/mhsanaei/mtg-multi/mtglib/obfuscation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type securedTestReplayCache struct {
	seen bool
}

func (c securedTestReplayCache) SeenBefore([]byte) bool { return c.seen }

type securedTestEventStream struct{}

func (securedTestEventStream) Send(context.Context, Event) {}

// securedClientFrame returns the 64-byte obfuscated2 handshake a secured
// ("dd") client sends for key and dc.
func securedClientFrame(t *testing.T, key []byte, dc int) []byte {
	t.Helper()

	client, server := net.Pipe()
	defer client.Close() //nolint: errcheck
	defer server.Close() //nolint: errcheck

	done := make(chan error, 1)

	go func() {
		_, err := obfuscation.Obfuscator{Secret: key}.SendHandshake(essentials.WrapNetConn(client), dc)
		done <- err
	}()

	frame := make([]byte, 64)
	_, err := io.ReadFull(server, frame)
	require.NoError(t, err)
	require.NoError(t, <-done)

	return frame
}

// securedTestStream wraps frame (followed by payload) into a stream context
// whose client connection is a connRewind, as doFakeTLSHandshake prepares it.
func securedTestStream(t *testing.T, data []byte) (*streamContext, *connRewind) {
	t.Helper()

	// A real TCP pair: the stream context needs a TCP remote address.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	defer listener.Close() //nolint: errcheck

	client, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)

	server, err := listener.Accept()
	require.NoError(t, err)

	t.Cleanup(func() {
		client.Close() //nolint: errcheck
		server.Close() //nolint: errcheck
	})

	_, err = client.Write(data)
	require.NoError(t, err)

	ctx := newStreamContext(context.Background(), testLogger(), essentials.WrapNetConn(server))
	t.Cleanup(ctx.Close)

	rewind := newConnRewind(ctx.clientConn)

	return ctx, rewind
}

func newSecuredTestProxy(set *secretSet, replay bool) *Proxy {
	p := &Proxy{
		stats:           NewProxyStats(),
		liveConns:       make(map[string]map[*streamContext]struct{}),
		logger:          testLogger(),
		antiReplayCache: securedTestReplayCache{seen: replay},
		eventStream:     securedTestEventStream{},
		securedEnabled:  true,
	}

	for _, name := range set.names {
		p.stats.PreRegister(name)
	}

	p.secrets.Store(set)

	return p
}

func securedKeys(set *secretSet) [][]byte {
	keys := make([][]byte, len(set.secrets))
	for i := range set.secrets {
		keys[i] = set.secrets[i].Key[:]
	}

	return keys
}

func TestDoSecuredHandshakeAllowed(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("alice.example.com")
	bob := GenerateSecret("bob.example.com")
	tag := [AdTagLength]byte{1, 2, 3}

	set := buildSecretSet(
		map[string]Secret{"alice": alice, "bob": bob},
		map[string][AdTagLength]byte{"bob": tag},
		nil,
		map[string]SecretLimits{"bob": {QuotaBytes: 1000}},
	)
	p := newSecuredTestProxy(set, false)

	ctx, rewind := securedTestStream(t, securedClientFrame(t, bob.Key[:], 4))

	host, err := p.doSecuredHandshake(ctx, rewind, set, securedKeys(set))
	require.NoError(t, err)

	assert.Equal(t, "bob.example.com", host)
	assert.True(t, ctx.secured)
	assert.Equal(t, "bob", ctx.secretName)
	assert.Equal(t, 4, ctx.dc)
	require.NotNil(t, ctx.adTag, "a dd client must get the per-secret adtag like a FakeTLS one")
	assert.Equal(t, tag, *ctx.adTag)
	assert.Empty(t, rewind.buf.Bytes(), "an authenticated client must not keep replay history")
}

func TestDoSecuredHandshakeDeniedByLimits(t *testing.T) {
	t.Parallel()

	cases := map[string]SecretLimits{
		"disabled":   {Disabled: true},
		"expired":    {ExpiresAt: time.Now().Add(-time.Hour)},
		"over quota": {QuotaBytes: 100},
	}

	for name, lim := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			alice := GenerateSecret("alice.example.com")
			set := buildSecretSet(map[string]Secret{"alice": alice}, nil, nil, map[string]SecretLimits{"alice": lim})
			p := newSecuredTestProxy(set, false)
			p.stats.users["alice"].quotaUsed.Store(500)

			frame := securedClientFrame(t, alice.Key[:], 2)
			ctx, rewind := securedTestStream(t, frame)

			host, err := p.doSecuredHandshake(ctx, rewind, set, securedKeys(set))
			require.Error(t, err)

			assert.Equal(t, "alice.example.com", host)
			assert.False(t, ctx.secured)
			assert.Empty(t, ctx.secretName)

			// The fronting host must get the client's bytes unchanged, exactly
			// like for a wrong secret.
			rewind.FinalRewind()

			replayed := make([]byte, len(frame))
			_, err = io.ReadFull(rewind, replayed)
			require.NoError(t, err)
			assert.True(t, bytes.Equal(frame, replayed))
		})
	}
}

func TestDoSecuredHandshakeUnknownSecret(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("alice.example.com")
	stranger := GenerateSecret("stranger.example.com")
	set := buildSecretSet(map[string]Secret{"alice": alice}, nil, nil, nil)
	p := newSecuredTestProxy(set, false)

	ctx, rewind := securedTestStream(t, securedClientFrame(t, stranger.Key[:], 2))

	host, err := p.doSecuredHandshake(ctx, rewind, set, securedKeys(set))
	require.Error(t, err)
	assert.Equal(t, "alice.example.com", host)
	assert.False(t, ctx.secured)
}

func TestDoSecuredHandshakeReplay(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("alice.example.com")
	set := buildSecretSet(map[string]Secret{"alice": alice}, nil, nil, nil)
	p := newSecuredTestProxy(set, true)

	ctx, rewind := securedTestStream(t, securedClientFrame(t, alice.Key[:], 2))

	_, err := p.doSecuredHandshake(ctx, rewind, set, securedKeys(set))
	require.Error(t, err)
	assert.False(t, ctx.secured)
}
