package web_test

import (
	"net"
	"testing"
	"time"

	"github.com/dolonet/mtg-multi/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mtg приводит адрес клиента жёстко: RemoteAddr().(*net.TCPAddr).IP. Свой тип
// адреса ронял процесс на первом же открытом потоке - поймано живой пробой на
// ноде, а не тестами, потому что тесты дёргали только String().
func TestStreamAddrsAreTCPAddr(t *testing.T) {
	got := make(chan net.Addr, 2)

	session := web.NewSession(web.Token{}, web.Profile{User: "u"}, net.ParseIP("203.0.113.7"),
		web.DefaultSessionConfig(), func(stream *web.Stream) {
			got <- stream.RemoteAddr()
			got <- stream.LocalAddr()
		})
	t.Cleanup(session.Close)

	require.NoError(t, session.Accept(web.Encode(web.FrameOpen, 1, nil)))

	select {
	case remote := <-got:
		tcp, ok := remote.(*net.TCPAddr)
		require.True(t, ok, "RemoteAddr обязан быть *net.TCPAddr")
		assert.Equal(t, "203.0.113.7", tcp.IP.String())

		_, ok = (<-got).(*net.TCPAddr)
		assert.True(t, ok, "LocalAddr обязан быть *net.TCPAddr")
	case <-time.After(2 * time.Second):
		t.Fatal("поток не открылся")
	}
}

// Без клиентского адреса приведение типа всё равно не должно падать.
func TestStreamAddrWithoutClientIP(t *testing.T) {
	got := make(chan net.Addr, 1)

	session := web.NewSession(web.Token{}, web.Profile{User: "u"}, nil,
		web.DefaultSessionConfig(), func(stream *web.Stream) { got <- stream.RemoteAddr() })
	t.Cleanup(session.Close)

	require.NoError(t, session.Accept(web.Encode(web.FrameOpen, 1, nil)))

	select {
	case remote := <-got:
		tcp, ok := remote.(*net.TCPAddr)
		require.True(t, ok)
		assert.NotNil(t, tcp.IP)
	case <-time.After(2 * time.Second):
		t.Fatal("поток не открылся")
	}
}
