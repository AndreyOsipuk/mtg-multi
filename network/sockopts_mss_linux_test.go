//go:build linux

package network_test

import (
	"net"
	"testing"

	"github.com/dolonet/mtg-multi/network"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func tcpMaxSeg(t *testing.T, conn net.Conn) int {
	t.Helper()

	rawConn, err := conn.(*net.TCPConn).SyscallConn() //nolint: forcetypeassert
	require.NoError(t, err)

	var (
		mss    int
		sysErr error
	)

	require.NoError(t, rawConn.Control(func(fd uintptr) {
		mss, sysErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_MAXSEG)
	}))
	require.NoError(t, sysErr)

	return mss
}

func dialPair(t *testing.T, listenerMSS int) (net.Conn, net.Conn) {
	t.Helper()

	lc := net.ListenConfig{Control: network.ListenControlMSS(listenerMSS)}

	ln, err := lc.Listen(t.Context(), "tcp4", "127.0.0.1:0")
	require.NoError(t, err)

	defer ln.Close() //nolint: errcheck

	client, err := net.Dial("tcp4", ln.Addr().String())
	require.NoError(t, err)

	t.Cleanup(func() { client.Close() }) //nolint: errcheck

	server, err := ln.Accept()
	require.NoError(t, err)

	t.Cleanup(func() { server.Close() }) //nolint: errcheck

	return server, client
}

// TCP_MAXSEG слушающего сокета объявляется клиенту в SYN-ACK: и клиент, и
// сервер дальше шлют сегменты не крупнее него (client-mss-bulk = 0).
func TestListenControlMSSAdvertisedInSynAck(t *testing.T) {
	server, client := dialPair(t, 92)

	clientMSS := tcpMaxSeg(t, client)
	serverMSS := tcpMaxSeg(t, server)

	assert.LessOrEqual(t, clientMSS, 92)
	assert.LessOrEqual(t, serverMSS, 92)
	t.Logf("listener MSS 92: TCP_MAXSEG клиента=%d, сервера=%d", clientMSS, serverMSS)
}

func TestListenControlMSSZeroKeepsDefault(t *testing.T) {
	server, client := dialPair(t, 0)

	assert.Greater(t, tcpMaxSeg(t, client), 1000)
	assert.Greater(t, tcpMaxSeg(t, server), 1000)
}

func TestListenControlMSSRejectsTooSmall(t *testing.T) {
	lc := net.ListenConfig{Control: network.ListenControlMSS(40)}

	_, err := lc.Listen(t.Context(), "tcp4", "127.0.0.1:0")
	assert.Error(t, err)
}
