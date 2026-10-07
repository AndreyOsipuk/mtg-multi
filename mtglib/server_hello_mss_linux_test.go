//go:build linux

package mtglib

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/dolonet/mtg-multi/mtglib/internal/tls"
	"github.com/dolonet/mtg-multi/mtglib/internal/tls/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// mssTestPair поднимает слушатель с TCP_MAXSEG = listenerMSS (0 - не трогать)
// и возвращает принятое серверное и клиентское соединения. clientRcvBuf > 0
// задаёт SO_RCVBUF клиента до connect (маленькое окно приёма).
func mssTestPair(t *testing.T, listenerMSS, clientRcvBuf int) (*net.TCPConn, *net.TCPConn) {
	t.Helper()

	// network.ListenControlMSS отсюда не импортировать (цикл импортов), его
	// проверяет тест пакета network; здесь то же самое напрямую.
	lc := net.ListenConfig{Control: func(_, _ string, conn syscall.RawConn) error {
		if listenerMSS <= 0 {
			return nil
		}

		var opErr error

		if err := conn.Control(func(fd uintptr) {
			opErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_MAXSEG, listenerMSS)
		}); err != nil {
			return err
		}

		return opErr
	}}

	ln, err := lc.Listen(t.Context(), "tcp4", "127.0.0.1:0")
	require.NoError(t, err)

	t.Cleanup(func() { ln.Close() }) //nolint: errcheck

	dialer := net.Dialer{}
	if clientRcvBuf > 0 {
		dialer.Control = func(_, _ string, conn syscall.RawConn) error {
			var opErr error

			err := conn.Control(func(fd uintptr) {
				opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, clientRcvBuf)
			})
			if err != nil {
				return err
			}

			return opErr
		}
	}

	client, err := dialer.DialContext(t.Context(), "tcp4", ln.Addr().String())
	require.NoError(t, err)

	t.Cleanup(func() { client.Close() }) //nolint: errcheck

	server, err := ln.Accept()
	require.NoError(t, err)

	t.Cleanup(func() { server.Close() }) //nolint: errcheck

	return server.(*net.TCPConn), client.(*net.TCPConn) //nolint: forcetypeassert
}

func tcpInfoOf(t *testing.T, conn *net.TCPConn) *unix.TCPInfo {
	t.Helper()

	rawConn, err := conn.SyscallConn()
	require.NoError(t, err)

	info, err := getTCPInfo(rawConn)
	require.NoError(t, err)

	return info
}

// waitAllAcked ждёт, пока все отправленные сервером данные подтверждены,
// чтобы tcpi_segs_out больше не менялся.
func waitAllAcked(t *testing.T, conn *net.TCPConn) *unix.TCPInfo {
	t.Helper()

	var info *unix.TCPInfo

	require.Eventually(t, func() bool {
		info = tcpInfoOf(t, conn)

		return info.Notsent_bytes == 0 && info.Unacked == 0
	}, 5*time.Second, time.Millisecond)

	return info
}

func readAllAsync(conn net.Conn, size int) <-chan []byte {
	done := make(chan []byte, 1)

	go func() {
		buf := make([]byte, size)
		n, _ := io.ReadFull(conn, buf)
		done <- buf[:n]
	}()

	return done
}

// Главный сценарий: сокет на bulk 1400, ServerHello (~4 КБ) режется по 92 -
// не меньше одного сегмента на кусок, а следующие данные идут крупными
// сегментами (tcpi_snd_mss >= 1000).
func TestWriteFragmentedSmallHelloThenBulk(t *testing.T) {
	server, client := mssTestPair(t, 1400, 0)

	clientMSS, err := getsockoptMSS(client)
	require.NoError(t, err)
	assert.LessOrEqual(t, clientMSS, 1400)
	assert.GreaterOrEqual(t, clientMSS, 1000)

	hello := make([]byte, 4096)
	_, err = rand.Read(hello)
	require.NoError(t, err)

	got := readAllAsync(client, len(hello))

	before := waitAllAcked(t, server)
	chunk := segmentPayload(92, before)
	assert.LessOrEqual(t, chunk, 80+12)

	n, err := writeFragmented(server, hello, 92, time.Now().Add(5*time.Second))
	require.NoError(t, err)
	assert.Equal(t, len(hello), n)

	afterHello := waitAllAcked(t, server)
	helloSegs := int(afterHello.Segs_out - before.Segs_out)
	wantSegs := (len(hello) + chunk - 1) / chunk

	assert.GreaterOrEqual(t, helloSegs, wantSegs, "ServerHello должен уйти кусками по %d байт", chunk)
	assert.Equal(t, hello, <-got)

	bulk := make([]byte, 64*1024)
	got = readAllAsync(client, len(bulk))

	_, err = server.Write(bulk)
	require.NoError(t, err)

	afterBulk := waitAllAcked(t, server)
	bulkSegs := int(afterBulk.Segs_out - afterHello.Segs_out)

	assert.GreaterOrEqual(t, int(afterBulk.Snd_mss), 1000)
	assert.Less(t, bulkSegs, len(bulk)/500, "после ServerHello сегменты должны быть крупными")
	assert.Len(t, <-got, len(bulk))

	t.Logf("ServerHello %d байт: кусок %d, сегментов %d (ожидалось >= %d); "+
		"bulk 64 КБ: сегментов %d, tcpi_snd_mss до=%d после=%d",
		len(hello), chunk, helloSegs, wantSegs, bulkSegs, before.Snd_mss, afterBulk.Snd_mss)
}

// Куски не должны склеиваться, когда отправка упирается в окно: клиент с
// крошечным окном приёма не читает 300 мс, ядро держит данные в очереди.
// Без ожидания tcpi_notsent_bytes = 0 очередные куски дописались бы в
// неотправленный хвост очереди и ушли одним большим сегментом.
func TestWriteFragmentedDoesNotCoalesceWhenWindowLimited(t *testing.T) {
	server, client := mssTestPair(t, 1400, 2048)

	hello := make([]byte, 4096)
	_, err := rand.Read(hello)
	require.NoError(t, err)

	before := waitAllAcked(t, server)
	chunk := segmentPayload(92, before)

	got := make(chan []byte, 1)

	go func() {
		time.Sleep(300 * time.Millisecond)

		buf := make([]byte, len(hello))
		n, _ := io.ReadFull(client, buf)
		got <- buf[:n]
	}()

	_, err = writeFragmented(server, hello, 92, time.Now().Add(5*time.Second))
	require.NoError(t, err)

	assert.Equal(t, hello, <-got)

	after := waitAllAcked(t, server)
	segs := int(after.Segs_out - before.Segs_out)
	wantSegs := (len(hello) + chunk - 1) / chunk

	assert.GreaterOrEqual(t, segs, wantSegs)
	t.Logf("окно приёма 2 КБ: ServerHello %d байт ушёл %d сегментами (кусков %d)", len(hello), segs, wantSegs)
}

// Настоящий ServerHello через fragmentedWriter разбирается клиентом как три
// TLS-записи: дробление не портит поток.
func TestSendServerHelloThroughFragmentedWriter(t *testing.T) {
	server, client := mssTestPair(t, 1400, 0)

	hello := &fake.ClientHello{CipherSuite: 4867, SessionID: make([]byte, 32)}
	_, err := rand.Read(hello.SessionID)
	require.NoError(t, err)

	secret := GenerateSecret("example.com")
	writer := fragmentedWriter{conn: server, mss: 92, deadline: time.Now().Add(5 * time.Second)}

	before := waitAllAcked(t, server)

	errCh := make(chan error, 1)

	go func() {
		errCh <- fake.SendServerHello(writer, secret.Key[:], hello, fake.NoiseParams{})
	}()

	reader := bufio.NewReader(client)
	total := 0

	for _, want := range []byte{tls.TypeHandshake, tls.TypeChangeCipherSpec, tls.TypeApplicationData} {
		rec := &bytes.Buffer{}

		recordType, length, err := tls.ReadRecord(reader, rec)
		require.NoError(t, err)
		assert.Equal(t, want, recordType)

		total += 5 + int(length)
	}

	require.NoError(t, <-errCh)

	after := waitAllAcked(t, server)
	chunk := segmentPayload(92, before)

	assert.GreaterOrEqual(t, int(after.Segs_out-before.Segs_out), (total+chunk-1)/chunk)
}

// Обёртка PROXY protocol (TCPConn()) - тоже TCP: дробление до неё доходит.
func TestTCPConnOfUnwrapsProxyProtocol(t *testing.T) {
	server, _ := mssTestPair(t, 0, 0)

	assert.Same(t, server, tcpConnOf(server))
	assert.Same(t, server, tcpConnOf(tcpWrapper{conn: server}))
	assert.Nil(t, tcpConnOf(nonTCPConn{}))
}

type tcpWrapper struct {
	net.Conn

	conn *net.TCPConn
}

func (w tcpWrapper) TCPConn() (*net.TCPConn, bool) { return w.conn, true }

type nonTCPConn struct {
	net.Conn
}

// Не TCP (поток WEB-режима) - запись целиком, без ошибок.
func TestWriteFragmentedFallsBackForNonTCP(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()  //nolint: errcheck
	defer right.Close() //nolint: errcheck

	got := readAllAsync(right, 3)

	n, err := writeFragmented(left, []byte("abc"), 92, time.Time{})
	require.NoError(t, err)
	assert.Equal(t, 3, n)
	assert.Equal(t, []byte("abc"), <-got)
}

func getsockoptMSS(conn *net.TCPConn) (int, error) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return 0, err //nolint: wrapcheck
	}

	var (
		mss    int
		sysErr error
	)

	if err := rawConn.Control(func(fd uintptr) {
		mss, sysErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_MAXSEG)
	}); err != nil {
		return 0, err //nolint: wrapcheck
	}

	return mss, sysErr //nolint: wrapcheck
}
