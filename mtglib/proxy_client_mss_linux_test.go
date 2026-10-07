//go:build linux

package mtglib_test

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dolonet/mtg-multi/antireplay"
	"github.com/dolonet/mtg-multi/events"
	"github.com/dolonet/mtg-multi/ipblocklist"
	"github.com/dolonet/mtg-multi/ipblocklist/files"
	"github.com/dolonet/mtg-multi/logger"
	"github.com/dolonet/mtg-multi/mtglib"
	"github.com/dolonet/mtg-multi/network"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yl2chen/cidranger"
	"golang.org/x/sys/unix"
)

// Секрет, которым подписаны снимки настоящих ClientHello в testdata пакета fake.
const snapshotSecret = "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d"

func snapshotClientHello(t *testing.T) []byte {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(
		"internal", "tls", "fake", "testdata", "client-hello-ok-19dfe38384b9884b.json"))
	require.NoError(t, err)

	snapshot := struct {
		Full string `json:"full"`
	}{}
	require.NoError(t, json.Unmarshal(data, &snapshot))

	full, err := base64.StdEncoding.DecodeString(snapshot.Full)
	require.NoError(t, err)

	return full
}

// serverHelloSegments проводит настоящее рукопожатие FakeTLS через прокси с
// заданным ServerHelloMSS и возвращает, сколько сегментов клиент получил,
// пока читал ServerHello (tcpi_segs_in), и размер ServerHello.
func serverHelloSegments(t *testing.T, serverHelloMSS int) (int, int) {
	t.Helper()

	secret, err := mtglib.ParseSecret(snapshotSecret)
	require.NoError(t, err)

	dialer, err := network.NewDefaultDialer(0, 0)
	require.NoError(t, err)

	ntw, err := network.NewNetwork(dialer, "mtgtest", "1.1.1.1", 0)
	require.NoError(t, err)

	allowlist, err := ipblocklist.NewFireholFromFiles(logger.NewNoopLogger(), 1,
		[]files.File{files.NewMem([]*net.IPNet{cidranger.AllIPv4, cidranger.AllIPv6})}, nil)
	require.NoError(t, err)

	go allowlist.Run(time.Second)

	require.Eventually(t, func() bool {
		return allowlist.Contains(net.ParseIP("127.0.0.1"))
	}, 2*time.Second, 10*time.Millisecond)

	proxy, err := mtglib.NewProxy(mtglib.ProxyOpts{
		Secret:          secret,
		Network:         ntw,
		AntiReplayCache: antireplay.NewNoop(),
		IPBlocklist:     ipblocklist.NewNoop(),
		IPAllowlist:     allowlist,
		EventStream:     events.NewNoopStream(),
		Logger:          logger.NewNoopLogger(),
		UseTestDCs:      true,
		// Снимок ClientHello сделан в 2021 году.
		TolerateTimeSkewness: 100 * 365 * 24 * time.Hour,
		ServerHelloMSS:       serverHelloMSS,
	})
	require.NoError(t, err)

	defer proxy.Shutdown()

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)

	defer listener.Close() //nolint: errcheck

	go proxy.Serve(listener) //nolint: errcheck

	conn, err := net.Dial("tcp4", listener.Addr().String())
	require.NoError(t, err)

	defer conn.Close() //nolint: errcheck

	client := conn.(*net.TCPConn) //nolint: forcetypeassert
	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))

	before := clientTCPInfo(t, client)

	_, err = client.Write(snapshotClientHello(t))
	require.NoError(t, err)

	total := 0

	for range 3 { // ServerHello, ChangeCipherSpec, ApplicationData
		header := make([]byte, 5)
		_, err := io.ReadFull(client, header)
		require.NoError(t, err)

		body := make([]byte, binary.BigEndian.Uint16(header[3:]))
		_, err = io.ReadFull(client, body)
		require.NoError(t, err)

		total += len(header) + len(body)
	}

	after := clientTCPInfo(t, client)

	return int(after.Segs_in - before.Segs_in), total
}

func clientTCPInfo(t *testing.T, conn *net.TCPConn) *unix.TCPInfo {
	t.Helper()

	rawConn, err := conn.SyscallConn()
	require.NoError(t, err)

	var (
		info   *unix.TCPInfo
		sysErr error
	)

	require.NoError(t, rawConn.Control(func(fd uintptr) {
		info, sysErr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
	}))
	require.NoError(t, sysErr)

	return info
}

// С ServerHelloMSS прокси шлёт ServerHello мелкими сегментами (здесь по 80
// байт полезной нагрузки), без него - несколькими крупными.
func TestProxyServerHelloMSS(t *testing.T) {
	plainSegs, plainSize := serverHelloSegments(t, 0)
	shapedSegs, shapedSize := serverHelloSegments(t, 92)

	assert.LessOrEqual(t, plainSegs, plainSize/1000+3)
	assert.GreaterOrEqual(t, shapedSegs, shapedSize/80)

	t.Logf("ServerHello без client-mss: %d байт, %d сегментов; с client-mss 92: %d байт, %d сегментов",
		plainSize, plainSegs, shapedSize, shapedSegs)
}
