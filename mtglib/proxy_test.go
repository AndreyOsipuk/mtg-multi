package mtglib_test

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dolonet/mtg-multi/essentials"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/dolonet/mtg-multi/antireplay"
	"github.com/dolonet/mtg-multi/events"
	"github.com/dolonet/mtg-multi/ipblocklist"
	"github.com/dolonet/mtg-multi/ipblocklist/files"
	"github.com/dolonet/mtg-multi/logger"
	"github.com/dolonet/mtg-multi/mtglib"
	"github.com/dolonet/mtg-multi/network"
	"github.com/stretchr/testify/suite"
	"github.com/yl2chen/cidranger"
)

type ProxyTestSuite struct {
	suite.Suite

	opts     *mtglib.ProxyOpts
	p        *mtglib.Proxy
	listener net.Listener
}

func (suite *ProxyTestSuite) ProxyAddress() string {
	_, port, _ := net.SplitHostPort(suite.listener.Addr().String())

	return net.JoinHostPort("127.0.0.1", port)
}

func (suite *ProxyTestSuite) ProxySecret() string {
	return suite.opts.Secret.Hex()
}

func (suite *ProxyTestSuite) SetupSuite() {
	dialer, err := network.NewDefaultDialer(0, 0)
	suite.NoError(err)

	ntw, err := network.NewNetwork(dialer, "mtgtest", "1.1.1.1", 0)
	suite.NoError(err)

	allowlist, _ := ipblocklist.NewFireholFromFiles(
		logger.NewNoopLogger(),
		1,
		[]files.File{
			files.NewMem([]*net.IPNet{
				cidranger.AllIPv4,
				cidranger.AllIPv6,
			}),
		},
		nil,
	)

	go allowlist.Run(time.Second)

	suite.opts = &mtglib.ProxyOpts{
		Secret:          mtglib.GenerateSecret("httpbin.org"),
		Network:         ntw,
		AntiReplayCache: antireplay.NewNoop(),
		IPBlocklist:     ipblocklist.NewNoop(),
		IPAllowlist:     allowlist,
		EventStream:     events.NewNoopStream(),
		Logger:          logger.NewNoopLogger(),
		UseTestDCs:      true,
	}

	proxy, err := mtglib.NewProxy(*suite.opts)
	suite.NoError(err)

	suite.p = proxy

	listener, err := net.Listen("tcp", ":0")
	suite.NoError(err)

	suite.listener = listener

	go suite.p.Serve(suite.listener) //nolint: errcheck
}

func (suite *ProxyTestSuite) TearDownSuite() {
	if suite.listener != nil {
		suite.listener.Close() //nolint: errcheck
	}

	if suite.p != nil {
		suite.p.Shutdown()
	}
}

func (suite *ProxyTestSuite) TestCannotInitNoSecret() {
	opts := *suite.opts
	opts.Secret = mtglib.Secret{}

	_, err := mtglib.NewProxy(opts)
	suite.Error(err)
}

func (suite *ProxyTestSuite) TestCannotInitNoNetwork() {
	opts := *suite.opts
	opts.Network = nil

	_, err := mtglib.NewProxy(opts)
	suite.Error(err)
}

func (suite *ProxyTestSuite) TestCannotInitNoAntiReplayCache() {
	opts := *suite.opts
	opts.AntiReplayCache = nil

	_, err := mtglib.NewProxy(opts)
	suite.Error(err)
}

func (suite *ProxyTestSuite) TestCannotInitNoIPBlocklist() {
	opts := *suite.opts
	opts.IPBlocklist = nil

	_, err := mtglib.NewProxy(opts)
	suite.Error(err)
}

func (suite *ProxyTestSuite) TestCannotInitNoIPAllowlist() {
	opts := *suite.opts
	opts.IPAllowlist = nil

	_, err := mtglib.NewProxy(opts)
	suite.Error(err)
}

func (suite *ProxyTestSuite) TestCannotInitNoEventStream() {
	opts := *suite.opts
	opts.EventStream = nil

	_, err := mtglib.NewProxy(opts)
	suite.Error(err)
}

func (suite *ProxyTestSuite) TestCannotInitNoLogger() {
	opts := *suite.opts
	opts.Logger = nil

	_, err := mtglib.NewProxy(opts)
	suite.Error(err)
}

func (suite *ProxyTestSuite) TestCannotInitIncorrectPreferIP() {
	opts := *suite.opts
	opts.PreferIP = "xxx"

	_, err := mtglib.NewProxy(opts)
	suite.Error(err)
}

func (suite *ProxyTestSuite) TestDomainFrontingAddress() {
	suite.Equal("httpbin.org:443", suite.p.DomainFrontingAddress())
}

func (suite *ProxyTestSuite) TestHTTPSRequest() {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: 5 * time.Second,
	}

	addr := fmt.Sprintf("https://%s/headers", suite.ProxyAddress())

	resp, err := client.Get(addr) //nolint: noctx
	suite.Require().NoError(err)

	defer resp.Body.Close() //nolint: errcheck

	suite.Equal(http.StatusOK, resp.StatusCode)

	data, err := io.ReadAll(resp.Body)
	suite.NoError(err)

	jsonStruct := struct {
		Headers struct {
			TraceID string `json:"X-Amzn-Trace-Id"` //nolint: tagliatelle
		} `json:"headers"`
	}{}

	suite.NoError(json.Unmarshal(data, &jsonStruct))
	suite.NotEmpty(jsonStruct.Headers.TraceID)
}

func TestProxy(t *testing.T) {
	t.Parallel()
	suite.Run(t, &ProxyTestSuite{})
}

// A WEB-mode stream goes through the same admission as a regular connection:
// a stream from a blocklisted address is closed instead of being served.
func TestProxyServeStreamAppliesBlocklist(t *testing.T) {
	t.Parallel()

	dialer, err := network.NewDefaultDialer(0, 0)
	if err != nil {
		t.Fatal(err)
	}

	ntw, err := network.NewNetwork(dialer, "mtgtest", "1.1.1.1", 0)
	if err != nil {
		t.Fatal(err)
	}

	_, loopback, _ := net.ParseCIDR("127.0.0.0/8")

	blocklist, _ := ipblocklist.NewFireholFromFiles(
		logger.NewNoopLogger(), 1, []files.File{files.NewMem([]*net.IPNet{loopback})}, nil)
	allowlist, _ := ipblocklist.NewFireholFromFiles(
		logger.NewNoopLogger(), 1, []files.File{files.NewMem([]*net.IPNet{cidranger.AllIPv4, cidranger.AllIPv6})}, nil)

	go blocklist.Run(time.Second)
	go allowlist.Run(time.Second)

	proxy, err := mtglib.NewProxy(mtglib.ProxyOpts{
		Secret:          mtglib.GenerateSecret("httpbin.org"),
		Network:         ntw,
		AntiReplayCache: antireplay.NewNoop(),
		IPBlocklist:     blocklist,
		IPAllowlist:     allowlist,
		EventStream:     events.NewNoopStream(),
		Logger:          logger.NewNoopLogger(),
		UseTestDCs:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Shutdown()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close() //nolint: errcheck

	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close() //nolint: errcheck

	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}

	// Wait until the blocklist has loaded the in-memory range.
	deadline := time.Now().Add(2 * time.Second)
	for !blocklist.Contains(net.ParseIP("127.0.0.1")) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	proxy.ServeStream(server.(essentials.Conn)) //nolint: forcetypeassert

	client.SetReadDeadline(time.Now().Add(time.Second)) //nolint: errcheck

	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("a stream from a blocklisted address must be closed")
	} else {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			t.Fatal("a stream from a blocklisted address must be closed, not left open")
		}
	}
}
