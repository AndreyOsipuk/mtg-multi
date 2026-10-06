package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dolonet/mtg-multi/antireplay"
	"github.com/dolonet/mtg-multi/events"
	"github.com/dolonet/mtg-multi/internal/config"
	"github.com/dolonet/mtg-multi/internal/utils"
	"github.com/dolonet/mtg-multi/ipblocklist"
	"github.com/dolonet/mtg-multi/logger"
	"github.com/dolonet/mtg-multi/mtglib"
	"github.com/dolonet/mtg-multi/network"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Контракт с панелью 3X-UI v3.9 (internal/mtproto/manager.go): панель ходит в
// API mtg на api-bind-to с заголовком Authorization: Bearer <api-token> -
// PUT /secrets ({"secrets":{имя:{secret,ad_tag,quota,expires}}}) ждёт 200,
// GET /stats читает users{connections,bytes_in,bytes_out}, POST
// /secrets/{имя}/reset-quota, POST /reload. Тест поднимает настоящий прокси с
// настоящим API, как это делает `mtg run`.

const panelTestToken = "0123456789abcdef0123456789abcdef"

type panelTestNode struct {
	t          *testing.T
	proxy      *mtglib.Proxy
	base       string
	configPath string
}

func freeLoopbackAddr(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	addr := ln.Addr().String()
	require.NoError(t, ln.Close())

	return addr
}

func writePanelConfig(t *testing.T, path, apiAddr, body string) {
	t.Helper()

	data := `bind-to = "127.0.0.1:1"
api-bind-to = "` + apiAddr + `"
api-token = "` + panelTestToken + `"
` + body

	tmp := path + ".tmp"
	require.NoError(t, os.WriteFile(tmp, []byte(data), 0o600))
	require.NoError(t, os.Rename(tmp, path))
}

// startPanelTestNode строит прокси так же, как runProxy: опции из конфига,
// reloader из того же readConfig, что у SIGHUP.
func startPanelTestNode(t *testing.T, body string) *panelTestNode {
	t.Helper()

	apiAddr := freeLoopbackAddr(t)
	path := filepath.Join(t.TempDir(), "config.toml")
	writePanelConfig(t, path, apiAddr, body)

	readConfig := func() (*config.Config, error) { return utils.ReadConfig(path) }

	conf, err := readConfig()
	require.NoError(t, err)

	dialer, err := network.NewDefaultDialer(0, 0)
	require.NoError(t, err)

	ntw, err := network.NewNetwork(dialer, "mtgtest", "1.1.1.1", 0)
	require.NoError(t, err)

	proxy, err := mtglib.NewProxy(mtglib.ProxyOpts{
		Logger:          logger.NewNoopLogger(),
		Network:         ntw,
		AntiReplayCache: antireplay.NewNoop(),
		IPBlocklist:     ipblocklist.NewNoop(),
		IPAllowlist:     ipblocklist.NewNoop(),
		EventStream:     events.NewNoopStream(),
		Secrets:         conf.GetSecrets(),
		APIBindTo:       conf.APIBindTo.Get(""),
		APIToken:        conf.GetAPIToken(),
		SecretsReloader: makeSecretsReloader(readConfig),
		GlobalAdTag:     conf.GetAdTag(),
		SecretAdTags:    conf.GetSecretAdTags(),
		SecretLimits:    conf.GetSecretLimits(),
	})
	require.NoError(t, err)
	t.Cleanup(proxy.Shutdown)

	node := &panelTestNode{t: t, proxy: proxy, base: "http://" + apiAddr, configPath: path}

	require.Eventually(t, func() bool {
		code, _ := node.do(http.MethodGet, "/stats", "", panelTestToken)

		return code == http.StatusOK
	}, 5*time.Second, 20*time.Millisecond, "management API did not start")

	return node
}

func (n *panelTestNode) do(method, path, body, token string) (int, []byte) {
	req, err := http.NewRequest(method, n.base+path, strings.NewReader(body))
	require.NoError(n.t, err)

	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close() //nolint: errcheck

	data, err := io.ReadAll(resp.Body)
	require.NoError(n.t, err)

	return resp.StatusCode, data
}

type panelStats struct {
	Users map[string]struct {
		Connections *int64 `json:"connections"`
		BytesIn     *int64 `json:"bytes_in"`
		BytesOut    *int64 `json:"bytes_out"`
	} `json:"users"`
	SecretsSHA256 string `json:"secrets_sha256"`
}

func (n *panelTestNode) stats() panelStats {
	code, body := n.do(http.MethodGet, "/stats", "", panelTestToken)
	require.Equal(n.t, http.StatusOK, code, string(body))

	var out panelStats
	require.NoError(n.t, json.Unmarshal(body, &out))

	return out
}

func (n *panelTestNode) secrets() string {
	code, body := n.do(http.MethodGet, "/secrets", "", panelTestToken)
	require.Equal(n.t, http.StatusOK, code, string(body))

	return string(body)
}

// expectedDigest - то же, что считает синк: sha256 от "имя=секрет(hex)" по
// именам через \n.
func expectedDigest(secrets map[string]mtglib.Secret, names ...string) string {
	lines := make([]string, len(names))
	for i, name := range names {
		lines[i] = name + "=" + secrets[name].Hex()
	}

	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))

	return hex.EncodeToString(sum[:])
}

func TestPanelContract(t *testing.T) {
	t.Parallel()

	secrets := map[string]mtglib.Secret{
		"alice@example.com": mtglib.GenerateSecret("example.com"),
		"bob@example.com":   mtglib.GenerateSecret("example.com"),
	}

	node := startPanelTestNode(t, `
[secrets]
"alice@example.com" = "`+secrets["alice@example.com"].Hex()+`"
`)

	initial := node.stats()
	assert.Equal(t, expectedDigest(secrets, "alice@example.com"), initial.SecretsSHA256)

	user, ok := initial.Users["alice@example.com"]
	require.True(t, ok)
	require.NotNil(t, user.Connections, "panel reads users.connections")
	require.NotNil(t, user.BytesIn, "panel reads users.bytes_in")
	require.NotNil(t, user.BytesOut, "panel reads users.bytes_out")

	// Ровно то, что шлёт панель (secretsPayload): quota в байтах с "B",
	// expires в RFC3339, ad_tag опционален.
	put := `{"secrets":{` +
		`"alice@example.com":{"secret":"` + secrets["alice@example.com"].Hex() + `","ad_tag":"0123456789abcdef0123456789abcdef"},` +
		`"bob@example.com":{"secret":"` + secrets["bob@example.com"].Hex() + `","quota":"1073741824B","expires":"2030-01-02T03:04:05Z"}}}`

	t.Run("without token", func(t *testing.T) {
		code, _ := node.do(http.MethodPut, "/secrets", put, "")
		assert.Equal(t, http.StatusUnauthorized, code)

		code, _ = node.do(http.MethodPut, "/secrets", put, "wrong")
		assert.Equal(t, http.StatusUnauthorized, code)

		code, _ = node.do(http.MethodGet, "/stats", "", "")
		assert.Equal(t, http.StatusUnauthorized, code)

		assert.Equal(t, initial.SecretsSHA256, node.stats().SecretsSHA256, "rejected PUT must not change the set")
	})

	code, body := node.do(http.MethodPut, "/secrets", put, panelTestToken)
	require.Equal(t, http.StatusOK, code, string(body))

	after := node.stats()
	assert.Equal(t, expectedDigest(secrets, "alice@example.com", "bob@example.com"), after.SecretsSHA256)
	assert.NotEqual(t, initial.SecretsSHA256, after.SecretsSHA256)
	assert.Contains(t, after.Users, "bob@example.com")

	code, body = node.do(http.MethodPost, "/secrets/bob@example.com/reset-quota", "", panelTestToken)
	assert.Equal(t, http.StatusOK, code, string(body))

	code, _ = node.do(http.MethodPost, "/secrets/nobody/reset-quota", "", panelTestToken)
	assert.Equal(t, http.StatusNotFound, code)

	// POST /reload перечитывает файл, в котором по-прежнему только alice.
	code, body = node.do(http.MethodPost, "/reload", "", panelTestToken)
	require.Equal(t, http.StatusOK, code, string(body))

	reloaded := node.stats()
	assert.Equal(t, initial.SecretsSHA256, reloaded.SecretsSHA256)
	assert.NotContains(t, reloaded.Users, "bob@example.com", "a removed user is not kept in stats")
}

// SIGHUP (перечитать файл), POST /reload и PUT /secrets от панели - три входа
// в один механизм, и состояние после них должно совпадать: набор, теги,
// лимиты и отпечаток.
func TestSighupAndPutSecretsReachTheSameState(t *testing.T) {
	t.Parallel()

	alice := mtglib.GenerateSecret("example.com")
	bob := mtglib.GenerateSecret("example.com")
	carol := mtglib.GenerateSecret("example.com")

	initial := `
[secrets]
alice = "` + alice.Hex() + `"
carol = "` + carol.Hex() + `"
`
	// Новый набор: carol удалена, bob добавлен с лимитами, у alice свой тег.
	desiredFile := `
[secret-ad-tags]
alice = "0123456789abcdef0123456789abcdef"

[secret-limits.bob]
quota = "1073741824B"
expires = "2030-01-02T03:04:05Z"

[secrets]
alice = "` + alice.Hex() + `"
bob = "` + bob.Hex() + `"
`
	desiredPut := `{"secrets":{` +
		`"alice":{"secret":"` + alice.Hex() + `","ad_tag":"0123456789abcdef0123456789abcdef"},` +
		`"bob":{"secret":"` + bob.Hex() + `","quota":"1073741824B","expires":"2030-01-02T03:04:05Z"}}}`

	viaPut := startPanelTestNode(t, initial)
	code, body := viaPut.do(http.MethodPut, "/secrets", desiredPut, panelTestToken)
	require.Equal(t, http.StatusOK, code, string(body))

	viaSighup := startPanelTestNode(t, initial)
	writePanelConfig(t, viaSighup.configPath, strings.TrimPrefix(viaSighup.base, "http://"), desiredFile)
	require.NoError(t, reloadSecrets(func() (*config.Config, error) {
		return utils.ReadConfig(viaSighup.configPath)
	}, viaSighup.proxy, logger.NewNoopLogger()))

	viaReload := startPanelTestNode(t, initial)
	writePanelConfig(t, viaReload.configPath, strings.TrimPrefix(viaReload.base, "http://"), desiredFile)
	code, body = viaReload.do(http.MethodPost, "/reload", "", panelTestToken)
	require.Equal(t, http.StatusOK, code, string(body))

	want := viaPut.secrets()
	assert.Contains(t, want, `"effective_ad_tag":"0123456789abcdef0123456789abcdef"`)
	assert.Contains(t, want, `"quota":1073741824`)
	assert.NotContains(t, want, `"carol"`)

	assert.JSONEq(t, want, viaSighup.secrets(), "SIGHUP and PUT /secrets diverged")
	assert.JSONEq(t, want, viaReload.secrets(), "POST /reload and PUT /secrets diverged")

	digest := viaPut.stats().SecretsSHA256
	assert.Equal(t, digest, viaSighup.stats().SecretsSHA256)
	assert.Equal(t, digest, viaReload.stats().SecretsSHA256)

	for _, node := range []*panelTestNode{viaPut, viaSighup, viaReload} {
		users := node.stats().Users
		assert.Contains(t, users, "bob")
		assert.NotContains(t, users, "carol")
	}
}
