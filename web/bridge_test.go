package web_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/dolonet/mtg-multi/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultBridgeRender(t *testing.T) {
	body, csp := web.DefaultBridge{}.Render("web6.proxy-os.store", "TOKEN-VALUE")

	t.Run("токен попадает в скрипт", func(t *testing.T) {
		assert.Contains(t, body, "TOKEN-VALUE")
		assert.NotContains(t, body, "__TOKEN__")
	})

	t.Run("подстановки не остаются пустыми", func(t *testing.T) {
		assert.NotContains(t, body, "__RUNTIME__")
		assert.NotContains(t, body, "__NONCE__")
	})

	// Политика обязана разрешать ровно наш скрипт: иначе подменённый ответ
	// исполнился бы в вебвью Telegram.
	t.Run("политика привязана к nonce страницы", func(t *testing.T) {
		_, after, found := strings.Cut(csp, "'nonce-")
		assert.True(t, found)

		nonce, _, found := strings.Cut(after, "'")
		assert.True(t, found)
		assert.NotEmpty(t, nonce)
		assert.Contains(t, body, `nonce="`+nonce+`"`)
		assert.Contains(t, csp, "default-src 'none'")
		assert.Contains(t, csp, "connect-src 'self'")
	})

	t.Run("nonce одноразовый", func(t *testing.T) {
		_, second := web.DefaultBridge{}.Render("web6.proxy-os.store", "TOKEN-VALUE")
		assert.NotEqual(t, csp, second)
	})
}

// Без диагностики в странице нет отправителя вовсе: она не обращается к
// диагностике, а это был бы лишний запрос на событие и узнаваемый рисунок.
func TestDefaultBridgeDiag(t *testing.T) {
	off, _ := web.DefaultBridge{}.Render("proxy.example.com", "TOKEN-VALUE")
	assert.NotContains(t, off, "/api/v1/diag")
	assert.NotContains(t, off, "__REPORT__")
	assert.Contains(t, off, "const report = () => {};")

	on, _ := web.DefaultBridge{Diag: true}.Render("proxy.example.com", "TOKEN-VALUE")
	assert.Contains(t, on, "/api/v1/diag")
	assert.NotContains(t, on, "__REPORT__")
}

// The script is adapted from telemt, and the page sent to the client is a
// copy of it: it must carry the same notice as web/bridge/runtime.js, that is
// the copyright, the licence, the note that this is a modified version and
// the list of changes.
func TestDefaultBridgeKeepsLicenceHeader(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("bridge", "runtime.js"))
	require.NoError(t, err)

	var header []string

	for line := range strings.Lines(string(source)) {
		if !strings.HasPrefix(line, "//") {
			break
		}

		header = append(header, line)
	}

	notice := strings.Join(header, "")
	require.Contains(t, notice, "Copyright (c) 2026 Telemt")
	require.Contains(t, notice, "TELEMT LICENSE 3.3")
	require.Contains(t, notice, "This is a modified version, not official Telemt.")
	require.Contains(t, notice, "Changes:")

	for _, diag := range []bool{false, true} {
		body, _ := web.DefaultBridge{Diag: diag}.Render("proxy.example.com", "TOKEN-VALUE")

		assert.Contains(t, body, notice, "diag=%v", diag)
	}
}

// One /up body from the page must fit the server limits and nginx's default
// client_max_body_size (1m), so that a burst of uploads does not depend on
// the proxy settings: a 413 from the proxy or a protocol error ends the
// bridge. One full frame must still fit, or the page could not send it.
func TestDefaultBridgeCapsUpBody(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("bridge", "runtime.js"))
	require.NoError(t, err)

	bytesMatch := regexp.MustCompile(`const MAX_UP_BYTES = (\d+) \* 1024;`).FindSubmatch(source)
	require.NotNil(t, bytesMatch, "the page must cap the size of one /up body")

	framesMatch := regexp.MustCompile(`const MAX_UP_FRAMES = (\d+);`).FindSubmatch(source)
	require.NotNil(t, framesMatch, "the page must cap the frames in one /up body")

	kilobytes, err := strconv.Atoi(string(bytesMatch[1]))
	require.NoError(t, err)

	frames, err := strconv.Atoi(string(framesMatch[1]))
	require.NoError(t, err)

	limit := int64(kilobytes) * 1024

	assert.LessOrEqual(t, limit, web.DefaultServerConfig().MaxBodyBytes)
	assert.LessOrEqual(t, limit, int64(1024*1024), "nginx default client_max_body_size")
	assert.GreaterOrEqual(t, limit, int64(web.HeaderBytes+web.DataChunkBytes))
	assert.LessOrEqual(t, frames, web.DefaultLimits().MaxFramesPerBody)
	assert.Positive(t, frames)
}
