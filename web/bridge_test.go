package web_test

import (
	"strings"
	"testing"

	"github.com/dolonet/mtg-multi/web"
	"github.com/stretchr/testify/assert"
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
