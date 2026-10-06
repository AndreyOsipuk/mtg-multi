package web_test

import (
	"strings"
	"testing"

	"github.com/mhsanaei/mtg-multi/web"
	"github.com/stretchr/testify/assert"
)

func TestDefaultBridgeRender(t *testing.T) {
	body, csp := web.DefaultBridge{}.Render("proxy.example.com", "TOKEN-VALUE")

	t.Run("token is injected into the script", func(t *testing.T) {
		assert.Contains(t, body, "TOKEN-VALUE")
		assert.NotContains(t, body, "__TOKEN__")
	})

	t.Run("no placeholders are left", func(t *testing.T) {
		assert.NotContains(t, body, "__RUNTIME__")
		assert.NotContains(t, body, "__NONCE__")
	})

	// The policy must allow exactly our script; otherwise a tampered response
	// would run inside the Telegram webview.
	t.Run("policy is bound to the page nonce", func(t *testing.T) {
		_, after, found := strings.Cut(csp, "'nonce-")
		assert.True(t, found)

		nonce, _, found := strings.Cut(after, "'")
		assert.True(t, found)
		assert.NotEmpty(t, nonce)
		assert.Contains(t, body, `nonce="`+nonce+`"`)
		assert.Contains(t, csp, "default-src 'none'")
		assert.Contains(t, csp, "connect-src 'self'")
	})

	t.Run("nonce is single-use", func(t *testing.T) {
		_, second := web.DefaultBridge{}.Render("proxy.example.com", "TOKEN-VALUE")
		assert.NotEqual(t, csp, second)
	})
}
