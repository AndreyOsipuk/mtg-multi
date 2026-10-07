package web_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mhsanaei/mtg-multi/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// Without diagnostics the page carries no reporter at all: it never calls the
// diagnostic endpoint, which would be one more request per event and a
// recognizable pattern.
func TestDefaultBridgeDiag(t *testing.T) {
	off, _ := web.DefaultBridge{}.Render("proxy.example.com", "TOKEN-VALUE")
	assert.NotContains(t, off, "/api/v1/diag")
	assert.NotContains(t, off, "__REPORT__")
	assert.Contains(t, off, "const report = () => {};")

	on, _ := web.DefaultBridge{Diag: true}.Render("proxy.example.com", "TOKEN-VALUE")
	assert.Contains(t, on, "/api/v1/diag")
	assert.NotContains(t, on, "__REPORT__")
}

// The licence header of the adapted script stays in the source, but the page
// sent to the client does not carry it, nor the name of the project.
func TestDefaultBridgeStripsLicenceHeader(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("bridge", "runtime.js"))
	require.NoError(t, err)
	require.Contains(t, string(source), "Portions of this file are adapted from telemt")

	for _, diag := range []bool{false, true} {
		body, _ := web.DefaultBridge{Diag: diag}.Render("proxy.example.com", "TOKEN-VALUE")

		assert.NotContains(t, strings.ToLower(body), "telemt")
		assert.NotContains(t, body, "Portions of this file")
		assert.NotContains(t, body, "LICENSE")
		// The code itself is intact.
		assert.Contains(t, body, "'use strict';")
		assert.Contains(t, body, "tproxy-init")
		assert.Contains(t, body, "})();")
	}
}
