package utils_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dolonet/mtg-multi/internal/config"
	"github.com/dolonet/mtg-multi/internal/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Тесты меняют окружение процесса, поэтому без t.Parallel.

func writeOverlay(t *testing.T, body string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "overlay.toml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))

	return path
}

func TestReadConfigWithoutOverlayIsUnchanged(t *testing.T) {
	t.Setenv(config.EnvConfigOverlay, "")

	conf, err := utils.ReadConfig(filepath.Join("testdata", "minimal.toml"))
	require.NoError(t, err)

	assert.Equal(t, "0.0.0.0:80", conf.BindTo[0].Get(""))
	assert.False(t, conf.Stats.Prometheus.Enabled.Get(false))
	assert.Nil(t, conf.DCPool.Enabled)
}

func TestReadConfigAppliesOverlay(t *testing.T) {
	t.Setenv(config.EnvConfigOverlay, writeOverlay(t, `
bind-to = "0.0.0.0:8443"
secret = "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d"

[stats.prometheus]
enabled = true
bind-to = "127.0.0.1:3129"

[dc-pool]
enabled = false
`))

	conf, err := utils.ReadConfig(filepath.Join("testdata", "minimal.toml"))
	require.NoError(t, err)

	assert.Equal(t, "0.0.0.0:80", conf.BindTo[0].Get(""), "the main config wins")
	assert.Equal(t, "7mqFMMq3P2Tvvt_rPx5qhmFnb29nbGUuY29t", conf.Secret.Base64(), "users come from the main config only")
	assert.True(t, conf.Stats.Prometheus.Enabled.Get(false))
	assert.Equal(t, "127.0.0.1:3129", conf.Stats.Prometheus.BindTo.Get(""))
	require.NotNil(t, conf.DCPool.Enabled)
	assert.False(t, conf.DCPool.Enabled.Value)
}

// Отсутствующий или битый файл дополнения - ошибка чтения конфига: на старте
// она фатальна, при перезагрузке текущий набор сохраняется.
func TestReadConfigOverlayErrors(t *testing.T) {
	t.Setenv(config.EnvConfigOverlay, filepath.Join(t.TempDir(), "absent.toml"))

	_, err := utils.ReadConfig(filepath.Join("testdata", "minimal.toml"))
	require.ErrorContains(t, err, config.EnvConfigOverlay)

	t.Setenv(config.EnvConfigOverlay, writeOverlay(t, "[stats\nbroken"))

	_, err = utils.ReadConfig(filepath.Join("testdata", "minimal.toml"))
	require.ErrorContains(t, err, config.EnvConfigOverlay)
}
