package config_test

import (
	"testing"

	"github.com/dolonet/mtg-multi/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const overlayMainConfig = `bind-to = "0.0.0.0:443"
prefer-ip = "prefer-ipv4"
api-bind-to = "127.0.0.1:40001"

[domain-fronting]
host = "panel.example.com"

[throttle]
max-connections = 100

[secrets]
"alice@example.com" = "7mqFMMq3P2Tvvt_rPx5qhmFnb29nbGUuY29t"
`

func mergeAndParse(t *testing.T, overlay string) *config.Config {
	t.Helper()

	merged, err := config.MergeOverlay([]byte(overlayMainConfig), []byte(overlay))
	require.NoError(t, err)

	conf, err := config.Parse(merged)
	require.NoError(t, err, string(merged))

	return conf
}

// Ключ основного конфига (его пишет панель) всегда главнее дополнения.
func TestMergeOverlayMainWins(t *testing.T) {
	t.Parallel()

	conf := mergeAndParse(t, `
bind-to = "0.0.0.0:8443"
prefer-ip = "only-ipv6"
concurrency = 4096

[throttle]
max-connections = 5
`)

	require.Len(t, conf.BindTo, 1)
	assert.Equal(t, "0.0.0.0:443", conf.BindTo[0].Get(""))
	assert.Equal(t, "prefer-ipv4", conf.PreferIP.String())
	assert.Equal(t, uint(100), conf.Throttle.MaxConnections.Get(0))
	assert.Equal(t, uint(4096), conf.GetConcurrency(0), "a missing key is taken from the overlay")
}

// Таблицы сливаются глубоко: из [domain-fronting] панели остаётся host, из
// дополнения добавляется port; вложенные таблицы приходят целиком.
func TestMergeOverlayDeepTables(t *testing.T) {
	t.Parallel()

	conf := mergeAndParse(t, `
tolerate-time-skewness = "5s"

[domain-fronting]
host = "overlay.example.com"
port = 8443

[stats.prometheus]
enabled = true
bind-to = "127.0.0.1:3129"

[defense.blocklist]
enabled = false

[defense.anti-replay]
enabled = true
max-size = "1mib"

[network.timeout]
tcp = "5s"
idle = "1m"

[dc-pool]
enabled = true
size = 3

[secured]
enabled = true
`)

	assert.Equal(t, "panel.example.com", conf.GetDomainFrontingHost())
	assert.Equal(t, uint(8443), conf.GetDomainFrontingPort(0))
	assert.True(t, conf.Stats.Prometheus.Enabled.Get(false))
	assert.Equal(t, "127.0.0.1:3129", conf.Stats.Prometheus.BindTo.Get(""))
	assert.True(t, conf.Defense.AntiReplay.Enabled.Get(false))
	assert.False(t, conf.Defense.Blocklist.Enabled.Get(false))
	assert.Equal(t, "5s", conf.Network.Timeout.TCP.String())
	assert.Equal(t, "5s", conf.TolerateTimeSkewness.String())
	require.NotNil(t, conf.DCPool.Enabled)
	assert.True(t, conf.DCPool.Enabled.Value)
	assert.Equal(t, uint(3), conf.DCPool.Size.Get(0))
	require.NotNil(t, conf.Secured.Enabled)
	assert.True(t, conf.Secured.Enabled.Value)
	assert.Equal(t, "127.0.0.1:40001", conf.APIBindTo.Get(""))
}

// Пользователи - только из основного конфига: [secrets], secret,
// [secret-limits] и [secret-ad-tags] из дополнения игнорируются.
func TestMergeOverlayIgnoresUsers(t *testing.T) {
	t.Parallel()

	conf := mergeAndParse(t, `
secret = "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d"

[secret-ad-tags]
"mallory" = "0123456789abcdef0123456789abcdef"

[secret-limits.mallory]
quota = "1GB"

[secret-limits."alice@example.com"]
disabled = true

[secrets]
"mallory" = "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d"
`)

	assert.Equal(t, []string{"alice@example.com"}, keysOf(conf.GetSecrets()))
	assert.Empty(t, conf.SecretAdTags)
	assert.Empty(t, conf.SecretLimits)
	assert.False(t, conf.Secret.Valid(), "a single legacy secret is not taken from the overlay either")
	require.NoError(t, conf.Validate())
}

func TestMergeOverlayBrokenOverlay(t *testing.T) {
	t.Parallel()

	_, err := config.MergeOverlay([]byte(overlayMainConfig), []byte("[stats\nbroken"))
	require.Error(t, err)
}

func keysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}

	return out
}
