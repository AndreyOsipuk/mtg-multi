package cli

import (
	"testing"

	"github.com/dolonet/mtg-multi/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parseFeaturesConfig(t *testing.T, body string) *config.Config {
	t.Helper()

	conf, err := config.Parse([]byte(`bind-to = "0.0.0.0:443"
secret = "7mqFMMq3P2Tvvt_rPx5qhmFnb29nbGUuY29t"
` + body))
	require.NoError(t, err)

	return conf
}

// Без раздела и без окружения - как на нодах до слияния: secured и пул
// включены, шейпинг выключен.
func TestFeaturesDefaults(t *testing.T) {
	for _, env := range []string{"MTG_SECURED", "MTG_DC_POOL", "MTG_DD_SHAPE", "MTG_DC_POOL_SIZE", "MTG_DC_POOL_DCS"} {
		t.Setenv(env, "")
	}

	conf := parseFeaturesConfig(t, "")

	assert.True(t, securedEnabled(conf))
	assert.True(t, dcPoolEnabled(conf))
	assert.False(t, ddShapeEnabled(conf))
	assert.Zero(t, dcPoolSize(conf))
	assert.Nil(t, dcPoolDCs(conf))
}

// Панель разделов не пишет - работает окружение, унаследованное от x-ui.
func TestFeaturesFromEnvironment(t *testing.T) {
	t.Setenv("MTG_SECURED", "0")
	t.Setenv("MTG_DC_POOL", "off")
	t.Setenv("MTG_DD_SHAPE", "1")
	t.Setenv("MTG_DC_POOL_SIZE", "4")
	t.Setenv("MTG_DC_POOL_DCS", "2,-2")

	conf := parseFeaturesConfig(t, "")

	assert.False(t, securedEnabled(conf))
	assert.False(t, dcPoolEnabled(conf))
	assert.True(t, ddShapeEnabled(conf))
	assert.Equal(t, uint(4), dcPoolSize(conf))
	assert.Equal(t, []int{2, -2}, dcPoolDCs(conf))

	t.Setenv("MTG_SECURED", "1")
	t.Setenv("MTG_DC_POOL", "on")

	assert.True(t, securedEnabled(conf))
	assert.True(t, dcPoolEnabled(conf))
}

// Раздел конфига главнее окружения, в том числе явное enabled = false.
func TestFeaturesConfigWinsOverEnvironment(t *testing.T) {
	t.Setenv("MTG_SECURED", "1")
	t.Setenv("MTG_DC_POOL", "1")
	t.Setenv("MTG_DD_SHAPE", "0")
	t.Setenv("MTG_DC_POOL_SIZE", "4")
	t.Setenv("MTG_DC_POOL_DCS", "2,-2")

	conf := parseFeaturesConfig(t, `
[secured]
enabled = false
shape = true

[dc-pool]
enabled = false
size = 3
dcs = [4, -4, 203]
`)

	assert.False(t, securedEnabled(conf))
	assert.True(t, ddShapeEnabled(conf))
	assert.False(t, dcPoolEnabled(conf))
	assert.Equal(t, uint(3), dcPoolSize(conf))
	assert.Equal(t, []int{4, -4, 203}, dcPoolDCs(conf))

	conf = parseFeaturesConfig(t, `
[secured]
enabled = true

[dc-pool]
enabled = true
`)
	t.Setenv("MTG_SECURED", "0")
	t.Setenv("MTG_DC_POOL", "0")

	assert.True(t, securedEnabled(conf))
	assert.True(t, dcPoolEnabled(conf))
}

func TestEnvSwitchGarbageFallsBackToDefault(t *testing.T) {
	t.Setenv("MTG_SECURED", "maybe")

	conf := parseFeaturesConfig(t, "")

	assert.True(t, securedEnabled(conf))
}
