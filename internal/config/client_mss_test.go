package config_test

import (
	"testing"

	"github.com/dolonet/mtg-multi/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parseClientMSS(t *testing.T, network string) (*config.Config, error) {
	t.Helper()

	conf, err := config.Parse([]byte(`bind-to = "0.0.0.0:443"
secret = "7mqFMMq3P2Tvvt_rPx5qhmFnb29nbGUuY29t"

[network]
` + network))
	require.NoError(t, err)

	return conf, conf.Validate()
}

func TestClientMSS(t *testing.T) {
	cases := []struct {
		name          string
		network       string
		wantHandshake uint
		wantBulk      uint
	}{
		{name: "не задано", network: "", wantHandshake: 0, wantBulk: 0},
		{name: "явный ноль", network: "client-mss = 0", wantHandshake: 0, wantBulk: 0},
		{name: "bulk по умолчанию 1400", network: "client-mss = 92", wantHandshake: 92, wantBulk: 1400},
		{name: "свой bulk", network: "client-mss = 92\nclient-mss-bulk = 1200", wantHandshake: 92, wantBulk: 1200},
		{name: "bulk 0 - вся сессия на client-mss", network: "client-mss = 92\nclient-mss-bulk = 0", wantHandshake: 92, wantBulk: 0},
		{name: "bulk без client-mss ни на что не влияет", network: "client-mss-bulk = 1400", wantHandshake: 0, wantBulk: 0},
		{name: "нижняя граница", network: "client-mss = 48", wantHandshake: 48, wantBulk: 1400},
		{name: "верхние границы", network: "client-mss = 1460\nclient-mss-bulk = 65495", wantHandshake: 1460, wantBulk: 65495},
		{name: "bulk нижняя граница", network: "client-mss = 92\nclient-mss-bulk = 536", wantHandshake: 92, wantBulk: 536},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conf, err := parseClientMSS(t, tc.network)
			require.NoError(t, err)

			handshake, bulk := conf.GetClientMSS()
			assert.Equal(t, tc.wantHandshake, handshake)
			assert.Equal(t, tc.wantBulk, bulk)
		})
	}
}

func TestClientMSSValidation(t *testing.T) {
	cases := []struct {
		name    string
		network string
		wantErr string
	}{
		{name: "client-mss меньше 48", network: "client-mss = 47", wantErr: "network.client-mss must be 0 or 48..1460"},
		{name: "client-mss больше 1460", network: "client-mss = 1461", wantErr: "network.client-mss must be 0 or 48..1460"},
		{name: "bulk меньше 536", network: "client-mss = 92\nclient-mss-bulk = 535", wantErr: "network.client-mss-bulk must be 0 or 536..65495"},
		{name: "bulk больше 65495", network: "client-mss = 92\nclient-mss-bulk = 65496", wantErr: "network.client-mss-bulk must be 0 or 536..65495"},
		{name: "bulk не больше client-mss", network: "client-mss = 1400\nclient-mss-bulk = 1400", wantErr: "must be greater than network.client-mss"},
		{name: "bulk 0 и client-mss ниже минимума ядра", network: "client-mss = 60\nclient-mss-bulk = 0", wantErr: "at least 88"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseClientMSS(t, tc.network)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestClientMSSNotANumber(t *testing.T) {
	_, err := config.Parse([]byte(`bind-to = "0.0.0.0:443"
secret = "7mqFMMq3P2Tvvt_rPx5qhmFnb29nbGUuY29t"

[network]
client-mss = "tspu"
`))
	assert.Error(t, err)
}

// Панель пишет урезанный конфиг, client-mss приходит из MTG_CONFIG_OVERLAY:
// раздел network сливается глубоко, явный 0 у bulk не теряется.
func TestClientMSSFromOverlay(t *testing.T) {
	conf := mergeAndParse(t, `[network]
client-mss = 92
client-mss-bulk = 0
`)
	require.NoError(t, conf.Validate())

	handshake, bulk := conf.GetClientMSS()
	assert.Equal(t, uint(92), handshake)
	assert.Equal(t, uint(0), bulk)

	conf = mergeAndParse(t, `[network]
client-mss = 92
`)
	require.NoError(t, conf.Validate())

	handshake, bulk = conf.GetClientMSS()
	assert.Equal(t, uint(92), handshake)
	assert.Equal(t, uint(config.DefaultClientMSSBulk), bulk)
}
