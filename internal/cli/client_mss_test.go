package cli

import (
	"testing"

	"github.com/dolonet/mtg-multi/internal/config"
	"github.com/dolonet/mtg-multi/logger"
	"github.com/dolonet/mtg-multi/network"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parseClientMSSConfig(t *testing.T, body string) *config.Config {
	t.Helper()

	conf, err := config.Parse([]byte(`bind-to = "0.0.0.0:443"
secret = "7mqFMMq3P2Tvvt_rPx5qhmFnb29nbGUuY29t"
` + body))
	require.NoError(t, err)
	require.NoError(t, conf.Validate())

	return conf
}

func TestClientMSSPlan(t *testing.T) {
	cases := []struct {
		name         string
		network      string
		wantHello    int
		wantListener int
	}{
		{name: "выключено", network: "", wantHello: 0, wantListener: 0},
		{name: "ServerHello по 92, сессия 1400", network: "[network]\nclient-mss = 92\n", wantHello: 92, wantListener: 1400},
		{name: "свой bulk", network: "[network]\nclient-mss = 92\nclient-mss-bulk = 1200\n", wantHello: 92, wantListener: 1200},
		{name: "вся сессия на 92", network: "[network]\nclient-mss = 92\nclient-mss-bulk = 0\n", wantHello: 0, wantListener: 92},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conf := parseClientMSSConfig(t, tc.network)

			hello, listener := clientMSSPlan(conf, logger.NewNoopLogger())

			if !network.ListenerMSSSupported {
				assert.Zero(t, hello)
				assert.Zero(t, listener)

				return
			}

			assert.Equal(t, tc.wantHello, hello)
			assert.Equal(t, tc.wantListener, listener)
		})
	}
}
