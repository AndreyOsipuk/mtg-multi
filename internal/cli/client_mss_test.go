package cli

import (
	"testing"

	"github.com/dolonet/mtg-multi/logger"
	"github.com/dolonet/mtg-multi/network"
	"github.com/stretchr/testify/assert"
)

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
			conf := parseFeaturesConfig(t, tc.network)

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
