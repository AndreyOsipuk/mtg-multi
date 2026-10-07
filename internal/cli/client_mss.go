package cli

import (
	"github.com/dolonet/mtg-multi/internal/config"
	"github.com/dolonet/mtg-multi/mtglib"
	"github.com/dolonet/mtg-multi/network"
)

// clientMSSPlan раскладывает [network] client-mss / client-mss-bulk на два
// механизма:
//   - listenerMSS - TCP_MAXSEG слушающего сокета, действует на всё соединение;
//   - serverHelloMSS - дробление одного ServerHello в пространстве пользователя.
//
// client-mss + bulk > 0: сокет на bulk, ServerHello режется по client-mss.
// client-mss + bulk = 0: всё соединение на client-mss (как iptables TCPMSS).
// client-mss = 0: ничего. Вне Linux параметры игнорируются с предупреждением.
func clientMSSPlan(conf *config.Config, logger mtglib.Logger) (serverHelloMSS, listenerMSS int) {
	handshake, bulk := conf.GetClientMSS()
	if handshake == 0 {
		return 0, 0
	}

	if !network.ListenerMSSSupported {
		logger.Warning("network.client-mss is supported only on Linux; ignored")

		return 0, 0
	}

	if bulk == 0 {
		serverHelloMSS, listenerMSS = 0, int(handshake)
	} else {
		serverHelloMSS, listenerMSS = int(handshake), int(bulk)
	}

	logger.BindInt("server_hello_mss", serverHelloMSS).
		BindInt("listener_mss", listenerMSS).
		Info("client MSS shaping is enabled")

	return serverHelloMSS, listenerMSS
}
