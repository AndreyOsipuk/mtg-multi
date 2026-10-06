package cli

import (
	"os"
	"strings"

	"github.com/dolonet/mtg-multi/internal/config"
)

// Наши возможности (secured/dd, тёплый пул DC, шейпинг dd) включаются
// разделами [secured] и [dc-pool] в конфиге. Панель 3X-UI таких разделов не
// пишет, поэтому запасной путь - окружение, которое mtg наследует от x-ui.
// Порядок: ключ в конфиге (с учётом MTG_CONFIG_OVERLAY) > окружение > значение
// по умолчанию. Умолчания - как на наших нодах до слияния: secured и пул
// включены, шейпинг выключен.

// envSwitch читает переключатель: 1/on/true/yes или 0/off/false/no. Пусто или
// мусор - ok=false, решает умолчание.
func envSwitch(name string) (value, ok bool) {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "on", "true", "yes":
		return true, true
	case "0", "off", "false", "no":
		return false, true
	}

	return false, false
}

func featureSwitch(fromConfig *config.TypeBool, env string, defaultValue bool) bool {
	if fromConfig != nil {
		return fromConfig.Value
	}

	if value, ok := envSwitch(env); ok {
		return value
	}

	return defaultValue
}

// securedEnabled - приём secured (dd): [secured] enabled > MTG_SECURED > вкл.
func securedEnabled(conf *config.Config) bool {
	return featureSwitch(conf.Secured.Enabled, "MTG_SECURED", true)
}

// ddShapeEnabled - шейпинг первого dd-ответа: [secured] shape > MTG_DD_SHAPE >
// выкл.
func ddShapeEnabled(conf *config.Config) bool {
	return featureSwitch(conf.Secured.Shape, "MTG_DD_SHAPE", false)
}

// dcPoolEnabled - тёплый пул DC: [dc-pool] enabled > MTG_DC_POOL > вкл.
func dcPoolEnabled(conf *config.Config) bool {
	return featureSwitch(conf.DCPool.Enabled, "MTG_DC_POOL", true)
}

// dcPoolSize - [dc-pool] size > MTG_DC_POOL_SIZE > 0 (умолчание mtglib).
func dcPoolSize(conf *config.Config) uint {
	if size := conf.DCPool.Size.Get(0); size != 0 {
		return size
	}

	return envUint("MTG_DC_POOL_SIZE")
}

// dcPoolDCs - [dc-pool] dcs > MTG_DC_POOL_DCS > nil (умолчание mtglib).
func dcPoolDCs(conf *config.Config) []int {
	if len(conf.DCPool.DCs) > 0 {
		return conf.DCPool.DCs
	}

	return envInts("MTG_DC_POOL_DCS")
}
