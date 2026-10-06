package cli

import (
	"fmt"

	"github.com/dolonet/mtg-multi/internal/config"
	"github.com/dolonet/mtg-multi/internal/utils"
)

type Run struct {
	ConfigPath string `kong:"arg,required,type='existingfile',help='Path to the configuration file.',name='config-path'"` //nolint: lll
}

func (r *Run) Run(cli *CLI, version string) error {
	// SIGHUP ловим первым делом: по умолчанию Go завершает процесс по нему, а
	// systemd считает такой выход чистым и не перезапускает. Запуск занимает
	// секунды (DNS-проверки, определение IP), и сигнал от синка в это окно
	// убил бы mtg. Пришедший до готовности сигнал применится сразу после старта.
	reloadSignals := utils.ReloadSignals()

	conf, err := utils.ReadConfig(r.ConfigPath)
	if err != nil {
		return fmt.Errorf("cannot init config: %w", err)
	}

	return runProxy(conf, version, reloadSignals, func() (*config.Config, error) {
		return utils.ReadConfig(r.ConfigPath)
	})
}
