package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/dolonet/mtg-multi/internal/config"
	"github.com/dolonet/mtg-multi/mtglib"
)

type secretsUpdater interface {
	UpdateSecrets(secrets map[string]mtglib.Secret) (mtglib.SecretsUpdate, error)
}

// reloadSecrets re-reads the configuration and applies its secrets to a
// running proxy. Other options are not reloaded. On any error the current
// secrets are kept.
func reloadSecrets(readConfig func() (*config.Config, error), proxy secretsUpdater, logger mtglib.Logger) error {
	conf, err := readConfig()
	if err != nil {
		logger.WarningError("reload: cannot read config, keeping current secrets", err)

		return err
	}

	update, err := proxy.UpdateSecrets(conf.GetSecrets())
	if err != nil {
		logger.WarningError("reload: cannot apply secrets, keeping current secrets", err)

		return fmt.Errorf("cannot apply secrets: %w", err)
	}

	logger.
		BindInt("added", update.Added).
		BindInt("removed", update.Removed).
		BindInt("changed", update.Changed).
		BindInt("closed_sessions", update.ClosedSessions).
		// Warning, not Info: by default mtg logs warnings only, and an
		// operator needs to see the result of every reload.
		Warning("reload: secrets have been updated")

	return nil
}

// watchReload reloads secrets on every signal until ctx is done.
func watchReload(
	ctx context.Context,
	signals <-chan os.Signal,
	readConfig func() (*config.Config, error),
	proxy secretsUpdater,
	logger mtglib.Logger,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-signals:
			reloadSecrets(readConfig, proxy, logger) //nolint: errcheck
		}
	}
}
