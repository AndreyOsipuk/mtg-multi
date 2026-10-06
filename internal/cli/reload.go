package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/dolonet/mtg-multi/internal/config"
	"github.com/dolonet/mtg-multi/mtglib"
	"github.com/dolonet/mtg-multi/web"
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

// webSecretsUpdater - то, что нужно от WEB-входа при перезагрузке.
type webSecretsUpdater interface {
	UpdateSecrets(secrets map[string][]byte) error
}

// webProxyUpdater применяет секреты и к прокси, и к WEB-входу. WEB идёт первым:
// его таблицы сначала целиком строятся и проверяются, и при ошибке прокси не
// трогаем - обе стороны остаются на прежнем списке.
type webProxyUpdater struct {
	proxy secretsUpdater
	web   webSecretsUpdater
}

func (u webProxyUpdater) UpdateSecrets(secrets map[string]mtglib.Secret) (mtglib.SecretsUpdate, error) {
	// Те же проверки, что в Proxy.UpdateSecrets, - до WEB: иначе WEB ушёл бы на
	// новый список, а прокси отказал и остался на старом.
	if len(secrets) == 0 {
		return mtglib.SecretsUpdate{}, mtglib.ErrSecretEmpty
	}

	for name, secret := range secrets {
		if !secret.Valid() {
			return mtglib.SecretsUpdate{}, fmt.Errorf("invalid secret %q", name)
		}
	}

	if err := u.web.UpdateSecrets(webSecrets(secrets)); err != nil {
		return mtglib.SecretsUpdate{}, fmt.Errorf("web: %w", err)
	}

	return u.proxy.UpdateSecrets(secrets) //nolint: wrapcheck
}

// webSecrets - ключи секретов в виде, который ждёт пакет web.
func webSecrets(secrets map[string]mtglib.Secret) map[string][]byte {
	out := make(map[string][]byte, len(secrets))

	for name, secret := range secrets {
		key := make([]byte, len(secret.Key))
		copy(key, secret.Key[:])
		out[name] = key
	}

	return out
}

var _ webSecretsUpdater = (*web.Server)(nil)
