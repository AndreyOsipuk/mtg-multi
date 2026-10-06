package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/dolonet/mtg-multi/internal/config"
	"github.com/dolonet/mtg-multi/mtglib"
	"github.com/dolonet/mtg-multi/web"
)

// secretsApplier - единая точка применения набора секретов в прокси
// (mtglib.Proxy.ApplySecrets). Через неё идут и SIGHUP, и POST /reload, и
// PUT /secrets от панели.
type secretsApplier interface {
	ApplySecrets(cfg mtglib.SecretConfig) (mtglib.SecretsUpdate, error)
}

// secretConfigOf - всё, что меняется на лету: секреты, рекламные теги и
// лимиты ([secret-limits]). Остальные опции конфига перезагрузкой не
// применяются.
func secretConfigOf(conf *config.Config) mtglib.SecretConfig {
	return mtglib.SecretConfig{
		Secrets:      conf.GetSecrets(),
		SecretAdTags: conf.GetSecretAdTags(),
		GlobalAdTag:  conf.GetAdTag(),
		Limits:       conf.GetSecretLimits(),
	}
}

// makeSecretsReloader builds the callback Proxy.ReloadSecrets uses to re-read
// the secret set on a POST /reload. It re-reads the same config as SIGHUP
// (readConfig), so both entry points see the same file and overlay. It returns
// nil when there is no config file (simple-run), leaving reload unsupported.
func makeSecretsReloader(readConfig func() (*config.Config, error)) func() (mtglib.SecretConfig, error) {
	if readConfig == nil {
		return nil
	}

	return func() (mtglib.SecretConfig, error) {
		conf, err := readConfig()
		if err != nil {
			return mtglib.SecretConfig{}, err
		}

		return secretConfigOf(conf), nil
	}
}

// reloadSecrets re-reads the configuration and applies its secrets, tags and
// limits to a running proxy. Other options are not reloaded. On any error the
// current secrets are kept.
func reloadSecrets(readConfig func() (*config.Config, error), proxy secretsApplier, logger mtglib.Logger) error {
	conf, err := readConfig()
	if err != nil {
		logger.WarningError("reload: cannot read config, keeping current secrets", err)

		return err
	}

	update, err := proxy.ApplySecrets(secretConfigOf(conf))
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
	proxy secretsApplier,
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

// webSecretsHook - хук для Proxy.SetSecretsHook: прокси вызывает его при
// любом применении (SIGHUP, POST /reload, PUT /secrets) после проверок и до
// подмены своего набора. WEB идёт первым: его таблицы сначала целиком
// строятся и проверяются, и при ошибке прокси не трогаем - обе стороны
// остаются на прежнем списке.
func webSecretsHook(w webSecretsUpdater) func(map[string]mtglib.Secret) error {
	return func(secrets map[string]mtglib.Secret) error {
		if err := w.UpdateSecrets(webSecrets(secrets)); err != nil {
			return fmt.Errorf("web: %w", err)
		}

		return nil
	}
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

var _ secretsApplier = (*mtglib.Proxy)(nil)
