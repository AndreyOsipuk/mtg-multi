package cli

import (
	"context"
	"errors"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/dolonet/mtg-multi/internal/config"
	"github.com/dolonet/mtg-multi/logger"
	"github.com/dolonet/mtg-multi/mtglib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeSecretsUpdater struct {
	mu      sync.Mutex
	calls   []map[string]mtglib.Secret
	configs []mtglib.SecretConfig
	err     error
}

func (f *fakeSecretsUpdater) ApplySecrets(cfg mtglib.SecretConfig) (mtglib.SecretsUpdate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.calls = append(f.calls, cfg.Secrets)
	f.configs = append(f.configs, cfg)

	return mtglib.SecretsUpdate{Added: len(cfg.Secrets)}, f.err
}

func (f *fakeSecretsUpdater) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return len(f.calls)
}

func TestReloadSecretsApplies(t *testing.T) {
	t.Parallel()

	alice := mtglib.GenerateSecret("example.com")
	bob := mtglib.GenerateSecret("example.com")
	updater := &fakeSecretsUpdater{}

	err := reloadSecrets(func() (*config.Config, error) {
		return &config.Config{Secrets: map[string]mtglib.Secret{"alice": alice, "bob": bob}}, nil
	}, updater, logger.NewNoopLogger())
	require.NoError(t, err)

	require.Len(t, updater.calls, 1)
	assert.Equal(t, map[string]mtglib.Secret{"alice": alice, "bob": bob}, updater.calls[0])
}

func TestReloadSecretsSingleSecret(t *testing.T) {
	t.Parallel()

	secret := mtglib.GenerateSecret("example.com")
	updater := &fakeSecretsUpdater{}

	err := reloadSecrets(func() (*config.Config, error) {
		return &config.Config{Secret: secret}, nil
	}, updater, logger.NewNoopLogger())
	require.NoError(t, err)

	assert.Equal(t, map[string]mtglib.Secret{"default": secret}, updater.calls[0])
}

// A broken config (for example a half-written file) must not reach the proxy.
func TestReloadSecretsKeepsCurrentOnBrokenConfig(t *testing.T) {
	t.Parallel()

	updater := &fakeSecretsUpdater{}

	err := reloadSecrets(func() (*config.Config, error) {
		return nil, errors.New("cannot parse config")
	}, updater, logger.NewNoopLogger())
	require.Error(t, err)
	assert.Zero(t, updater.callCount())
}

func TestReloadSecretsReportsUpdateError(t *testing.T) {
	t.Parallel()

	updater := &fakeSecretsUpdater{err: mtglib.ErrSecretEmpty}

	err := reloadSecrets(func() (*config.Config, error) {
		return &config.Config{Secret: mtglib.GenerateSecret("example.com")}, nil
	}, updater, logger.NewNoopLogger())
	require.ErrorIs(t, err, mtglib.ErrSecretEmpty)
}

func TestWatchReloadOnSignal(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	signals := make(chan os.Signal, 1)
	updater := &fakeSecretsUpdater{}
	done := make(chan struct{})

	go func() {
		defer close(done)
		watchReload(ctx, signals, func() (*config.Config, error) {
			return &config.Config{Secret: mtglib.GenerateSecret("example.com")}, nil
		}, updater, logger.NewNoopLogger())
	}()

	signals <- syscall.SIGHUP
	signals <- syscall.SIGHUP

	require.Eventually(t, func() bool { return updater.callCount() == 2 }, time.Second, 5*time.Millisecond)

	cancel()
	<-done
}

// SIGHUP применяет не только секреты, но и лимиты с рекламными тегами - как
// POST /reload и PUT /secrets.
func TestReloadSecretsAppliesLimitsAndAdTags(t *testing.T) {
	t.Parallel()

	alice := mtglib.GenerateSecret("example.com")
	updater := &fakeSecretsUpdater{}

	conf, err := config.Parse([]byte(`
bind-to = "0.0.0.0:443"
ad-tag = "0123456789abcdef0123456789abcdef"

[secret-limits.alice]
quota = "10GB"
expires = "2030-01-02"

[secrets]
alice = "` + alice.Hex() + `"
`))
	require.NoError(t, err)

	require.NoError(t, reloadSecrets(func() (*config.Config, error) { return conf, nil }, updater, logger.NewNoopLogger()))

	require.Len(t, updater.configs, 1)
	cfg := updater.configs[0]
	require.NotNil(t, cfg.GlobalAdTag)
	assert.Positive(t, cfg.Limits["alice"].QuotaBytes)
	assert.Equal(t, 2030, cfg.Limits["alice"].ExpiresAt.Year())
}

func TestMakeSecretsReloader(t *testing.T) {
	t.Parallel()

	assert.Nil(t, makeSecretsReloader(nil), "simple-run: reload is unsupported")

	secret := mtglib.GenerateSecret("example.com")
	reloader := makeSecretsReloader(func() (*config.Config, error) {
		return &config.Config{Secret: secret}, nil
	})

	cfg, err := reloader()
	require.NoError(t, err)
	assert.Equal(t, map[string]mtglib.Secret{"default": secret}, cfg.Secrets)

	_, err = makeSecretsReloader(func() (*config.Config, error) {
		return nil, errors.New("broken")
	})()
	require.Error(t, err)
}

type fakeWebUpdater struct {
	calls []map[string][]byte
	err   error
}

func (f *fakeWebUpdater) UpdateSecrets(secrets map[string][]byte) error {
	f.calls = append(f.calls, secrets)

	return f.err
}

// Хук WEB-входа отдаёт WEB ключи секретов и пробрасывает его ошибку: при ней
// прокси (mtglib) не подменяет набор - см. TestSecretsHook в mtglib.
func TestWebSecretsHook(t *testing.T) {
	t.Parallel()

	secret := mtglib.GenerateSecret("example.com")
	secrets := map[string]mtglib.Secret{"alice": secret}

	webSide := &fakeWebUpdater{}
	require.NoError(t, webSecretsHook(webSide)(secrets))
	require.Len(t, webSide.calls, 1)
	assert.Equal(t, secret.Key[:], webSide.calls[0]["alice"])

	failing := &fakeWebUpdater{err: errors.New("duplicate capability")}
	require.Error(t, webSecretsHook(failing)(secrets))
}
