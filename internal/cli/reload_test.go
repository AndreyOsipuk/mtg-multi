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
	mu    sync.Mutex
	calls []map[string]mtglib.Secret
	err   error
}

func (f *fakeSecretsUpdater) UpdateSecrets(secrets map[string]mtglib.Secret) (mtglib.SecretsUpdate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.calls = append(f.calls, secrets)

	return mtglib.SecretsUpdate{Added: len(secrets)}, f.err
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

type fakeWebUpdater struct {
	calls []map[string][]byte
	err   error
}

func (f *fakeWebUpdater) UpdateSecrets(secrets map[string][]byte) error {
	f.calls = append(f.calls, secrets)

	return f.err
}

// WEB проверяется первым: если его таблицы не собрались, прокси остаётся на
// прежнем списке, иначе обычный вход и WEB разошлись бы по пользователям.
func TestWebProxyUpdater(t *testing.T) {
	t.Parallel()

	secret := mtglib.GenerateSecret("example.com")
	secrets := map[string]mtglib.Secret{"alice": secret}

	t.Run("both are updated", func(t *testing.T) {
		t.Parallel()

		proxy := &fakeSecretsUpdater{}
		webSide := &fakeWebUpdater{}

		_, err := webProxyUpdater{proxy: proxy, web: webSide}.UpdateSecrets(secrets)
		require.NoError(t, err)

		require.Len(t, webSide.calls, 1)
		assert.Equal(t, secret.Key[:], webSide.calls[0]["alice"])
		assert.Equal(t, 1, proxy.callCount())
	})

	t.Run("web error keeps the proxy untouched", func(t *testing.T) {
		t.Parallel()

		proxy := &fakeSecretsUpdater{}
		webSide := &fakeWebUpdater{err: errors.New("duplicate capability")}

		_, err := webProxyUpdater{proxy: proxy, web: webSide}.UpdateSecrets(secrets)
		require.Error(t, err)
		assert.Zero(t, proxy.callCount())
	})
}
