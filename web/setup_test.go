package web_test

import (
	"testing"

	"github.com/dolonet/mtg-multi/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetupFromEnv(t *testing.T) {
	secrets := map[string][]byte{"petya_1": []byte("0123456789abcdef")}

	t.Run("без MTG_WEB_BIND режим выключен", func(t *testing.T) {
		srv, bind, err := web.SetupFromEnv(secrets, nil)
		require.NoError(t, err)
		assert.Nil(t, srv)
		assert.Empty(t, bind)
	})

	// HTTP-вход говорит открытым текстом: снаружи это был бы прокси без TLS и
	// без маскировки. TLS терминирует nginx, поэтому только loopback.
	t.Run("наружу выставить нельзя", func(t *testing.T) {
		t.Setenv("MTG_WEB_BIND", "0.0.0.0:18080")
		t.Setenv("MTG_WEB_HOST", "web6.proxy-os.store")

		_, _, err := web.SetupFromEnv(secrets, nil)
		assert.ErrorIs(t, err, web.ErrPublicBind)
	})

	t.Run("без домена не поднимается", func(t *testing.T) {
		t.Setenv("MTG_WEB_BIND", "127.0.0.1:18080")

		_, _, err := web.SetupFromEnv(secrets, nil)
		assert.ErrorIs(t, err, web.ErrNoHost)
	})

	t.Run("без секретов не поднимается", func(t *testing.T) {
		t.Setenv("MTG_WEB_BIND", "127.0.0.1:18080")
		t.Setenv("MTG_WEB_HOST", "web6.proxy-os.store")

		_, _, err := web.SetupFromEnv(map[string][]byte{}, nil)
		assert.ErrorIs(t, err, web.ErrNoSecrets)
	})

	t.Run("собирается и выдаёт мост своему клиенту", func(t *testing.T) {
		t.Setenv("MTG_WEB_BIND", "127.0.0.1:18080")
		t.Setenv("MTG_WEB_HOST", "web6.proxy-os.store")

		srv, bind, err := web.SetupFromEnv(secrets, func(*web.Stream) {})
		require.NoError(t, err)
		require.NotNil(t, srv)

		t.Cleanup(srv.Close)
		assert.Equal(t, "127.0.0.1:18080", bind)
	})
}

// Профиль считается из того же секрета, что и обычный MTProto: WEB - это
// другой транспорт для того же пользователя, а не отдельная учётная запись.
func TestBuildProfilesUsesSameSecrets(t *testing.T) {
	secret := []byte("0123456789abcdef")

	profiles, err := web.BuildProfiles(map[string][]byte{"petya_1": secret}, "web6.proxy-os.store", web.SecretModeDD)
	require.NoError(t, err)
	require.Len(t, profiles, 1)

	expected, err := web.DeriveCapability(web.ClientSecret(secret, web.SecretModeDD), "web6.proxy-os.store")
	require.NoError(t, err)

	assert.Equal(t, "petya_1", profiles[0].User)
	assert.Equal(t, expected, profiles[0].Capability)
}
