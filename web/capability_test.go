package web_test

import (
	"encoding/hex"
	"testing"

	"github.com/dolonet/mtg-multi/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test vectors taken from telemt (https://github.com/telemt/telemt),
// Copyright (c) 2026 Telemt, licensed under the TELEMT LICENSE 3.3; see
// web/LICENSE.telemt.
//
// Эталонные векторы взяты из telemt (config/load/runtime_web.rs), где серверная
// часть WEB реализована первой. Их назначение - доказать, что наш Go считает
// ровно то же значение, которое вычисляет Telegram Desktop: разойдись мы хоть
// на байт, клиент просто получит заглушку вместо прокси, и отлаживать это по
// симптому «не подключается» крайне тяжело.
func TestDeriveCapabilityReferenceVectors(t *testing.T) {
	secret, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	require.NoError(t, err)

	t.Run("plain", func(t *testing.T) {
		capability, err := web.DeriveCapability(web.ClientSecret(secret, web.SecretModePlain), "proxy.example.com")
		require.NoError(t, err)
		assert.Equal(t, "MHLEY5PmW1GWqJkSrlmJpvJUiLhBH_QKy6yKg8a0JPk", web.EncodeCapability(capability))
	})

	t.Run("dd", func(t *testing.T) {
		capability, err := web.DeriveCapability(web.ClientSecret(secret, web.SecretModeDD), "proxy.example.com")
		require.NoError(t, err)
		assert.Equal(t, "IpJrt3e7sKtzPyoXy6w-Zj6GGEvsvclN66JzQEfPYLA", web.EncodeCapability(capability))
	})
}

func TestClientSecretDDPrefix(t *testing.T) {
	secret := []byte{0x01, 0x02}

	assert.Equal(t, []byte{0xdd, 0x01, 0x02}, web.ClientSecret(secret, web.SecretModeDD))
	assert.Equal(t, []byte{0x01, 0x02}, web.ClientSecret(secret, web.SecretModePlain))
}

// Один и тот же секрет на разных хостах даёт разные значения: подсмотренную
// ссылку нельзя перенести на другой наш домен.
func TestDeriveCapabilityDependsOnHost(t *testing.T) {
	secret := web.ClientSecret([]byte("0123456789abcdef"), web.SecretModeDD)

	first, err := web.DeriveCapability(secret, "web3.proxy-os.online")
	require.NoError(t, err)

	second, err := web.DeriveCapability(secret, "web4.proxy-os.online")
	require.NoError(t, err)

	assert.NotEqual(t, first, second)
}

func TestDeriveCapabilityRejectsEmptySecret(t *testing.T) {
	_, err := web.DeriveCapability(nil, "web3.proxy-os.online")
	assert.ErrorIs(t, err, web.ErrEmptySecret)
}

func TestParseBridgeQuery(t *testing.T) {
	secret := web.ClientSecret([]byte("0123456789abcdef"), web.SecretModeDD)
	capability, err := web.DeriveCapability(secret, "web3.proxy-os.online")
	require.NoError(t, err)

	encoded := web.EncodeCapability(capability)

	t.Run("канонический запрос принимается", func(t *testing.T) {
		parsed, ok := web.ParseBridgeQuery("bridge=" + encoded)
		require.True(t, ok)
		assert.Equal(t, capability, parsed)
	})

	// Всё, что не точный канонический вид, - не наш клиент. Такие запросы
	// должны уходить в заглушку, поэтому здесь важен именно отказ, а не ошибка.
	for name, query := range map[string]string{
		"пустая строка":         "",
		"без префикса":          encoded,
		"чужой параметр":        "b=" + encoded,
		"лишний параметр":       "bridge=" + encoded + "&x=1",
		"короткое значение":     "bridge=" + encoded[:42],
		"длинное значение":      "bridge=" + encoded + "A",
		"выравнивание base64":   "bridge=" + encoded[:40] + "===",
		"недопустимые символы":  "bridge=" + encoded[:40] + "!!!",
		"параметр без значения": "bridge=",
	} {
		t.Run(name, func(t *testing.T) {
			_, ok := web.ParseBridgeQuery(query)
			assert.False(t, ok)
		})
	}
}

func TestProfileTableMatch(t *testing.T) {
	const host = "web3.proxy-os.online"

	makeProfile := func(user, secret string) web.Profile {
		capability, err := web.DeriveCapability(web.ClientSecret([]byte(secret), web.SecretModeDD), host)
		require.NoError(t, err)

		return web.Profile{User: user, Capability: capability, SecretMode: web.SecretModeDD}
	}

	petya := makeProfile("petya_1", "0123456789abcdef")
	vasya := makeProfile("vasya_2", "fedcba9876543210")

	table, err := web.NewProfileTable([]web.Profile{petya, vasya})
	require.NoError(t, err)
	assert.Equal(t, 2, table.Len())

	t.Run("находит своего", func(t *testing.T) {
		profile, ok := table.Match(vasya.Capability)
		require.True(t, ok)
		assert.Equal(t, "vasya_2", profile.User)
	})

	t.Run("чужой не проходит", func(t *testing.T) {
		alien := makeProfile("alien_3", "aaaaaaaaaaaaaaaa")
		_, ok := table.Match(alien.Capability)
		assert.False(t, ok)
	})
}

// Одинаковый capability у двух пользователей означает одинаковый секрет: их
// трафик было бы не различить, и статистика одного уехала бы другому. Такую
// конфигурацию отвергаем на старте, а не выясняем потом по жалобам.
func TestProfileTableRejectsDuplicateCapability(t *testing.T) {
	capability, err := web.DeriveCapability(web.ClientSecret([]byte("0123456789abcdef"), web.SecretModeDD), "web3")
	require.NoError(t, err)

	_, err = web.NewProfileTable([]web.Profile{
		{User: "petya_1", Capability: capability},
		{User: "vasya_2", Capability: capability},
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "petya_1")
	assert.Contains(t, err.Error(), "vasya_2")
}
