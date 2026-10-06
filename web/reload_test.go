package web_test

import (
	"testing"

	"github.com/mhsanaei/mtg-multi/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const reloadHost = "web.example.com"

func capabilityFor(t *testing.T, secret []byte) [web.CapabilityLen]byte {
	t.Helper()

	capability, err := web.DeriveCapability(web.ClientSecret(secret, web.SecretModeDD), reloadHost)
	require.NoError(t, err)

	return capability
}

func reloadServer(t *testing.T, secrets map[string][]byte) (*web.Server, *web.ProfileTable) {
	t.Helper()

	profiles, err := web.BuildProfiles(secrets, reloadHost, web.SecretModeDD)
	require.NoError(t, err)

	table, err := web.NewProfileTable(profiles)
	require.NoError(t, err)

	cfg := web.DefaultServerConfig()
	cfg.VHosts = []web.VHost{{Host: reloadHost, Profiles: table, SecretMode: web.SecretModeDD}}
	srv := web.NewServer(cfg)
	t.Cleanup(srv.Close)

	return srv, table
}

// After a reload a new user must get the bridge page, and a removed one must
// be treated like a stranger.
func TestServerUpdateSecrets(t *testing.T) {
	t.Parallel()

	alice := []byte("0123456789abcdef")
	bob := []byte("fedcba9876543210")
	carol := []byte("aaaaaaaaaaaaaaaa")

	srv, table := reloadServer(t, map[string][]byte{"alice": alice, "bob": bob})

	require.NoError(t, srv.UpdateSecrets(map[string][]byte{"alice": alice, "carol": carol}))

	profile, ok := table.Match(capabilityFor(t, carol))
	require.True(t, ok)
	assert.Equal(t, "carol", profile.User)
	assert.Equal(t, web.SecretModeDD, profile.SecretMode)

	_, ok = table.Match(capabilityFor(t, alice))
	assert.True(t, ok)

	_, ok = table.Match(capabilityFor(t, bob))
	assert.False(t, ok)
	assert.Equal(t, 2, table.Len())
}

func TestServerUpdateSecretsKeepsTableOnError(t *testing.T) {
	t.Parallel()

	alice := []byte("0123456789abcdef")
	srv, table := reloadServer(t, map[string][]byte{"alice": alice})

	assert.ErrorIs(t, srv.UpdateSecrets(map[string][]byte{}), web.ErrNoSecrets)

	// The same secret for two users makes them indistinguishable: the table
	// must stay as it was.
	same := []byte("bbbbbbbbbbbbbbbb")
	require.Error(t, srv.UpdateSecrets(map[string][]byte{"bob": same, "carol": same}))

	_, ok := table.Match(capabilityFor(t, alice))
	assert.True(t, ok)
	assert.Equal(t, 1, table.Len())
}
