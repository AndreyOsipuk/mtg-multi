package mtglib

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"sync"
)

// secretSet is an immutable snapshot of the configured secrets. The proxy
// swaps it atomically on every update (SIGHUP, POST /reload, the management
// API), so a handshake always works with one consistent snapshot. secrets,
// names, keys, adTags and limits stay index-aligned: secrets[i] belongs to
// names[i]; hostnames is the deduplicated, sorted set of secret hosts used for
// SNI matching.
type secretSet struct {
	secrets   []Secret
	names     []string
	hostnames []string
	keys      [][]byte
	byName    map[string]Secret

	// adTags[i] is the per-secret advertising tag override for secrets[i], or
	// nil when that secret has no override; globalAdTag applies to any secret
	// without an override, or nil when no advertising is configured.
	adTags      []*[AdTagLength]byte
	globalAdTag *[AdTagLength]byte
	// limits[i] holds the governance limits (quota, expiry, disabled) for
	// secrets[i]; the zero value means the secret is unrestricted.
	limits []SecretLimits
}

// newSecretSet builds a snapshot of plain secrets without advertising tags and
// limits.
func newSecretSet(secrets map[string]Secret) *secretSet {
	return buildSecretSet(secrets, nil, nil, nil)
}

// newSecretSetFromConfig builds a snapshot of a full SecretConfig.
func newSecretSetFromConfig(cfg SecretConfig) *secretSet {
	return buildSecretSet(cfg.Secrets, cfg.SecretAdTags, cfg.GlobalAdTag, cfg.Limits)
}

// buildSecretSet turns a name->secret map into an immutable, name-sorted
// snapshot. Sorting keeps names[i] and secrets[i] aligned and makes the
// matched index stable across processes for a given secret map. perSecret
// carries optional per-name advertising tags and global is the fallback tag;
// both may be nil. limitsMap carries optional per-name governance limits and
// may be nil.
func buildSecretSet(
	secretsMap map[string]Secret,
	perSecret map[string][AdTagLength]byte,
	global *[AdTagLength]byte,
	limitsMap map[string]SecretLimits,
) *secretSet {
	names := make([]string, 0, len(secretsMap))
	for name := range secretsMap {
		names = append(names, name)
	}

	sort.Strings(names)

	set := &secretSet{
		secrets:     make([]Secret, 0, len(names)),
		names:       names,
		keys:        make([][]byte, 0, len(names)),
		byName:      make(map[string]Secret, len(names)),
		adTags:      make([]*[AdTagLength]byte, len(names)),
		globalAdTag: global,
		limits:      make([]SecretLimits, len(names)),
	}

	// Collect unique hostnames across all secrets for SNI matching.
	hostnameSet := make(map[string]struct{}, len(names))

	for i, name := range names {
		secret := secretsMap[name]
		set.secrets = append(set.secrets, secret)
		set.keys = append(set.keys, secret.Key[:])
		set.byName[name] = secret
		hostnameSet[secret.Host] = struct{}{}

		if tag, ok := perSecret[name]; ok {
			t := tag
			set.adTags[i] = &t
		}

		if lim, ok := limitsMap[name]; ok {
			set.limits[i] = lim
		}
	}

	set.hostnames = make([]string, 0, len(hostnameSet))
	for h := range hostnameSet {
		set.hostnames = append(set.hostnames, h)
	}

	sort.Strings(set.hostnames)

	return set
}

// effectiveAdTag returns the advertising tag that applies to secrets[i]: the
// per-secret override if present, otherwise the global tag, otherwise nil (the
// direct-DC path).
func (s *secretSet) effectiveAdTag(i int) *[AdTagLength]byte {
	if i < len(s.adTags) && s.adTags[i] != nil {
		return s.adTags[i]
	}

	return s.globalAdTag
}

// limitsOf returns the governance limits of a secret by name; an unknown name
// has no limits.
func (s *secretSet) limitsOf(name string) SecretLimits {
	idx := sort.SearchStrings(s.names, name)
	if idx < len(s.names) && s.names[idx] == name && idx < len(s.limits) {
		return s.limits[idx]
	}

	return SecretLimits{}
}

// toConfig reconstructs a mutable SecretConfig from the immutable snapshot. It
// is the copy-on-write starting point for the management-API mutators, which
// apply a delta and swap the result back in.
func (s *secretSet) toConfig() SecretConfig {
	secrets := make(map[string]Secret, len(s.names))

	var perSecret map[string][AdTagLength]byte

	var limits map[string]SecretLimits

	for i, name := range s.names {
		secrets[name] = s.secrets[i]

		if s.adTags[i] != nil {
			if perSecret == nil {
				perSecret = make(map[string][AdTagLength]byte)
			}

			perSecret[name] = *s.adTags[i]
		}

		if i < len(s.limits) && !s.limits[i].IsZero() {
			if limits == nil {
				limits = make(map[string]SecretLimits)
			}

			limits[name] = s.limits[i]
		}
	}

	return SecretConfig{Secrets: secrets, SecretAdTags: perSecret, GlobalAdTag: s.globalAdTag, Limits: limits}
}

// digest - sha256 от строк "имя=секрет(hex)" в порядке имён через \n. Синк
// считает то же самое из своего конфига и так проверяет, что перезагрузка
// применилась целиком: по одним именам смену ключей не увидеть.
func (s *secretSet) digest() string {
	lines := make([]string, len(s.names))
	for i, name := range s.names {
		lines[i] = name + "=" + s.secrets[i].Hex()
	}

	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))

	return hex.EncodeToString(sum[:])
}

// sameSecret reports whether name is present in the set with the given key.
//
// Сравнивается только ключ: смена одного host на рукопожатие не влияет (ключ
// тот же), а уже открытые сессии такого пользователя закрывает UpdateSecrets.
func (s *secretSet) sameSecret(name string, key []byte) bool {
	secret, ok := s.byName[name]

	return ok && bytes.Equal(secret.Key[:], key)
}

// SecretsUpdate describes the result of applying a new secret set.
type SecretsUpdate struct {
	// Added is the number of new secret names.
	Added int
	// Removed is the number of secret names that are gone.
	Removed int
	// Changed is the number of names that are kept with a different key or
	// host.
	Changed int
	// ClosedSessions is the number of live sessions that were closed because
	// their secret was removed or changed, or because it is now disabled or
	// expired.
	ClosedSessions int
}

// sessionRegistry tracks authenticated sessions per secret name, so that
// sessions of a removed or changed secret can be closed on update.
type sessionRegistry struct {
	mu       sync.Mutex
	sessions map[string]map[*streamContext]struct{}
}

func newSessionRegistry() *sessionRegistry {
	return &sessionRegistry{
		sessions: make(map[string]map[*streamContext]struct{}),
	}
}

// add registers a session. The caller must hold r.mu.
func (r *sessionRegistry) add(ctx *streamContext) {
	byName := r.sessions[ctx.secretName]
	if byName == nil {
		byName = make(map[*streamContext]struct{})
		r.sessions[ctx.secretName] = byName
	}

	byName[ctx] = struct{}{}
}

func (r *sessionRegistry) remove(ctx *streamContext) {
	r.mu.Lock()
	defer r.mu.Unlock()

	byName := r.sessions[ctx.secretName]
	delete(byName, ctx)

	if len(byName) == 0 {
		delete(r.sessions, ctx.secretName)
	}
}
