// Package web реализует WEB-режим: MTProto внутри обычного HTTPS.
//
// Как это работает со стороны клиента. Пользователь получает ссылку
// tg://webproxy?server=<хост>&secret=dd<ключ>. Telegram Desktop сам вычисляет
// из секрета и хоста 32-байтное значение (здесь - capability), открывает в
// вебвью https://<хост>/?bridge=<base64url(capability)> и передаёт странице
// MessagePort. Страницу с JS отдаём мы; она перекладывает кадры между портом и
// HTTP-запросами к нам. Внутри кадров идёт обычный обфусцированный MTProto с
// тем же секретом, поэтому дальше работает существующий путь mtg.
//
// С Telegram Desktop жёстко зафиксированы ровно две вещи: формула capability
// (этот файл) и формат кадра (frame.go). Транспорт между страницей и сервером -
// наш собственный, потому что JS-клиент раздаём мы сами.
//
// Происхождение: серверная часть WEB впервые реализована в проекте telemt
// (https://github.com/telemt/telemt, TELEMT LICENSE 3.3, см. LICENSE.telemt).
// Это независимая реализация того же протокола на Go, не официальный telemt.
package web

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
)

// capabilityContext - константа протокола Telegram Desktop. Менять нельзя:
// клиент считает HMAC с ровно этой строкой, включая перевод строки в конце.
const capabilityContext = "tdesktop-web-proxy-bridge-v1\n"

// CapabilityLen - длина значения, которым клиент представляется серверу.
const CapabilityLen = sha256.Size

// bridgeQueryLen - длина base64url(32 байта) без выравнивания.
const bridgeQueryLen = 43

// SecretMode - в каком виде ключ попадает в ссылку пользователя.
//
// От этого зависит и сам секрет, и capability: клиент считает HMAC на том виде
// ключа, который он получил в ссылке.
type SecretMode string

const (
	// SecretModePlain - ссылка несёт голый 16-байтный ключ.
	SecretModePlain SecretMode = "plain"
	// SecretModeDD - ссылка несёт dd-ключ: байт 0xdd и следом 16 байт.
	SecretModeDD SecretMode = "dd"
)

// ErrEmptySecret - HMAC без ключа бессмысленен, это ошибка конфигурации.
var ErrEmptySecret = errors.New("web: секрет пользователя пуст")

// ClientSecret собирает ключ в том виде, в каком его видит клиент.
func ClientSecret(secret []byte, mode SecretMode) []byte {
	if mode == SecretModeDD {
		out := make([]byte, 0, len(secret)+1)
		out = append(out, 0xdd)

		return append(out, secret...)
	}

	out := make([]byte, len(secret))
	copy(out, secret)

	return out
}

// DeriveCapability повторяет вычисление Telegram Desktop:
// HMAC-SHA256(ключ-из-ссылки, "tdesktop-web-proxy-bridge-v1\n" + хост).
//
// Хост - тот, что в ссылке, в нижнем регистре и без порта. Одно и то же
// значение на разных vhost'ах не совпадёт, поэтому подсмотренная ссылка не
// переносится на другой домен.
func DeriveCapability(clientSecret []byte, host string) ([CapabilityLen]byte, error) {
	var out [CapabilityLen]byte

	if len(clientSecret) == 0 {
		return out, ErrEmptySecret
	}

	mac := hmac.New(sha256.New, clientSecret)
	_, _ = mac.Write([]byte(capabilityContext))
	_, _ = mac.Write([]byte(host))
	copy(out[:], mac.Sum(nil))

	return out, nil
}

// EncodeCapability кодирует значение так, как его ждёт строка запроса.
func EncodeCapability(capability [CapabilityLen]byte) string {
	return base64.RawURLEncoding.EncodeToString(capability[:])
}

// ParseBridgeQuery разбирает строку запроса вида "bridge=<43 символа>".
//
// Принимается ТОЛЬКО канонический вид: ровно один параметр, ровно 43 символа,
// и повторное кодирование обязано дать ту же строку. Всё остальное - не наш
// клиент, и такой запрос должен уйти в заглушку, а не получить ошибку: для
// наблюдателя мы обычный веб-сервер.
func ParseBridgeQuery(query string) ([CapabilityLen]byte, bool) {
	var out [CapabilityLen]byte

	const prefix = "bridge="
	if len(query) != len(prefix)+bridgeQueryLen || query[:len(prefix)] != prefix {
		return out, false
	}

	value := query[len(prefix):]

	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != CapabilityLen {
		return out, false
	}

	// Канонизация: "abc=" и прочие варианты того же значения не принимаем.
	if base64.RawURLEncoding.EncodeToString(decoded) != value {
		return out, false
	}

	copy(out[:], decoded)

	return out, true
}

// Profile - один пользователь на одном vhost.
type Profile struct {
	// User - имя секрета в конфиге mtg (оно же в статистике).
	User string
	// Capability - предвычисленное значение для сверки с ?bridge=.
	Capability [CapabilityLen]byte
	// SecretMode - вид ключа в выданной пользователю ссылке.
	SecretMode SecretMode
}

// ProfileTable - таблица профилей одного vhost.
type ProfileTable struct {
	profiles []Profile
}

// NewProfileTable строит таблицу и отвергает совпадающие capability.
//
// Совпадение означало бы, что два пользователя неразличимы (одинаковый секрет),
// и трафик одного пошёл бы в статистику другого. Лучше отказать на старте.
func NewProfileTable(profiles []Profile) (*ProfileTable, error) {
	seen := make(map[[CapabilityLen]byte]string, len(profiles))

	for _, profile := range profiles {
		if previous, ok := seen[profile.Capability]; ok {
			return nil, errors.New("web: одинаковый capability у пользователей " + previous + " и " + profile.User)
		}

		seen[profile.Capability] = profile.User
	}

	table := make([]Profile, len(profiles))
	copy(table, profiles)

	return &ProfileTable{profiles: table}, nil
}

// Match ищет профиль по значению из строки запроса.
//
// Проходит таблицу ЦЕЛИКОМ и сравнивает в постоянном времени: время ответа не
// должно зависеть ни от позиции пользователя в таблице, ни от того, сколько
// байт значения совпало. Иначе подбор capability превращается в задачу по
// измерению задержек.
func (t *ProfileTable) Match(candidate [CapabilityLen]byte) (Profile, bool) {
	var (
		found Profile
		hit   int
	)

	for _, profile := range t.profiles {
		equal := subtle.ConstantTimeCompare(profile.Capability[:], candidate[:])
		if equal == 1 {
			found = profile
			hit = 1
		}
	}

	return found, hit == 1
}

// Len возвращает число профилей в таблице.
func (t *ProfileTable) Len() int {
	return len(t.profiles)
}
