package web

import (
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Включение и настройка WEB идут через окружение - так в этом форке уже сделаны
// MTG_DD_SHAPE и MTG_DC_POOL. Разбор конфига не трогаем: одна строка в
// systemd-юните включает режим и так же легко его выключает.
//
//	MTG_WEB_BIND            - адрес HTTP-входа, только loopback (напр. 127.0.0.1:18080).
//	                          Пусто = WEB выключен.
//	MTG_WEB_HOST            - домен из ссылки tg://webproxy (напр. web6.proxy-os.store).
//	MTG_WEB_SECRET_MODE     - вид ключа в ссылке: dd (по умолчанию) или plain.
//	MTG_WEB_DECOY_DIR       - каталог со статикой заглушки.
//	MTG_WEB_TRUSTED_PROXIES - CIDR'ы, от которых принимаем X-Forwarded-For
//	                          (по умолчанию localhost - там наш nginx).
const (
	envBind       = "MTG_WEB_BIND"
	envHost       = "MTG_WEB_HOST"
	envSecretMode = "MTG_WEB_SECRET_MODE"
	envDecoyDir   = "MTG_WEB_DECOY_DIR"
	// MTG_WEB_DIAG=on включает приём отметок от страницы-моста (в лог).
	// Только на время разбора: это лишний открытый путь на сервере.
	envDiag           = "MTG_WEB_DIAG"
	envTrustedProxies = "MTG_WEB_TRUSTED_PROXIES"
	// MTG_WEB_MAX_SESSIONS / MTG_WEB_MAX_PENDING - пределы живых сессий и
	// выданных мостом токенов (по умолчанию 1024 и 4096).
	envMaxSessions = "MTG_WEB_MAX_SESSIONS"
	envMaxPending  = "MTG_WEB_MAX_PENDING"
)

// Ошибки настройки.
var (
	// ErrNoHost - включили WEB, но не сказали, для какого домена.
	ErrNoHost = errors.New("web: не задан " + envHost)
	// ErrNoSecrets - включили WEB, но пользователей нет.
	ErrNoSecrets = errors.New("web: нет ни одного секрета")
	// ErrPublicBind - попытка выставить HTTP-вход наружу.
	ErrPublicBind = errors.New("web: " + envBind + " должен быть на loopback - TLS терминирует nginx")
)

// Enabled сообщает, включён ли WEB.
func Enabled() bool {
	return strings.TrimSpace(os.Getenv(envBind)) != ""
}

// BuildProfiles считает capability для каждого пользователя.
//
// Секреты те же, что у обычного MTProto: пользователь один, меняется только
// транспорт. Поэтому WEB не требует ни отдельной выдачи, ни своей таблицы -
// достаточно ссылки другого вида.
func BuildProfiles(secrets map[string][]byte, host string, mode SecretMode) ([]Profile, error) {
	profiles := make([]Profile, 0, len(secrets))

	for user, secret := range secrets {
		capability, err := DeriveCapability(ClientSecret(secret, mode), host)
		if err != nil {
			return nil, err
		}

		profiles = append(profiles, Profile{User: user, Capability: capability, SecretMode: mode})
	}

	return profiles, nil
}

// SetupFromEnv собирает HTTP-вход по окружению. Возвращает (nil, "", nil),
// если WEB выключен - это штатное состояние, а не ошибка.
func SetupFromEnv(secrets map[string][]byte, handle func(*Stream)) (*Server, string, error) {
	bind := strings.TrimSpace(os.Getenv(envBind))
	if bind == "" {
		return nil, "", nil
	}

	if err := checkLoopback(bind); err != nil {
		return nil, "", err
	}

	host := strings.ToLower(strings.TrimSpace(os.Getenv(envHost)))
	if host == "" {
		return nil, "", ErrNoHost
	}

	if len(secrets) == 0 {
		return nil, "", ErrNoSecrets
	}

	mode := SecretModeDD
	if strings.EqualFold(strings.TrimSpace(os.Getenv(envSecretMode)), string(SecretModePlain)) {
		mode = SecretModePlain
	}

	profiles, err := BuildProfiles(secrets, host, mode)
	if err != nil {
		return nil, "", err
	}

	table, err := NewProfileTable(profiles)
	if err != nil {
		return nil, "", err
	}

	trusted, err := parseCIDRs(os.Getenv(envTrustedProxies))
	if err != nil {
		return nil, "", err
	}

	cfg := DefaultServerConfig()
	cfg.VHosts = []VHost{{Host: host, Profiles: table, Decoy: newDecoy(os.Getenv(envDecoyDir)), SecretMode: mode}}
	cfg.TrustedProxyCIDRs = trusted
	cfg.Bridge = DefaultBridge{}
	cfg.Handle = handle

	if n, ok := envPositiveInt(envMaxSessions); ok {
		cfg.MaxSessions = n
	}

	if n, ok := envPositiveInt(envMaxPending); ok {
		cfg.MaxPending = n
	}

	if strings.EqualFold(strings.TrimSpace(os.Getenv(envDiag)), "on") {
		cfg.Diag = func(clientIP, message string) {
			log.Printf("[web-diag] %s: %s", clientIP, message)
		}
	}

	return NewServer(cfg), bind, nil
}

// checkLoopback не даёт выставить вход наружу: он говорит по открытому HTTP,
// и снаружи это был бы прокси без всякой маскировки и шифрования.
func checkLoopback(bind string) error {
	host, _, err := net.SplitHostPort(bind)
	if err != nil {
		return err
	}

	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return ErrPublicBind
	}

	return nil
}

func parseCIDRs(value string) ([]*net.IPNet, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		value = "127.0.0.1/32,::1/128"
	}

	out := make([]*net.IPNet, 0, 2)

	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		_, network, err := net.ParseCIDR(part)
		if err != nil {
			return nil, err
		}

		out = append(out, network)
	}

	return out, nil
}

// directoryDecoy отдаёт статику обычного сайта.
type directoryDecoy struct {
	handler http.Handler
}

func newDecoy(dir string) Decoy {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return emptyDecoy{}
	}

	return directoryDecoy{handler: http.FileServer(http.Dir(filepath.Clean(dir)))}
}

func (d directoryDecoy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.handler.ServeHTTP(w, r)
}

// emptyDecoy - заглушка, когда каталог не задан: отвечаем как обычный сервер
// на несуществующую страницу, без единого намёка на прокси.
type emptyDecoy struct{}

func (emptyDecoy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}

// Serve поднимает HTTP-вход на loopback.
//
// Таймауты выставлены явно: без них зависший запрос держит соединение
// бесконечно. ReadHeaderTimeout короткий, а общий WriteTimeout не ставим -
// длинный опрос /down намеренно придерживает ответ.
func Serve(srv *Server, bind string) error {
	httpServer := &http.Server{
		Addr:              bind,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       90 * time.Second,
	}

	return httpServer.ListenAndServe()
}

// envPositiveInt читает положительное число из окружения; пусто или мусор -
// остаётся значение по умолчанию.
func envPositiveInt(name string) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(os.Getenv(name)))
	if err != nil || n <= 0 {
		return 0, false
	}

	return n, true
}
