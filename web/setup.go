package web

import (
	"errors"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"
)

// Settings configure the WEB mode; they come from the [web] section of the
// config. An empty BindTo disables the mode.
type Settings struct {
	// BindTo is the HTTP listener address. It must be a loopback address:
	// TLS is terminated by a reverse proxy (nginx) in front of mtg.
	BindTo string
	// Host is the domain from the tg://webproxy link.
	Host string
	// SecretMode is the kind of key in the link: dd (default) or plain.
	SecretMode SecretMode
	// DecoyDir is a directory with the static site served to everyone who is
	// not a client. Empty serves 404 like an ordinary server.
	DecoyDir string
	// TrustedProxies are the networks X-Forwarded-For is accepted from.
	// Defaults to localhost, where the reverse proxy runs.
	TrustedProxies []*net.IPNet
	// MaxSessions and MaxPending cap live sessions and bridge tokens that have
	// not been used yet. Zero keeps the defaults.
	MaxSessions int
	MaxPending  int
	// Diag accepts diagnostic marks from the bridge page into the log. For
	// troubleshooting only: it is one more open path on the server.
	Diag bool
}

// Setup errors.
var (
	// ErrNoHost means the WEB mode is enabled without a domain.
	ErrNoHost = errors.New("web: host is not set")
	// ErrNoSecrets means the WEB mode is enabled without any secret.
	ErrNoSecrets = errors.New("web: no secrets")
	// ErrPublicBind means an attempt to expose the plain HTTP listener.
	ErrPublicBind = errors.New("web: bind-to must be a loopback address, TLS is terminated by a reverse proxy")
)

// BuildProfiles derives a capability for every user.
//
// The secrets are the same as for regular MTProto: the user is the same, only
// the transport differs. The WEB mode needs neither separate provisioning nor
// its own user table, just a different link.
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

// Setup builds the HTTP entry from settings. It returns (nil, "", nil) when
// the mode is disabled: this is a normal state, not an error.
func Setup(settings Settings, secrets map[string][]byte, handle func(*Stream)) (*Server, string, error) {
	bind := strings.TrimSpace(settings.BindTo)
	if bind == "" {
		return nil, "", nil
	}

	if err := checkLoopback(bind); err != nil {
		return nil, "", err
	}

	host := strings.ToLower(strings.TrimSpace(settings.Host))
	if host == "" {
		return nil, "", ErrNoHost
	}

	if len(secrets) == 0 {
		return nil, "", ErrNoSecrets
	}

	mode := settings.SecretMode
	if mode != SecretModePlain {
		mode = SecretModeDD
	}

	profiles, err := BuildProfiles(secrets, host, mode)
	if err != nil {
		return nil, "", err
	}

	table, err := NewProfileTable(profiles)
	if err != nil {
		return nil, "", err
	}

	trusted := settings.TrustedProxies
	if len(trusted) == 0 {
		trusted = defaultTrustedProxies()
	}

	cfg := DefaultServerConfig()
	cfg.VHosts = []VHost{{Host: host, Profiles: table, Decoy: newDecoy(settings.DecoyDir), SecretMode: mode}}
	cfg.TrustedProxyCIDRs = trusted
	cfg.Bridge = DefaultBridge{Diag: settings.Diag}
	cfg.Handle = handle

	if settings.MaxSessions > 0 {
		cfg.MaxSessions = settings.MaxSessions
	}

	if settings.MaxPending > 0 {
		cfg.MaxPending = settings.MaxPending
	}

	if settings.Diag {
		cfg.Diag = func(clientIP, message string) {
			log.Printf("[web-diag] %s: %s", clientIP, message)
		}
	}

	return NewServer(cfg), bind, nil
}

func defaultTrustedProxies() []*net.IPNet {
	_, v4, _ := net.ParseCIDR("127.0.0.1/32")
	_, v6, _ := net.ParseCIDR("::1/128")

	return []*net.IPNet{v4, v6}
}

// checkLoopback refuses to expose the listener: it speaks plain HTTP, and from
// the outside it would be a proxy without any masking or encryption.
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

// directoryDecoy serves the static files of an ordinary site.
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

// emptyDecoy is used when no directory is set: it answers like an ordinary
// server on a missing page, without any hint of a proxy.
type emptyDecoy struct{}

func (emptyDecoy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}

// Serve runs the HTTP entry on loopback.
//
// Timeouts are explicit: without them a stuck request holds the connection
// forever. ReadHeaderTimeout is short, and there is no overall WriteTimeout
// because the /down long poll holds the response on purpose.
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
