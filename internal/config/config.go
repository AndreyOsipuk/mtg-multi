package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/mhsanaei/mtg-multi/mtglib"
)

type Optional struct {
	Enabled TypeBool `json:"enabled"`
}

// ConfigSecretLimit is the typed form of a single [secret-limits.<name>] table:
// an optional data quota (with reset policy), an expiry deadline and a disabled
// flag. All fields are optional; the zero value leaves the secret unrestricted.
type ConfigSecretLimit struct {
	Quota      TypeBytes      `json:"quota"`
	QuotaReset TypeQuotaReset `json:"quotaReset"`
	Expires    TypeExpiry     `json:"expires"`
	Disabled   TypeBool       `json:"disabled"`
}

type ListConfig struct {
	Optional

	DownloadConcurrency TypeConcurrency    `json:"downloadConcurrency"`
	URLs                []TypeBlocklistURI `json:"urls"`
	UpdateEach          TypeDuration       `json:"updateEach"`
}

type Config struct {
	Debug                       TypeBool                     `json:"debug"`
	AllowFallbackOnUnknownDC    TypeBool                     `json:"allowFallbackOnUnknownDc"`
	Secret                      mtglib.Secret                `json:"secret"`
	Secrets                     map[string]mtglib.Secret     `json:"secrets"`
	AdTag                       TypeAdTag                    `json:"adTag"`
	SecretAdTags                map[string]TypeAdTag         `json:"secretAdTags"`
	SecretLimits                map[string]ConfigSecretLimit `json:"secretLimits"`
	UsageStateFile              string                       `json:"usageStateFile"`
	APIToken                    string                       `json:"apiToken"`
	BindTo                      []TypeHostPort               `json:"bindTo"`
	ProxyProtocolListener       TypeBool                     `json:"proxyProtocolListener"`
	PreferIP                    TypePreferIP                 `json:"preferIp"`
	AutoUpdate                  TypeBool                     `json:"autoUpdate"`
	DomainFrontingPort          TypePort                     `json:"domainFrontingPort"`
	DomainFrontingIP            TypeIP                       `json:"domainFrontingIp"`
	DomainFrontingProxyProtocol TypeBool                     `json:"domainFrontingProxyProtocol"`
	TolerateTimeSkewness        TypeDuration                 `json:"tolerateTimeSkewness"`
	Concurrency                 TypeConcurrency              `json:"concurrency"`
	PublicIPv4                  TypeIP                       `json:"publicIpv4"`
	PublicIPv6                  TypeIP                       `json:"publicIpv6"`
	DomainFronting              struct {
		Host          TypeHost `json:"host"`
		IP            TypeIP   `json:"ip"`
		Port          TypePort `json:"port"`
		ProxyProtocol TypeBool `json:"proxyProtocol"`
	} `json:"domainFronting"`
	Defense struct {
		AntiReplay struct {
			Optional

			MaxSize   TypeBytes     `json:"maxSize"`
			ErrorRate TypeErrorRate `json:"errorRate"`
		} `json:"antiReplay"`
		Blocklist    ListConfig `json:"blocklist"`
		Allowlist    ListConfig `json:"allowlist"`
		Doppelganger struct {
			URLs       []TypeHttpsURL  `json:"urls"`
			Repeats    TypeConcurrency `json:"repeats_per_raid"`
			UpdateEach TypeDuration    `json:"raid_each"`
			DRS        TypeBool        `json:"drs"`
		} `json:"doppelganger"`
	} `json:"defense"`
	Network struct {
		Timeout struct {
			TCP       TypeDuration `json:"tcp"`
			HTTP      TypeDuration `json:"http"`
			Idle      TypeDuration `json:"idle"`
			Handshake TypeDuration `json:"handshake"`
		} `json:"timeout"`
		KeepAlive struct {
			Disabled TypeBool        `json:"disabled"`
			Idle     TypeDuration    `json:"idle"`
			Interval TypeDuration    `json:"interval"`
			Count    TypeConcurrency `json:"count"`
		} `json:"keepAlive"`
		DOHIP           TypeIP         `json:"dohIp"`
		DNS             TypeDNSURI     `json:"dns"`
		Proxies         []TypeProxyURL `json:"proxies"`
		TCPNotSentLowat TypeBytes      `json:"tcpNotSentLowat"`
		// ClientMSS is the MSS the FakeTLS ServerHello is split by (0 disables).
		ClientMSS TypeTCPMSS `json:"clientMss"`
		// ClientMSSBulk is the MSS of the rest of the session; nil means the
		// key is absent (default), an explicit 0 keeps the whole session at
		// ClientMSS.
		ClientMSSBulk *TypeTCPMSS `json:"clientMssBulk"`
	} `json:"network"`
	APIBindTo TypeHostPort `json:"apiBindTo"`
	Throttle  struct {
		MaxConnections TypeConcurrency `json:"maxConnections"`
		CheckInterval  TypeDuration    `json:"checkInterval"`
	} `json:"throttle"`
	Stats struct {
		StatsD struct {
			Optional

			Address      TypeHostPort        `json:"address"`
			MetricPrefix TypeMetricPrefix    `json:"metricPrefix"`
			TagFormat    TypeStatsdTagFormat `json:"tagFormat"`
		} `json:"statsd"`
		Prometheus struct {
			Optional

			BindTo       TypeHostPort     `json:"bindTo"`
			HTTPPath     TypeHTTPPath     `json:"httpPath"`
			MetricPrefix TypeMetricPrefix `json:"metricPrefix"`
		} `json:"prometheus"`
	} `json:"stats"`
}

func (c *Config) GetConcurrency(defaultValue uint) uint {
	if concurrency := c.Concurrency.Get(0); concurrency != 0 {
		return concurrency
	}
	return c.Concurrency.Get(defaultValue)
}

func (c *Config) GetDNS() *url.URL {
	var dohURL *url.URL

	if dohIP := c.Network.DOHIP.Get(nil); dohIP != nil {
		dohURL, _ = url.Parse("https://" + dohIP.String())
	}

	return c.Network.DNS.Get(dohURL)
}

func (c *Config) GetDomainFrontingPort(defaultValue uint) uint {
	if port := c.DomainFronting.Port.Get(0); port != 0 {
		return port
	}
	return c.DomainFrontingPort.Get(defaultValue)
}

func (c *Config) GetDomainFrontingHost() string {
	return c.DomainFronting.Host.Get("")
}

func (c *Config) GetDomainFrontingProxyProtocol(defaultValue bool) bool {
	return c.DomainFronting.ProxyProtocol.Get(false) || c.DomainFrontingProxyProtocol.Get(defaultValue)
}

func (c *Config) Validate() error {
	if len(c.Secrets) == 0 {
		if !c.Secret.Valid() {
			return fmt.Errorf("invalid secret %s", c.Secret.String())
		}
	} else {
		for name, s := range c.Secrets {
			if !s.Valid() {
				return fmt.Errorf("invalid secret %q: %s", name, s.String())
			}
		}
	}

	if len(c.BindTo) == 0 {
		return fmt.Errorf("incorrect bind-to parameter: no addresses specified")
	}

	seen := make(map[string]struct{}, len(c.BindTo))

	for _, addr := range c.BindTo {
		v := addr.Get("")
		if v == "" {
			return fmt.Errorf("incorrect bind-to parameter: empty address")
		}

		if _, ok := seen[v]; ok {
			return fmt.Errorf("duplicate bind-to address: %s", v)
		}

		seen[v] = struct{}{}
	}

	if err := c.validateAdTags(); err != nil {
		return err
	}

	if err := c.validateSecretLimits(); err != nil {
		return err
	}

	return c.validateClientMSS()
}

// Bounds of client-mss and client-mss-bulk. client-mss goes up to 1460 (the
// Ethernet MSS); the ServerHello is split in user space, so values below the
// kernel minimum are fine too. But with client-mss-bulk = 0 client-mss is set
// on the socket itself, and the kernel rejects TCP_MAXSEG below TCP_MIN_MSS
// (88). bulk is no less than the classic 536 and no more than the kernel limit
// (MAX_TCP_WINDOW).
const (
	ClientMSSMin       = 48
	ClientMSSMax       = 1460
	ClientMSSKernelMin = 88
	ClientMSSBulkMin   = 536
	ClientMSSBulkMax   = 65495

	// DefaultClientMSSBulk is the MSS of the session after the ServerHello
	// when client-mss is set and client-mss-bulk is not.
	DefaultClientMSSBulk = 1400
)

func (c *Config) validateClientMSS() error {
	mss := c.Network.ClientMSS.Get(0)
	if mss != 0 && (mss < ClientMSSMin || mss > ClientMSSMax) {
		return fmt.Errorf("network.client-mss must be 0 or %d..%d, got %d",
			ClientMSSMin, ClientMSSMax, mss)
	}

	if c.Network.ClientMSSBulk == nil {
		return nil
	}

	bulk := c.Network.ClientMSSBulk.Get(0)
	if bulk != 0 && (bulk < ClientMSSBulkMin || bulk > ClientMSSBulkMax) {
		return fmt.Errorf("network.client-mss-bulk must be 0 or %d..%d, got %d",
			ClientMSSBulkMin, ClientMSSBulkMax, bulk)
	}

	if mss != 0 && bulk == 0 && mss < ClientMSSKernelMin {
		return fmt.Errorf("network.client-mss must be at least %d when network.client-mss-bulk = 0, got %d",
			ClientMSSKernelMin, mss)
	}

	if mss != 0 && bulk != 0 && bulk <= mss {
		return fmt.Errorf("network.client-mss-bulk (%d) must be greater than network.client-mss (%d)",
			bulk, mss)
	}

	return nil
}

// GetClientMSS returns the MSS for the ServerHello and the MSS of the rest of
// the session. client-mss = 0 disables everything (0, 0); client-mss-bulk
// without client-mss has no effect. bulk = 0 keeps the whole session at
// client-mss, as iptables TCPMSS on the client SYN would.
func (c *Config) GetClientMSS() (handshake, bulk uint) {
	handshake = c.Network.ClientMSS.Get(0)
	if handshake == 0 {
		return 0, 0
	}

	if c.Network.ClientMSSBulk == nil {
		return handshake, DefaultClientMSSBulk
	}

	return handshake, c.Network.ClientMSSBulk.Get(0)
}

// validateAdTags ensures every [secret-ad-tags] entry names a secret that
// actually exists. Tag byte-length is already enforced at parse time by
// TypeAdTag.Set, so here we only guard against typos in the secret name.
func (c *Config) validateAdTags() error {
	if len(c.SecretAdTags) == 0 {
		return nil
	}

	known := make(map[string]struct{}, len(c.Secrets)+1)
	if len(c.Secrets) > 0 {
		for name := range c.Secrets {
			known[name] = struct{}{}
		}
	} else {
		known["default"] = struct{}{}
	}

	for name := range c.SecretAdTags {
		if _, ok := known[name]; !ok {
			return fmt.Errorf("secret-ad-tags refers to unknown secret %q", name)
		}
	}

	return nil
}

// validateSecretLimits ensures every [secret-limits] entry names a secret that
// actually exists. Field values are already validated at parse time by their
// Type* setters, so here we only guard against typos in the secret name.
func (c *Config) validateSecretLimits() error {
	if len(c.SecretLimits) == 0 {
		return nil
	}

	known := make(map[string]struct{}, len(c.Secrets)+1)
	if len(c.Secrets) > 0 {
		for name := range c.Secrets {
			known[name] = struct{}{}
		}
	} else {
		known["default"] = struct{}{}
	}

	for name := range c.SecretLimits {
		if _, ok := known[name]; !ok {
			return fmt.Errorf("secret-limits refers to unknown secret %q", name)
		}
	}

	return nil
}

// GetSecrets returns all secrets as a map. If the new [secrets] section is used,
// returns that map. Otherwise, wraps the single Secret as {"default": Secret}.
func (c *Config) GetSecrets() map[string]mtglib.Secret {
	if len(c.Secrets) > 0 {
		return c.Secrets
	}

	return map[string]mtglib.Secret{"default": c.Secret}
}

// GetAdTag returns the global advertising tag, or nil when none is configured.
func (c *Config) GetAdTag() *[mtglib.AdTagLength]byte {
	return c.AdTag.Get()
}

// GetSecretAdTags returns the per-secret advertising tag overrides keyed by
// secret name, or nil when none are configured.
func (c *Config) GetSecretAdTags() map[string][mtglib.AdTagLength]byte {
	if len(c.SecretAdTags) == 0 {
		return nil
	}

	out := make(map[string][mtglib.AdTagLength]byte, len(c.SecretAdTags))

	for name, tag := range c.SecretAdTags {
		if t := tag.Get(); t != nil {
			out[name] = *t
		}
	}

	return out
}

// GetSecretLimits converts the [secret-limits] tables into the engine-level
// map keyed by secret name, or nil when none impose any restriction.
func (c *Config) GetSecretLimits() map[string]mtglib.SecretLimits {
	if len(c.SecretLimits) == 0 {
		return nil
	}

	out := make(map[string]mtglib.SecretLimits, len(c.SecretLimits))

	for name, l := range c.SecretLimits {
		lim := mtglib.SecretLimits{
			QuotaBytes: int64(l.Quota.Get(0)),
			ExpiresAt:  l.Expires.Get(time.Time{}),
			Disabled:   l.Disabled.Get(false),
		}

		if l.QuotaReset.Get("none") == mtglib.QuotaResetMonthly.String() {
			lim.QuotaReset = mtglib.QuotaResetMonthly
		}

		if lim.IsZero() {
			continue
		}

		out[name] = lim
	}

	if len(out) == 0 {
		return nil
	}

	return out
}

// GetAPIToken returns the bearer token guarding the management API, or an empty
// string when the API should stay unauthenticated (localhost-bind convention).
func (c *Config) GetAPIToken() string {
	return c.APIToken
}

// GetBindAddrs returns all bind addresses as strings.
func (c *Config) GetBindAddrs() []string {
	addrs := make([]string, len(c.BindTo))

	for i, hp := range c.BindTo {
		addrs[i] = hp.Get("")
	}

	return addrs
}

// GetFirstBindPort returns the port of the first bind address.
func (c *Config) GetFirstBindPort() uint {
	if len(c.BindTo) == 0 {
		return 0
	}

	return c.BindTo[0].Port
}

func (c *Config) String() string {
	buf := &bytes.Buffer{}
	encoder := json.NewEncoder(buf)

	encoder.SetEscapeHTML(false)

	if err := encoder.Encode(c); err != nil {
		panic(err)
	}

	return buf.String()
}
